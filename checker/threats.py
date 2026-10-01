"""
Modulo 2 - Inteligencia de amenazas.

Le pregunta a bases de datos externas si una URL esta reportada como
maliciosa. Por ahora: Google Safe Browsing. VirusTotal llega el Dia 3.

Tres reglas que rigen todo este modulo:

  1. Si no se pudo consultar, el resultado es DESCONOCIDO, nunca "seguro".
     Un error de red no es una constancia de limpieza.

  2. La llave NUNCA aparece en un mensaje, un error o un log. En esta API
     la llave viaja dentro de la URL de la peticion, asi que imprimir esa
     URL en un error significa filtrarla en pantalla.

  3. Los resultados se reportan citando la fuente. Nuestra herramienta no
     "sabe" que un sitio es malicioso: sabe que Google lo reporto. No es
     lo mismo, y los terminos de Google exigen decirlo asi.
"""

import base64
import threading
import time
from dataclasses import dataclass, field

import httpx

from checker import cache, config

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
TIEMPO_LIMITE = 10.0

# Que tipos de amenaza le preguntamos a Google.
TIPOS_DE_AMENAZA = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

# Traduccion de los nombres tecnicos a algo que se entienda.
NOMBRES = {
    "MALWARE": "Malware (software malicioso)",
    "SOCIAL_ENGINEERING": "Phishing o ingenieria social",
    "UNWANTED_SOFTWARE": "Software no deseado",
    "POTENTIALLY_HARMFUL_APPLICATION": "Aplicacion potencialmente dañina",
    # Los de VirusTotal (Dia 3)
    "MALICIOUS": "Marcada como maliciosa por uno o mas antivirus",
    "SUSPICIOUS": "Marcada como sospechosa por uno o mas antivirus",
}

# Como nos identificamos ante Google.
CLIENTE_ID = "url-checker-educativo"
CLIENTE_VERSION = "0.1"


@dataclass
class Amenaza:
    """Una coincidencia reportada por una base de datos de amenazas."""

    fuente: str     # quien lo reporta, por ejemplo "Google Safe Browsing"
    tipo: str       # el nombre tecnico, por ejemplo SOCIAL_ENGINEERING
    url: str        # cual de las URLs que preguntamos coincidio

    @property
    def descripcion(self) -> str:
        """El tipo de amenaza en español."""
        return NOMBRES.get(self.tipo, self.tipo)


@dataclass
class ResultadoAmenazas:
    """Lo que averiguamos al preguntar a las bases de datos.

    Ojo con la diferencia entre estos dos casos:
        consultado=True,  amenazas=[]  -> preguntamos y salio limpio
        consultado=False, amenazas=[]  -> NO pudimos preguntar (desconocido)
    Confundirlos es el error clasico de las herramientas de seguridad.
    """

    fuente: str
    consultado: bool = False
    amenazas: list[Amenaza] = field(default_factory=list)
    error: str | None = None
    estadisticas: dict[str, int] = field(default_factory=dict)
    del_cache: bool = False

    @property
    def limpio(self) -> bool:
        """Solo True si de verdad preguntamos y no hubo coincidencias."""
        return self.consultado and not self.amenazas

    @property
    def resumen(self) -> str:
        if not self.consultado:
            return f"DESCONOCIDO - no se pudo consultar ({self.error})"
        if not self.amenazas:
            return "Sin coincidencias"
        tipos = ", ".join(sorted({a.descripcion for a in self.amenazas}))
        return f"REPORTADO: {tipos}"


def consultar_safe_browsing(urls: list[str]) -> ResultadoAmenazas:
    """Le pregunta a Google Safe Browsing por una o varias URLs de golpe.

    Se mandan juntas la URL original y la final de la cadena: un acortador
    limpio puede llevarte a un sitio sucio, hay que preguntar por los dos.
    """
    resultado = ResultadoAmenazas(fuente="Google Safe Browsing")

    llave = config.obtener("GOOGLE_SAFE_BROWSING_API_KEY")
    if not llave:
        resultado.error = "falta la llave de API"
        return resultado

    # Quitamos repetidas conservando el orden (si original == final, va una sola).
    unicas = list(dict.fromkeys(u for u in urls if u))
    if not unicas:
        resultado.error = "no se paso ninguna URL"
        return resultado

    cuerpo = {
        "client": {"clientId": CLIENTE_ID, "clientVersion": CLIENTE_VERSION},
        "threatInfo": {
            "threatTypes": TIPOS_DE_AMENAZA,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in unicas],
        },
    }

    try:
        # La llave va como parametro de la URL. params= se encarga de
        # escaparla bien; nunca la pegamos a mano con f-strings.
        respuesta = httpx.post(
            ENDPOINT,
            params={"key": llave},
            json=cuerpo,
            timeout=TIEMPO_LIMITE,
        )
    except httpx.RequestError as error:
        # OJO: usamos type(error).__name__ y NO str(error).
        # El texto del error de httpx suele incluir la URL completa de la
        # peticion... y la URL lleva la llave adentro. Imprimirlo la filtra.
        resultado.error = f"problema de red ({type(error).__name__})"
        return resultado

    if respuesta.status_code == 400:
        resultado.error = "peticion mal formada (400)"
        return resultado
    if respuesta.status_code in (401, 403):
        resultado.error = "la llave no es valida o la API no esta habilitada (403)"
        return resultado
    if respuesta.status_code == 429:
        resultado.error = "cuota agotada por hoy (429)"
        return resultado
    if respuesta.status_code != 200:
        resultado.error = f"respuesta inesperada ({respuesta.status_code})"
        return resultado

    try:
        datos = respuesta.json()
    except ValueError:
        resultado.error = "la respuesta no es JSON valido"
        return resultado

    # Google contesta {} cuando no hay nada. Silencio significa limpio.
    for coincidencia in datos.get("matches", []):
        resultado.amenazas.append(Amenaza(
            fuente="Google Safe Browsing",
            tipo=coincidencia.get("threatType", "DESCONOCIDO"),
            url=coincidencia.get("threat", {}).get("url", ""),
        ))

    resultado.consultado = True
    return resultado


# =====================================================================
#  VirusTotal (Semana 2, Dia 3)
# =====================================================================

VT_ENDPOINT = "https://www.virustotal.com/api/v3/urls"

# Cuota gratuita de VirusTotal: 4 peticiones por minuto, 500 al dia.
VT_MAXIMO = 4
VT_VENTANA = 60.0


class Limitador:
    """No deja salir mas de N peticiones dentro de una ventana de tiempo.

    Guarda la hora de cada peticion. Antes de dejar pasar una nueva, tira
    las que ya salieron de la ventana y cuenta las que quedan. Si ya hay
    demasiadas, espera lo necesario para que la mas vieja caduque.

    Esto se llama "ventana deslizante" y es mas justo que simplemente
    dormir un rato entre peticion y peticion: si llevas horas sin usar la
    API, las primeras 4 salen de inmediato.
    """

    def __init__(self, maximo: int, ventana: float) -> None:
        self.maximo = maximo
        self.ventana = ventana
        self.marcas: list[float] = []
        # Con hilos, dos podrian ver "quedan lugares" al mismo tiempo y
        # pasar los dos. El candado lo impide.
        self._candado = threading.Lock()

    def esperar(self) -> float:
        """Bloquea si hace falta. Devuelve cuantos segundos espero."""
        espero_total = 0.0
        while True:
            with self._candado:
                # time.monotonic() siempre avanza, aunque cambies la hora del
                # sistema. Para medir intervalos es mejor que time.time().
                ahora = time.monotonic()
                self.marcas = [m for m in self.marcas if ahora - m < self.ventana]

                if len(self.marcas) < self.maximo:
                    self.marcas.append(ahora)
                    return espero_total

                # La mas vieja manda: cuando caduque, se libera un lugar.
                espera = self.ventana - (ahora - self.marcas[0]) + 0.05

            # El sleep va FUERA del candado: dormir con el candado puesto
            # dejaria a los demas hilos bloqueados sin necesidad.
            time.sleep(espera)
            espero_total += espera


_limitador_vt = Limitador(VT_MAXIMO, VT_VENTANA)


def id_de_url(url: str) -> str:
    """Convierte una URL en el identificador que usa VirusTotal.

    Es la URL en base64 "seguro para URLs", sin los signos = del final.
    Asi lo pide su documentacion.
    """
    codificado = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
    return codificado.rstrip("=")


def consultar_virustotal(url: str, usar_cache: bool = True) -> ResultadoAmenazas:
    """Pregunta a VirusTotal cuantos antivirus marcaron esta URL.

    VirusTotal no escanea en el momento: consulta su base de datos de
    analisis previos. Si nunca nadie la ha enviado, contesta 404, y eso
    NO significa que este limpia: significa que no sabemos nada de ella.
    """
    resultado = ResultadoAmenazas(fuente="VirusTotal")

    llave = config.obtener("VIRUSTOTAL_API_KEY")
    if not llave:
        resultado.error = "falta la llave de API"
        return resultado

    clave_cache = f"virustotal:{url}"

    # --- Primero el cache: la peticion mas rapida es la que no se hace ---
    if usar_cache:
        guardado = cache.leer(clave_cache)
        if guardado is not None:
            resultado.consultado = True
            resultado.del_cache = True
            resultado.estadisticas = guardado.get("estadisticas", {})
            for a in guardado.get("amenazas", []):
                resultado.amenazas.append(Amenaza(
                    fuente="VirusTotal", tipo=a["tipo"], url=a["url"]))
            return resultado

    # --- No estaba en cache: hay que preguntar ---
    _limitador_vt.esperar()

    try:
        respuesta = httpx.get(
            f"{VT_ENDPOINT}/{id_de_url(url)}",
            # Aqui la llave va en un ENCABEZADO, no en la URL. Es mas seguro:
            # los encabezados no aparecen en logs de servidores ni en el
            # historial del navegador como si pasa con los parametros.
            headers={"x-apikey": llave, "accept": "application/json"},
            timeout=TIEMPO_LIMITE,
        )
    except httpx.RequestError as error:
        resultado.error = f"problema de red ({type(error).__name__})"
        return resultado

    if respuesta.status_code == 404:
        # Nadie ha analizado esta URL nunca. No sabemos nada de ella.
        resultado.error = "VirusTotal no tiene analisis de esta URL"
        return resultado
    if respuesta.status_code == 401:
        resultado.error = "la llave de VirusTotal no es valida (401)"
        return resultado
    if respuesta.status_code == 429:
        resultado.error = "cuota de VirusTotal agotada (429)"
        return resultado
    if respuesta.status_code != 200:
        resultado.error = f"respuesta inesperada ({respuesta.status_code})"
        return resultado

    try:
        datos = respuesta.json()
    except ValueError:
        resultado.error = "la respuesta no es JSON valido"
        return resultado

    stats = datos.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    resultado.estadisticas = {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }

    maliciosos = resultado.estadisticas["malicious"]
    sospechosos = resultado.estadisticas["suspicious"]

    # Guardamos las cuentas tal cual. Decidir si eso significa "peligroso"
    # es trabajo del Modulo 3, en la Semana 3. Aqui solo reportamos.
    if maliciosos > 0:
        resultado.amenazas.append(Amenaza(
            fuente="VirusTotal", tipo="MALICIOUS", url=url))
    elif sospechosos > 0:
        resultado.amenazas.append(Amenaza(
            fuente="VirusTotal", tipo="SUSPICIOUS", url=url))

    resultado.consultado = True

    if usar_cache:
        cache.guardar(clave_cache, {
            "estadisticas": resultado.estadisticas,
            "amenazas": [{"tipo": a.tipo, "url": a.url} for a in resultado.amenazas],
        }, limpio=resultado.limpio)

    return resultado


# Para probar este archivo solo:  python -m checker.threats <url> [<url2> ...]
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Uso: python -m checker.threats <url> [<url2> ...]")
        sys.exit(1)

    urls = sys.argv[1:]

    google = consultar_safe_browsing(urls)
    print(f"\n{google.fuente}: {google.resumen}")
    for amenaza in google.amenazas:
        print(f"  - [{amenaza.descripcion}] {amenaza.url}")

    for url in urls:
        vt = consultar_virustotal(url)
        origen = " (del cache)" if vt.del_cache else ""
        print(f"\n{vt.fuente}{origen} sobre {url}:")
        print(f"  {vt.resumen}")
        if vt.estadisticas:
            e = vt.estadisticas
            print(f"  maliciosos={e['malicious']}  sospechosos={e['suspicious']}  "
                  f"inofensivos={e['harmless']}  sin deteccion={e['undetected']}")
    print()
