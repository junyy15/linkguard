"""
Modulo 1 - Salud del enlace.

Aqui la herramienta sale a internet por primera vez: toca la puerta del sitio
y anota que contesta.

Decisiones importantes:
  - follow_redirects=False: NO dejamos que la libreria siga los redirects sola.
    Manana los seguimos nosotros, revisando el anti-SSRF en cada salto.
  - verify=True: verificamos el certificado TLS. Si esta mal, lo REPORTAMOS.
    Nunca se apaga la verificacion para "que funcione".
  - HEAD primero: pide solo los encabezados, no la pagina. Mas rapido y no
    descargamos contenido de un sitio que todavia no sabemos si es seguro.
"""

import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from checker.validator import validar_url

# Cuanto esperamos antes de rendirnos. Un programa que espera para siempre
# es un programa roto.
TIEMPO_LIMITE = 5.0

# Quien decimos ser. Es de buena educacion identificarse, y ademas algunos
# sitios bloquean a quien no manda User-Agent.
AGENTE = "URL-Health-Checker/0.1 (proyecto educativo)"


@dataclass
class Salud:
    """Lo que averiguamos al tocar la puerta del sitio."""

    categoria: str                  # OK | REDIRECCION | ROTO | BLOQUEADO | ERROR
    codigo: int | None = None       # 200, 404, 500...
    razon: str = ""                 # explicacion en español
    tiempo_ms: int | None = None    # cuanto tardo en contestar
    destino: str | None = None      # a donde manda, si es un redirect
    metodo: str | None = None       # HEAD o GET
    tipo_error: str | None = None   # "timeout" | "ssl" | "conexion" | "red"


def clasificar(codigo: int) -> tuple[str, str]:
    """Convierte un numero de estado HTTP en algo que un humano entienda.

    Los codigos van por familias, y el primer digito es el que manda:
        2xx = todo bien
        3xx = "eso se mudo, ve a esta otra direccion"
        4xx = "el error es tuyo" (404 = no existe, 403 = no te dejo pasar)
        5xx = "el error es mio" (el servidor se rompio)
    """
    if 200 <= codigo < 300:
        return "OK", "El sitio respondio correctamente"
    if 300 <= codigo < 400:
        return "REDIRECCION", "El sitio te manda a otra direccion"
    if codigo == 404:
        return "ROTO", "La pagina no existe (404)"

    # 401, 403 y 429 NO significan que el enlace este roto: significan que el
    # sitio no nos deja pasar por ser un programa. Meterlos en el mismo cajon
    # que un 404 seria un falso positivo, y una herramienta que grita "roto"
    # cuando no lo esta pierde toda su credibilidad.
    if codigo in (401, 403):
        return "BLOQUEADO", "El sitio no deja entrar a programas automaticos (no esta roto)"
    if codigo == 429:
        return "BLOQUEADO", "Demasiadas peticiones seguidas (429): hay que esperar"

    if 400 <= codigo < 500:
        return "ROTO", f"Error del lado del cliente ({codigo})"
    if 500 <= codigo < 600:
        return "ROTO", f"El servidor tiene un problema ({codigo})"
    return "ROTO", f"Codigo de estado inesperado ({codigo})"


def es_error_de_certificado(error: Exception) -> bool:
    """Distingue un fallo de certificado TLS de un fallo de conexion normal.

    httpx no tiene una excepcion propia para SSL: envuelve la original.
    Por eso recorremos la cadena de causas (error.__cause__) hasta el fondo
    buscando un ssl.SSLError. Es como preguntar '¿y eso por que paso?'
    varias veces seguidas.
    """
    causa: BaseException | None = error
    while causa is not None:
        if isinstance(causa, ssl.SSLError):
            return True
        causa = causa.__cause__

    # Red de seguridad por si la cadena de causas viene vacia.
    texto = str(error).upper()
    return "SSL" in texto or "CERTIFICATE" in texto


def revisar_salud(url: str, tiempo_limite: float = TIEMPO_LIMITE) -> Salud:
    """Hace UNA peticion al sitio y reporta como le fue.

    No sigue redirects: si el sitio contesta 301, lo anotamos y ya.
    Seguir la cadena es el trabajo del Dia 4.
    """
    inicio = time.perf_counter()

    def transcurrido() -> int:
        """Milisegundos desde que empezamos. Se calcula igual si hubo error."""
        return int((time.perf_counter() - inicio) * 1000)

    try:
        with httpx.Client(
            follow_redirects=False,
            timeout=tiempo_limite,
            headers={"User-Agent": AGENTE},
            verify=True,
        ) as cliente:
            # HEAD pide solo los encabezados, no la pagina completa.
            respuesta = cliente.head(url)
            metodo = "HEAD"

            # Muchos servidores manejan mal el HEAD y contestan 403, 405 o 501
            # aunque la pagina exista. En ese caso reintentamos con GET.
            if respuesta.status_code in (403, 405, 501):
                respuesta = cliente.get(url)
                metodo = "GET"

    except httpx.TimeoutException:
        return Salud(
            categoria="ERROR",
            # :g muestra el numero "como se vea mejor": 5 sale como "5" y
            # 0.001 sale como "0.001". Con :.0f los dos salian como "0".
            razon=f"El sitio no respondio en {tiempo_limite:g} segundos",
            tiempo_ms=transcurrido(),
            tipo_error="timeout",
        )

    except httpx.ConnectError as error:
        # Aqui caen dos cosas distintas que conviene separar.
        if es_error_de_certificado(error):
            return Salud(
                categoria="ERROR",
                razon="El certificado de seguridad (HTTPS) no es valido",
                tiempo_ms=transcurrido(),
                tipo_error="ssl",
            )
        return Salud(
            categoria="ERROR",
            razon="No se pudo conectar con el servidor",
            tiempo_ms=transcurrido(),
            tipo_error="conexion",
        )

    except httpx.RequestError as error:
        # Cualquier otro problema de red. RequestError es la clase "madre"
        # de todos los errores de httpx, asi que esto atrapa lo que sobre.
        return Salud(
            categoria="ERROR",
            razon=f"Problema de red: {type(error).__name__}",
            tiempo_ms=transcurrido(),
            tipo_error="red",
        )

    categoria, razon = clasificar(respuesta.status_code)

    # Si es un redirect, el servidor dice a donde en el encabezado "Location".
    destino = respuesta.headers.get("location") if categoria == "REDIRECCION" else None

    return Salud(
        categoria=categoria,
        codigo=respuesta.status_code,
        razon=razon,
        tiempo_ms=transcurrido(),
        destino=destino,
        metodo=metodo,
    )


# =====================================================================
#  La cadena de redirecciones (Dia 4)
# =====================================================================

# Cuantos saltos aguantamos antes de rendirnos. Las cadenas legitimas casi
# nunca pasan de 3 o 4. Un numero alto suele ser un bucle o un rastreador.
MAX_SALTOS = 10


@dataclass
class Salto:
    """Un eslabon de la cadena."""

    numero: int
    url: str
    codigo: int | None = None
    destino: str | None = None


@dataclass
class Cadena:
    """El recorrido completo, de la primera URL hasta la ultima."""

    saltos: list[Salto] = field(default_factory=list)
    url_final: str = ""
    salud_final: Salud | None = None
    problema: str | None = None        # por que se corto la cadena, si se corto
    cambia_de_dominio: bool = False    # empieza en un dominio y acaba en otro
    baja_seguridad: bool = False       # en algun punto pasa de https a http

    @property
    def num_saltos(self) -> int:
        """Cuantas redirecciones hubo. 0 significa que llego directo."""
        return max(len(self.saltos) - 1, 0)


def dominio_de(url: str) -> str:
    """Saca el dominio de una URL, o cadena vacia si no se puede."""
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def seguir_cadena(url: str, max_saltos: int = MAX_SALTOS) -> Cadena:
    """Sigue las redirecciones una por una hasta llegar al destino final.

    En CADA salto volvemos a validar la URL. Ese es el punto de todo esto:
    una cadena puede empezar en un dominio publico e inocente y terminar
    apuntando a 127.0.0.1. Validar solo la primera URL no sirve de nada.
    """
    cadena = Cadena()
    actual = url
    ya_visitadas: set[str] = set()

    for numero in range(1, max_saltos + 1):
        salud = revisar_salud(actual)
        salto = Salto(numero=numero, url=actual, codigo=salud.codigo)
        cadena.saltos.append(salto)
        ya_visitadas.add(actual)

        # ¿Llegamos? Si no es una redireccion, aqui se acaba el viaje.
        if salud.categoria != "REDIRECCION" or not salud.destino:
            cadena.url_final = actual
            cadena.salud_final = salud
            break

        # El encabezado Location puede venir incompleto, por ejemplo "/login".
        # urljoin lo combina con la URL actual para formar la direccion completa.
        siguiente = urljoin(actual, salud.destino)
        salto.destino = siguiente

        # --- EL GUARDIA, OTRA VEZ ---
        # Este es el corazon del Dia 4: revalidamos cada salto.
        validacion = validar_url(siguiente)
        if not validacion.ok:
            cadena.url_final = actual
            cadena.salud_final = salud
            cadena.problema = f"Salto {numero} bloqueado: {validacion.motivo}"
            break
        siguiente = validacion.url or siguiente

        # ¿Bucle? Si ya pasamos por ahi, estamos dando vueltas.
        if siguiente in ya_visitadas:
            cadena.url_final = siguiente
            cadena.salud_final = salud
            cadena.problema = "La cadena da vueltas en circulo (bucle de redirecciones)"
            break

        # ¿Bajamos de https a http? Ahi los datos dejan de ir cifrados.
        if actual.lower().startswith("https://") and siguiente.lower().startswith("http://"):
            cadena.baja_seguridad = True

        actual = siguiente

    else:
        # Este 'else' es del FOR, no del IF: se ejecuta solo si el bucle
        # termino sin ningun break, es decir, si agotamos los saltos.
        cadena.url_final = actual
        cadena.salud_final = None
        cadena.problema = f"Demasiadas redirecciones (mas de {max_saltos})"

    # ¿Terminamos en un dominio distinto al que empezamos?
    inicio = dominio_de(url)
    fin = dominio_de(cadena.url_final)
    cadena.cambia_de_dominio = bool(inicio and fin and inicio != fin)

    return cadena


# Para probar este archivo solo:  python -m checker.health <url>
# (con -m, no con la ruta: asi Python sabe que 'checker' es un paquete)
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Uso: python checker/health.py <url>")
        sys.exit(1)

    resultado = seguir_cadena(sys.argv[1])
    for salto in resultado.saltos:
        print(f"  {salto.numero}. [{salto.codigo}] {salto.url}")
        if salto.destino:
            print(f"      -> {salto.destino}")
    print(f"\nFinal: {resultado.url_final}")
    print(f"Saltos: {resultado.num_saltos}")
    if resultado.problema:
        print(f"Problema: {resultado.problema}")
