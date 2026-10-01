"""
Modulo 1 - Salud del enlace.

Aqui la herramienta sale a internet por primera vez: toca la puerta del sitio
y anota que contesta.

Decisiones importantes:
  - follow_redirects=False: NO dejamos que la libreria siga los redirects sola.
    Los seguimos nosotros, revisando el anti-SSRF en cada salto.
  - verify=True: verificamos el certificado TLS. Si esta mal, lo REPORTAMOS.
    Nunca se apaga la verificacion para "que funcione".
  - HEAD primero: pide solo los encabezados, no la pagina.
  - Nunca se descarga el cuerpo de la respuesta (ver abajo).
  - La IP se fija antes de conectar (ver abajo).

=====================================================================
 DNS REBINDING: por que no basta con validar antes
=====================================================================

El diseño original tenia un hueco. El orden era:

    1. validator.py resuelve el DNS  ->  "93.184.216.34, publica, OK"
    2. httpx resuelve el DNS OTRA VEZ al conectarse  ->  127.0.0.1

Son DOS resoluciones distintas. Un atacante que controle su propio
servidor DNS puede contestar una IP publica en la primera y 127.0.0.1
en la segunda (con TTL 0 el sistema no guarda la respuesta vieja).
La validacion aprueba, y la conexion termina en tu maquina.

Se llama DNS rebinding, y es el bypass clasico de los filtros anti-SSRF.
En la terminal casi no importa, porque las URLs las eliges tu. En api.py
expuesto por HTTP, es LA vulnerabilidad.

El arreglo es resolver UNA SOLA VEZ y conectarse a esa IP, no al nombre:

    - La URL de la peticion lleva la IP ya validada.
    - El encabezado Host lleva el nombre original (si no, el servidor no
      sabe que sitio le estas pidiendo).
    - La extension sni_hostname lleva el nombre original, para que el
      certificado TLS se siga verificando contra el nombre y no contra
      la IP. Esto es lo que impide que el arreglo debilite el HTTPS:
      un certificado que no corresponda al nombre se sigue rechazando.

=====================================================================
 NUNCA SE DESCARGA EL CUERPO
=====================================================================

Antes, cuando el HEAD fallaba y caiamos al GET, httpx descargaba la
pagina entera en memoria. Un servidor malicioso podia mandar gigabytes.
Ahora todas las peticiones usan cliente.stream(): se leen los
encabezados, se toma el codigo y se cierra la conexion sin leer una
sola linea del cuerpo. No lo necesitamos para nada.
"""

import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlunparse

import httpx

from checker.validator import ip_es_interna, resolver_dominio, validar_url

# Cuanto esperamos antes de rendirnos. Un programa que espera para siempre
# es un programa roto.
TIEMPO_LIMITE = 5.0

# Tope para la cadena COMPLETA. Sin esto, 10 saltos de 5 segundos son 50
# segundos: una peticion a la API colgada casi un minuto.
TIEMPO_TOTAL = 20.0

# Quien decimos ser. Es de buena educacion identificarse, y ademas algunos
# sitios bloquean a quien no manda User-Agent.
AGENTE = "URL-Health-Checker/0.1 (proyecto educativo)"


class DestinoNoPermitido(Exception):
    """La URL resolvio a una direccion interna."""


class DestinoNoResoluble(Exception):
    """El DNS no supo contestar por ese dominio."""


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


def ordenar_ips(ips: list[str]) -> list[str]:
    """IPv4 primero, IPv6 despues.

    Importa: muchas computadoras tienen IPv6 configurado pero sin salida
    real. Si eligieramos la IPv6 primero, fallarian sitios que antes
    funcionaban. Se intentan en este orden hasta que una conecte.
    """
    return [ip for ip in ips if ":" not in ip] + [ip for ip in ips if ":" in ip]


def fijar_destino(url: str) -> tuple[list[str], str, dict[str, str], dict[str, str]]:
    """Resuelve el DNS UNA vez, valida las IPs y prepara la peticion.

    Devuelve (ips validadas, plantilla de url, cabeceras, extensiones).
    La plantilla lleva '{ip}' donde va la direccion, para poder probar
    varias sin volver a resolver nada.

    Lanza DestinoNoPermitido si alguna IP es interna, y DestinoNoResoluble
    si el DNS no contesta.
    """
    partes = urlparse(url)
    host = partes.hostname
    if not host:
        raise DestinoNoPermitido("La URL no tiene dominio")

    es_https = partes.scheme.lower() == "https"
    puerto = partes.port or (443 if es_https else 80)

    try:
        ips = resolver_dominio(host)
    except (socket.gaierror, UnicodeError, ValueError) as error:
        raise DestinoNoResoluble(f"El DNS no resolvio '{host}'") from error

    if not ips:
        raise DestinoNoResoluble(f"El DNS no devolvio ninguna IP para '{host}'")

    # Basta con que UNA sea interna para desconfiar de todo el dominio.
    internas = [ip for ip in ips if ip_es_interna(ip)]
    if internas:
        raise DestinoNoPermitido(
            f"Apunta a una direccion interna ({', '.join(internas)})")

    # La plantilla con {ip} en el lugar de la direccion.
    plantilla = urlunparse(partes._replace(netloc="{ip}:" + str(puerto)))

    # El Host lleva el puerto solo si no es el estandar del esquema.
    host_cabecera = host if puerto in (80, 443) else f"{host}:{puerto}"

    return (
        ordenar_ips(ips),
        plantilla,
        {"Host": host_cabecera},
        # sni_hostname hace que el certificado se verifique contra el
        # NOMBRE y no contra la IP. Sin esto, fijar la IP romperia HTTPS.
        {"sni_hostname": host},
    )


def _direccion(ip: str) -> str:
    """Las IPv6 van entre corchetes dentro de una URL."""
    return f"[{ip}]" if ":" in ip else ip


def revisar_salud(url: str, tiempo_limite: float = TIEMPO_LIMITE) -> Salud:
    """Hace UNA peticion al sitio y reporta como le fue.

    No sigue redirects: si el sitio contesta 301, lo anotamos y ya.
    Seguir la cadena es trabajo de seguir_cadena().
    """
    inicio = time.perf_counter()

    def transcurrido() -> int:
        """Milisegundos desde que empezamos. Se calcula igual si hubo error."""
        return int((time.perf_counter() - inicio) * 1000)

    # --- Resolver y validar ANTES de conectarse ---
    try:
        ips, plantilla, cabeceras, extensiones = fijar_destino(url)
    except DestinoNoPermitido as error:
        return Salud(categoria="ERROR", razon=str(error),
                     tiempo_ms=transcurrido(), tipo_error="ssrf")
    except DestinoNoResoluble as error:
        return Salud(categoria="ERROR", razon=str(error),
                     tiempo_ms=transcurrido(), tipo_error="dns")

    def pedir(cliente: httpx.Client, metodo: str, destino: str):
        """Hace la peticion SIN descargar el cuerpo.

        stream() entrega los encabezados y deja el cuerpo sin leer; al
        salir del with, la conexion se cierra. Nunca llega a memoria ni
        un byte de la pagina.
        """
        with cliente.stream(metodo, destino, headers=cabeceras,
                            extensions=extensiones) as respuesta:
            return respuesta.status_code, dict(respuesta.headers)

    ultimo_error: Exception | None = None

    try:
        with httpx.Client(
            follow_redirects=False,
            timeout=tiempo_limite,
            headers={"User-Agent": AGENTE},
            verify=True,
        ) as cliente:
            # Se prueban las IPs en orden hasta que una conecte.
            for ip in ips:
                destino = plantilla.format(ip=_direccion(ip))
                try:
                    codigo, cabeceras_respuesta = pedir(cliente, "HEAD", destino)
                    metodo = "HEAD"

                    # Muchos servidores manejan mal el HEAD y contestan 403,
                    # 405 o 501 aunque la pagina exista. Reintentamos con GET.
                    if codigo in (403, 405, 501):
                        codigo, cabeceras_respuesta = pedir(cliente, "GET", destino)
                        metodo = "GET"
                    break
                except httpx.ConnectError as error:
                    # Si es un problema de certificado no tiene caso probar
                    # otra IP: el certificado seria el mismo.
                    if es_error_de_certificado(error):
                        raise
                    ultimo_error = error
            else:
                # Ninguna IP conecto.
                raise ultimo_error or httpx.ConnectError("sin IPs utilizables")

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

    categoria, razon = clasificar(codigo)

    # Si es un redirect, el servidor dice a donde en el encabezado "Location".
    # Las cabeceras de httpx no distinguen mayusculas; el dict() si, asi que
    # se busca en minusculas, que es como las entrega.
    destino = cabeceras_respuesta.get("location") if categoria == "REDIRECCION" else None

    return Salud(
        categoria=categoria,
        codigo=codigo,
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


def seguir_cadena(url: str, max_saltos: int = MAX_SALTOS,
                  tiempo_total: float = TIEMPO_TOTAL) -> Cadena:
    """Sigue las redirecciones una por una hasta llegar al destino final.

    En CADA salto volvemos a validar la URL. Ese es el punto de todo esto:
    una cadena puede empezar en un dominio publico e inocente y terminar
    apuntando a 127.0.0.1. Validar solo la primera URL no sirve de nada.

    tiempo_total es el tope para TODA la cadena. Sin el, 10 saltos de 5
    segundos son 50 segundos: una peticion a la API colgada casi un minuto,
    y una forma facil de tumbar el servidor con unas pocas URLs lentas.
    """
    cadena = Cadena()
    actual = url
    ya_visitadas: set[str] = set()
    fin = time.monotonic() + tiempo_total

    for numero in range(1, max_saltos + 1):
        # A cada salto se le da lo que quede del presupuesto total, nunca
        # mas de lo que le toca por si solo.
        restante = fin - time.monotonic()
        if restante <= 0:
            cadena.url_final = actual
            cadena.salud_final = None
            cadena.problema = (f"La cadena tardo mas de {tiempo_total:g} segundos "
                               f"en total y se corto")
            break

        salud = revisar_salud(actual, tiempo_limite=min(TIEMPO_LIMITE, restante))
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
