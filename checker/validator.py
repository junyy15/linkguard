"""
Modulo 0 - Validador de URLs.

Primera linea de defensa. Antes de visitar cualquier enlace revisamos:
  1. Que este bien escrito.
  2. Que use http o https (nada de javascript:, file:, data:).
  3. Que NO apunte a una direccion interna (guardia anti-SSRF).

Si algo no se puede comprobar, se rechaza. Lista blanca, no lista negra.
"""

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

# Solo estos dos esquemas nos interesan. Cualquier otro se rechaza.
ESQUEMAS_PERMITIDOS = {"http", "https"}

# Las URLs de verdad casi nunca pasan de aqui. Un texto gigante suele ser un ataque.
LARGO_MAXIMO = 2048

# Detecta si el texto ya trae un esquema al inicio, por ejemplo "https:" o "javascript:".
PATRON_ESQUEMA = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:")


@dataclass
class Validacion:
    """El resultado del validador, empaquetado en un solo objeto."""

    ok: bool
    url: str | None = None          # la URL ya limpia y normalizada
    motivo: str | None = None       # por que se rechazo (solo si ok es False)
    ips: list[str] = field(default_factory=list)  # a que IPs apunta el dominio


def normalizar(texto: str) -> str:
    """Limpia espacios y agrega https:// si el usuario no escribio el esquema.

    Ojo con el detalle: solo agregamos https:// si NO hay ningun esquema.
    Si escribieramos 'https://' delante de 'javascript:alert(1)' estariamos
    disfrazando un esquema peligroso y el siguiente paso ya no lo detectaria.
    """
    texto = texto.strip()
    if not PATRON_ESQUEMA.match(texto):
        texto = "https://" + texto
    return texto


def ip_es_interna(ip_texto: str) -> bool:
    """Devuelve True si la IP pertenece a la red interna, al propio equipo,
    o a cualquier rango que no sea internet publico.

    Esta funcion es el corazon del guardia anti-SSRF.
    """
    ip = ipaddress.ip_address(ip_texto)

    # Truco de evasion: ::ffff:127.0.0.1 es una IPv6 que en realidad
    # envuelve una IPv4. La desenvolvemos antes de juzgarla.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    return (
        ip.is_private        # 10.x, 172.16-31.x, 192.168.x  (redes caseras y de oficina)
        or ip.is_loopback    # 127.0.0.1  (tu propia maquina)
        or ip.is_link_local  # 169.254.x  (incluye los metadatos de la nube)
        or ip.is_reserved    # rangos apartados por la IANA
        or ip.is_multicast   # 224.x
        or ip.is_unspecified # 0.0.0.0
    )


def resolver_dominio(host: str) -> list[str]:
    """Pregunta al DNS a que IPs corresponde un dominio.

    Devuelve una lista porque un dominio puede apuntar a varias IPs a la vez
    (IPv4 e IPv6, o varios servidores). Tenemos que revisarlas TODAS: basta
    con que una sea interna para desconfiar.

    Lanza socket.gaierror si el dominio no existe.
    """
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    # Cada 'info' es una tupla; la IP vive en info[4][0].
    # set(...) quita repetidos, sorted(...) los deja en orden estable.
    return sorted({info[4][0] for info in infos})


def validar_url(entrada: str) -> Validacion:
    """Revisa una URL de principio a fin y devuelve un objeto Validacion."""

    # --- Paso 1: que no venga vacia ---
    if not entrada or not entrada.strip():
        return Validacion(ok=False, motivo="La URL esta vacia")

    url = normalizar(entrada)

    # --- Paso 2: largo razonable ---
    if len(url) > LARGO_MAXIMO:
        return Validacion(ok=False, motivo=f"La URL es demasiado larga ({len(url)} caracteres)")

    # --- Paso 3: partirla en pedazos ---
    # urlparse convierte 'https://ejemplo.com:8080/ruta' en piezas separadas:
    # scheme='https', hostname='ejemplo.com', port=8080, path='/ruta'
    try:
        partes = urlparse(url)
    except ValueError as error:
        return Validacion(ok=False, motivo=f"La URL esta mal formada: {error}")

    # --- Paso 4: solo http y https ---
    esquema = partes.scheme.lower()
    if esquema not in ESQUEMAS_PERMITIDOS:
        return Validacion(ok=False, motivo=f"Esquema no permitido: '{esquema}:'")

    # --- Paso 5: que tenga dominio ---
    # .hostname ya viene en minusculas y sin el puerto. Puede lanzar
    # ValueError si el puerto es basura, por eso el try.
    try:
        host = partes.hostname
        # Pedir el puerto es lo que dispara la revision: si no esta entre
        # 1 y 65535, esta propiedad lanza ValueError y cae en el except.
        _ = partes.port
    except ValueError as error:
        return Validacion(ok=False, motivo=f"La URL esta mal formada: {error}")

    if not host:
        return Validacion(ok=False, motivo="La URL no tiene dominio")

    # --- Paso 6: nada de usuario:contrasena@dominio ---
    # Truco clasico de phishing: https://www.banco.com@sitio-malo.com
    # A simple vista parece el banco, pero el dominio real es sitio-malo.com.
    if partes.username or partes.password:
        return Validacion(
            ok=False,
            motivo="La URL lleva credenciales antes del dominio (truco comun de phishing)",
        )

    # --- Paso 7: EL GUARDIA ANTI-SSRF ---
    try:
        ips = resolver_dominio(host)
    except socket.gaierror:
        return Validacion(ok=False, motivo=f"El dominio '{host}' no existe o no responde el DNS")
    except (UnicodeError, ValueError) as error:
        return Validacion(ok=False, motivo=f"Dominio invalido: {error}")

    if not ips:
        return Validacion(ok=False, motivo=f"El dominio '{host}' no devolvio ninguna IP")

    internas = [ip for ip in ips if ip_es_interna(ip)]
    if internas:
        return Validacion(
            ok=False,
            motivo=f"Apunta a una direccion interna ({', '.join(internas)}). Bloqueado por seguridad.",
            ips=ips,
        )

    # --- Aprobada ---
    return Validacion(ok=True, url=url, ips=ips)


# Para probar este archivo solo:  python -m checker.validator <url>
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Uso: python checker/validator.py <url>")
        sys.exit(1)

    resultado = validar_url(sys.argv[1])
    print(resultado)
