"""
Heuristicas: el olfato propio de la herramienta.

Google y VirusTotal solo saben de sitios que alguien YA reporto. Un dominio
de phishing recien registrado esta limpio en todas las bases de datos
durante horas o dias. Eso se llama ataque de dia cero, y es cuando mas
daño hace.

Estas reglas no miran la reputacion, miran la FORMA del engaño.

Ojo con una cosa: las heuristicas se equivocan mas que las bases de datos.
Por eso ninguna de estas es una regla dura. Todas suman puntos y nada mas.
Un dominio raro no es un dominio malicioso.
"""

import unicodedata
from dataclasses import dataclass
from urllib.parse import urlparse

# Acortadores conocidos. No son malos por si mismos, pero esconden el
# destino, y encadenar varios es una tecnica clasica de ocultamiento.
ACORTADORES = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "bl.ink",
    "s.id", "t.ly", "short.io", "lnkd.in", "db.tt", "qr.ae", "adf.ly",
}

# Marcas que mas suplantan. La lista corta a proposito: cada entrada de mas
# es una posibilidad de falso positivo.
MARCAS = {
    "google", "facebook", "instagram", "whatsapp", "youtube", "amazon",
    "apple", "microsoft", "netflix", "paypal", "spotify", "linkedin",
    "twitter", "tiktok", "dropbox", "github", "steam", "binance",
    "bancomer", "banorte", "santander", "bbva", "hsbc", "citibanamex",
    "mercadolibre", "mercadopago", "oxxo", "sat", "correos",
}

# Sufijos de dos partes. Sin esto, el "dominio registrable" de
# 'algo.com.mx' se calcularia como 'com.mx', que esta mal.
#
# NOTA HONESTA: esto es una aproximacion. La solucion correcta es la
# Public Suffix List de Mozilla (la libreria tldextract la trae). Para un
# proyecto educativo esta lista cubre lo que vamos a ver; para produccion
# habria que usar la lista de verdad.
SUFIJOS_COMPUESTOS = {
    "com.mx", "org.mx", "net.mx", "edu.mx", "gob.mx",
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.br", "com.ar", "com.co", "com.es", "com.au", "co.jp", "com.cn",
}


@dataclass
class Hallazgo:
    """Algo que nos llamo la atencion, con su peso."""

    texto: str
    peso: int


# =====================================================================
#  Piezas sueltas
# =====================================================================

def dominio_registrable(host: str) -> str:
    """El dominio que alguien pudo comprar.

    De 'www.paypal.com.seguro.xyz' devuelve 'seguro.xyz'.
    De 'mail.banco.com.mx' devuelve 'banco.com.mx'.
    """
    partes = host.lower().strip(".").split(".")
    if len(partes) < 2:
        return host.lower()

    ultimos_dos = ".".join(partes[-2:])
    if ultimos_dos in SUFIJOS_COMPUESTOS and len(partes) >= 3:
        return ".".join(partes[-3:])
    return ultimos_dos


def nombre_sin_sufijo(host: str) -> str:
    """Solo la parte comprada: de 'banco.com.mx' devuelve 'banco'."""
    return dominio_registrable(host).split(".")[0]


def decodificar_punycode(host: str) -> str | None:
    """Convierte 'xn--80ak6aa92e.com' en lo que se ve en pantalla.

    Devuelve None si no hay nada que decodificar o si falla.
    """
    if "xn--" not in host.lower():
        return None
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return None


def alfabetos_de(texto: str) -> set[str]:
    """Que alfabetos usa un texto: LATIN, CYRILLIC, GREEK...

    unicodedata.name() da el nombre oficial de cada caracter, por ejemplo
    'CYRILLIC SMALL LETTER A'. La primera palabra es el alfabeto.
    """
    encontrados = set()
    for caracter in texto:
        if not caracter.isalpha():
            continue
        try:
            encontrados.add(unicodedata.name(caracter).split()[0])
        except ValueError:
            encontrados.add("DESCONOCIDO")
    return encontrados


def distancia(a: str, b: str) -> int:
    """Cuantos cambios de una letra hacen falta para pasar de 'a' a 'b'.

    Se llama distancia de Levenshtein. 'amazon' y 'arnazon' estan a 2
    (quitar la m, poner r y n... en realidad 2 operaciones).

    Se construye una tabla donde cada casilla dice: cuantos cambios para
    convertir los primeros i caracteres de 'a' en los primeros j de 'b'.
    Cada casilla se calcula a partir de sus tres vecinas de arriba y de la
    izquierda, eligiendo el camino mas barato.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    # Solo necesitamos la fila anterior, no la tabla completa.
    fila_anterior = list(range(len(b) + 1))
    for i, letra_a in enumerate(a, start=1):
        fila = [i]
        for j, letra_b in enumerate(b, start=1):
            borrar = fila_anterior[j] + 1
            insertar = fila[j - 1] + 1
            sustituir = fila_anterior[j - 1] + (letra_a != letra_b)
            fila.append(min(borrar, insertar, sustituir))
        fila_anterior = fila
    return fila_anterior[-1]


def es_acortador(host: str) -> bool:
    return dominio_registrable(host) in ACORTADORES


# =====================================================================
#  Las heuristicas
# =====================================================================

def revisar_dominio(host: str) -> list[Hallazgo]:
    """Revisa un solo dominio buscando señales de suplantacion."""
    hallazgos: list[Hallazgo] = []
    if not host:
        return hallazgos

    host = host.lower()
    registrable = dominio_registrable(host)
    nombre = nombre_sin_sufijo(host)

    # --- 1. Punycode: letras de otros alfabetos disfrazadas ---
    visible = decodificar_punycode(host)
    if visible:
        alfabetos = alfabetos_de(visible)
        # Mezclar alfabetos en un mismo dominio casi nunca es legitimo:
        # es justo lo que se hace para imitar una marca.
        if len(alfabetos - {"DESCONOCIDO"}) > 1:
            hallazgos.append(Hallazgo(
                f"El dominio mezcla alfabetos ({', '.join(sorted(alfabetos))}) "
                f"y en pantalla se ve como '{visible}'. Tecnica clasica de "
                f"suplantacion.", peso=3))
        else:
            hallazgos.append(Hallazgo(
                f"El dominio usa caracteres especiales: en pantalla se ve "
                f"como '{visible}'", peso=1))

    # --- 2. Una marca conocida metida donde no manda ---
    # En 'paypal.com.seguro.xyz' el dominio real es seguro.xyz, pero a
    # simple vista lees paypal.com.
    etiquetas_previas = host[: -len(registrable)].strip(".").split(".")
    for etiqueta in etiquetas_previas:
        if etiqueta in MARCAS:
            hallazgos.append(Hallazgo(
                f"Usa el nombre '{etiqueta}' en el subdominio, pero el dominio "
                f"real es '{registrable}'", peso=3))
            break

    # --- 3. Typosquatting: casi igual a una marca, pero no igual ---
    if nombre not in MARCAS and len(nombre) >= 5:
        for marca in MARCAS:
            if abs(len(nombre) - len(marca)) > 2:
                continue
            separacion = distancia(nombre, marca)
            if 1 <= separacion <= 2:
                hallazgos.append(Hallazgo(
                    f"El dominio '{nombre}' se parece mucho a '{marca}' "
                    f"({separacion} letra(s) de diferencia)", peso=3))
                break

    # --- 4. Señales debiles de la forma del dominio ---
    etiquetas = host.split(".")
    if len(etiquetas) >= 5:
        hallazgos.append(Hallazgo(
            f"Dominio con muchos niveles ({len(etiquetas)} partes)", peso=1))

    if nombre.count("-") >= 3:
        hallazgos.append(Hallazgo(
            f"El dominio tiene muchos guiones ('{nombre}')", peso=1))

    return hallazgos


def revisar_cadena(urls: list[str]) -> list[Hallazgo]:
    """Revisa el recorrido completo buscando ocultamiento."""
    hallazgos: list[Hallazgo] = []

    acortadores_usados = []
    for url in urls:
        try:
            host = urlparse(url).hostname or ""
        except ValueError:
            continue
        if host and es_acortador(host):
            dominio = dominio_registrable(host)
            if dominio not in acortadores_usados:
                acortadores_usados.append(dominio)

    if len(acortadores_usados) >= 2:
        hallazgos.append(Hallazgo(
            f"Pasa por {len(acortadores_usados)} acortadores distintos "
            f"({', '.join(acortadores_usados)}): cada capa esconde la siguiente",
            peso=3))
    elif len(acortadores_usados) == 1:
        hallazgos.append(Hallazgo(
            f"Es un enlace acortado ({acortadores_usados[0]}): el destino "
            f"no se ve a simple vista", peso=1))

    return hallazgos


# Para probar este archivo solo:  python -m checker.heuristicas <dominio>
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Uso: python -m checker.heuristicas <dominio o url>")
        sys.exit(1)

    entrada = sys.argv[1]
    anfitrion = urlparse(entrada).hostname or entrada

    print(f"\nDominio:     {anfitrion}")
    print(f"Registrable: {dominio_registrable(anfitrion)}")
    visible = decodificar_punycode(anfitrion)
    if visible:
        print(f"Se ve como:  {visible}")

    encontrados = revisar_dominio(anfitrion) + revisar_cadena([entrada])
    if not encontrados:
        print("\nSin hallazgos.\n")
    else:
        print()
        for hallazgo in encontrados:
            print(f"  +{hallazgo.peso}  {hallazgo.texto}")
        print()
