"""
Banco de pruebas VISUAL del proyecto.

    ⚠ DESDE LA SEMANA 3 DIA 4, QUIEN MANDA ES PYTEST.

    Las pruebas de verdad viven en tests/ y se corren con:

        .\\pruebas.bat                -> las 125
        .\\pruebas.bat -m "not red"   -> las 108 que no tocan internet (1 seg)

    Este archivo se queda porque sirve para OTRA cosa: VER la herramienta
    trabajando, con sus tablas y colores, mientras aprendes que hace cada
    modulo. pytest te dice si algo se rompio; esto te enseña como funciona.

    Deuda conocida: varias comprobaciones estan duplicadas entre este
    archivo y tests/. Si alguna vez se contradicen, la buena es la de
    tests/, y hay que recortar este archivo para que solo muestre.

    python probar.py                 -> corre TODO (los tres bancos)
    python probar.py --validador     -> solo el Modulo 0
    python probar.py --salud         -> solo el Modulo 1 (peticiones)
    python probar.py --cadena        -> solo las redirecciones
    python probar.py --amenazas      -> solo Google Safe Browsing
    python probar.py --virustotal    -> solo VirusTotal, limitador y cache
    python probar.py --scanner       -> solo el coordinador y los hilos
    python probar.py --scoring       -> solo el criterio del veredicto
    python probar.py --heuristicas   -> solo el olfato propio (punycode, typos)
    python probar.py <url>           -> prueba una sola URL

Cada banco devuelve cuantos fallos tuvo, y al final se suman. Si algo falla,
el programa termina con codigo 1: asi otros programas pueden saber que hubo
un problema sin tener que leer la pantalla.
"""

import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import time
from concurrent.futures import ThreadPoolExecutor

import checker.cache as cache
import checker.health as health
import checker.heuristicas as heuristicas
import checker.scoring as scoring
import checker.threats as threats
from checker.health import Cadena, Salto, Salud, clasificar, revisar_salud, seguir_cadena
from checker.scanner import Analisis, analizar
from checker.threats import (
    Amenaza,
    Limitador,
    ResultadoAmenazas,
    consultar_safe_browsing,
    consultar_virustotal,
)
from checker.validator import Validacion, validar_url

console = Console()


def marca(bien: bool) -> str:
    """La palomita o la tache, siempre igual en todo el archivo."""
    return "[bold green]OK[/bold green]" if bien else "[bold red]FALLO[/bold red]"


def etiqueta(url: str) -> str:
    """Nombre legible, porque una URL vacia no se ve en pantalla."""
    if url == "":
        return "(vacia)"
    if not url.strip():
        return "(solo espacios)"
    return url


# =====================================================================
#  BANCO 1 - El validador (Modulo 0)
# =====================================================================

# (url, esperamos que pase?, por que nos importa)
CASOS_VALIDADOR = [
    ("https://example.com",                        True,  "Sitio normal y correcto"),
    ("example.com",                                True,  "Sin https:// - debe agregarlo solo"),
    ("https://github.com/anthropics",              True,  "Con ruta"),
    ("javascript:alert(1)",                        False, "Esquema peligroso: codigo, no pagina"),
    ("file:///C:/Windows/",                        False, "Esquema peligroso: archivos locales"),
    ("data:text/html,<h1>hola</h1>",               False, "Esquema peligroso: pagina incrustada"),
    ("http://127.0.0.1:8080/admin",                False, "SSRF: tu propia maquina"),
    ("http://192.168.1.1/",                        False, "SSRF: tu router"),
    ("http://10.0.0.5/",                           False, "SSRF: red interna"),
    ("http://169.254.169.254/latest/meta-data/",   False, "SSRF: metadatos de la nube (Capital One)"),
    ("http://localhost",                           False, "SSRF: nombre de tu propia maquina"),
    ("http://[::1]/",                              False, "SSRF: loopback en IPv6"),
    ("http://0.0.0.0",                             False, "SSRF: direccion sin especificar"),
    ("https://www.banco.com@sitio-malo.com",       False, "Phishing: el dominio real va despues del @"),
    ("http://dominio-que-no-existe-98765.com",     False, "El DNS no lo resuelve"),
    ("http://example.com:99999",                   False, "Puerto imposible (el maximo es 65535)"),
    ("",                                           False, "Entrada vacia"),
    ("   ",                                        False, "Solo espacios"),
]


def probar_validador(detalle: bool = True) -> tuple[int, int]:
    """Corre el banco del validador. Devuelve (fallos, total)."""

    # Una sola llamada por URL: el resultado se guarda y se reutiliza.
    resultados = [
        (url, esperado, descripcion, validar_url(url))
        for url, esperado, descripcion in CASOS_VALIDADOR
    ]

    tabla = Table(title="Modulo 0 - Validador", title_style="bold cyan", pad_edge=False)
    tabla.add_column("", width=6)
    tabla.add_column("URL", style="cyan", overflow="fold")
    tabla.add_column("", justify="right", width=8)

    fallos = []
    for url, esperado, descripcion, resultado in resultados:
        bien = resultado.ok == esperado
        if not bien:
            fallos.append((url, esperado, descripcion, resultado))
        veredicto = "[green]paso[/green]" if resultado.ok else "[red]rechazo[/red]"
        tabla.add_row(marca(bien), etiqueta(url), veredicto)

    console.print()
    console.print(tabla)

    for url, esperado, descripcion, resultado in fallos:
        esperabamos = "que la rechazara" if not esperado else "que la aceptara"
        paso = "la acepto" if resultado.ok else f"la rechazo: {resultado.motivo}"
        console.print(Panel(
            f"[cyan]{etiqueta(url)}[/cyan]\n\nCaso: {descripcion}\n"
            f"Esperabamos [bold]{esperabamos}[/bold], pero [bold]{paso}[/bold].",
            title="[bold red]FALLO[/bold red]", border_style="red",
        ))

    if detalle:
        console.print("\n[bold]Motivo de cada rechazo:[/bold]\n")
        for url, _e, _d, resultado in resultados:
            if not resultado.ok:
                console.print(f"  [cyan]{etiqueta(url)}[/cyan]")
                console.print(f"     [yellow]{resultado.motivo}[/yellow]")
        console.print()

    return len(fallos), len(resultados)


# =====================================================================
#  BANCO 2 - Salud del enlace (Modulo 1)
# =====================================================================

# Estas NO salen a internet: prueban solo la funcion que traduce numeros.
CASOS_CLASIFICAR = [
    (200, "OK"), (204, "OK"),
    (301, "REDIRECCION"), (302, "REDIRECCION"),
    (401, "BLOQUEADO"), (403, "BLOQUEADO"), (429, "BLOQUEADO"),
    (404, "ROTO"), (410, "ROTO"),
    (500, "ROTO"), (503, "ROTO"),
]

# Estas si salen a internet. (url, categoria esperada, descripcion, limite)
CASOS_SALUD = [
    ("https://example.com",           "OK",          "Sitio que responde bien", 5.0),
    ("http://github.com",             "REDIRECCION", "Manda de http a https", 5.0),
    ("https://www.google.com/pagina-que-no-existe-12345",
                                      "ROTO",        "Pagina que no existe (404)", 5.0),
    ("https://expired.badssl.com/",   "ERROR",       "Certificado vencido", 5.0),
    ("https://self-signed.badssl.com/", "ERROR",     "Certificado hecho en casa", 5.0),
    ("https://example.com",           "ERROR",       "Timeout forzado (limite 0.001 s)", 0.001),
]


def probar_salud(detalle: bool = True) -> tuple[int, int]:
    """Corre el banco de salud. Devuelve (fallos, total)."""

    # --- Parte A: logica pura, sin internet ---
    tabla_logica = Table(title="Modulo 1a - Codigos HTTP (sin internet)",
                         title_style="bold cyan", pad_edge=False)
    tabla_logica.add_column("", width=6)
    tabla_logica.add_column("Codigo", justify="right", width=7)
    tabla_logica.add_column("Esperado")
    tabla_logica.add_column("Obtenido")

    fallos = 0
    for codigo, esperado in CASOS_CLASIFICAR:
        obtenido, _texto = clasificar(codigo)
        bien = obtenido == esperado
        if not bien:
            fallos += 1
        tabla_logica.add_row(marca(bien), str(codigo), esperado,
                             obtenido if bien else f"[red]{obtenido}[/red]")

    console.print()
    console.print(tabla_logica)

    # --- Parte B: peticiones reales ---
    resultados = [
        (descripcion, esperado, revisar_salud(url, tiempo_limite=limite))
        for url, esperado, descripcion, limite in CASOS_SALUD
    ]

    tabla_red = Table(title="Modulo 1b - Peticiones reales", title_style="bold cyan",
                      pad_edge=False)
    tabla_red.add_column("", width=6)
    tabla_red.add_column("Caso", overflow="fold")
    tabla_red.add_column("Esperado", justify="center")
    tabla_red.add_column("Obtenido", justify="center")
    tabla_red.add_column("ms", justify="right", width=6)

    for descripcion, esperado, salud in resultados:
        bien = salud.categoria == esperado
        if not bien:
            fallos += 1
        tabla_red.add_row(
            marca(bien), descripcion, esperado,
            salud.categoria if bien else f"[red]{salud.categoria}[/red]",
            str(salud.tiempo_ms if salud.tiempo_ms is not None else "-"),
        )

    console.print()
    console.print(tabla_red)

    if detalle:
        console.print("\n[bold]Que contesto cada sitio:[/bold]\n")
        for descripcion, _esperado, salud in resultados:
            codigo = f"[bold]{salud.codigo}[/bold] " if salud.codigo else ""
            console.print(f"  [cyan]{descripcion}[/cyan]")
            console.print(f"     {codigo}[yellow]{salud.razon}[/yellow]")
            if salud.destino:
                console.print(f"     [dim]-> {salud.destino}[/dim]")
        console.print()

    return fallos, len(CASOS_CLASIFICAR) + len(CASOS_SALUD)


# =====================================================================
#  BANCO 3 - Cadena de redirecciones
# =====================================================================
#
# Para probar "una cadena que redirige a 127.0.0.1" haria falta un servidor
# malicioso de verdad. Como no lo tenemos, SIMULAMOS las respuestas: le
# cambiamos temporalmente a seguir_cadena() la funcion que consulta internet
# por una falsa que devuelve lo que nosotros le dictamos.


def redireccion_a(destino: str) -> Salud:
    """Respuesta falsa que dice 've a esta otra direccion'."""
    return Salud(categoria="REDIRECCION", codigo=301, razon="simulado",
                 tiempo_ms=1, destino=destino, metodo="HEAD")


def llegada() -> Salud:
    """Respuesta falsa que dice 'aqui se acaba, todo bien'."""
    return Salud(categoria="OK", codigo=200, razon="simulado",
                 tiempo_ms=1, metodo="HEAD")


def simular(guion: dict[str, Salud], inicio: str, max_saltos: int = 10):
    """Corre seguir_cadena() con respuestas dictadas por nosotros.

    El try/finally es importante: pase lo que pase, la funcion de verdad
    vuelve a su lugar. Si no, las pruebas siguientes hablarian con el doble.
    """
    original = health.revisar_salud
    health.revisar_salud = lambda url, tiempo_limite=5.0: guion.get(url, llegada())
    try:
        return health.seguir_cadena(inicio, max_saltos=max_saltos)
    finally:
        health.revisar_salud = original


def probar_cadena(detalle: bool = True) -> tuple[int, int]:
    """Corre el banco de redirecciones. Devuelve (fallos, total)."""
    casos = []

    # 1. Empieza publico y acaba apuntando a tu maquina.
    cadena = simular({
        "https://example.com/inicio": redireccion_a("https://example.com/paso2"),
        "https://example.com/paso2": redireccion_a("http://127.0.0.1/admin"),
    }, "https://example.com/inicio")
    casos.append(("Redirige a 127.0.0.1 en el salto 2", "cortar la cadena",
                  "bloquead" in (cadena.problema or ""), cadena.problema or "no la corto"))

    # 2. Bucle: A manda a B, B manda a A.
    cadena = simular({
        "https://example.com/a": redireccion_a("https://example.com/b"),
        "https://example.com/b": redireccion_a("https://example.com/a"),
    }, "https://example.com/a")
    casos.append(("Bucle: A manda a B, B manda a A", "detectar el bucle",
                  "circulo" in (cadena.problema or ""), cadena.problema or "no lo detecto"))

    # 3. Baja de https a http.
    cadena = simular({
        "https://example.com/seguro": redireccion_a("http://example.com/inseguro"),
    }, "https://example.com/seguro")
    casos.append(("Pasa de https a http", "marcar baja_seguridad",
                  cadena.baja_seguridad, f"baja_seguridad={cadena.baja_seguridad}"))

    # 4. Location incompleto.
    cadena = simular({
        "https://example.com/uno": redireccion_a("/dos"),
    }, "https://example.com/uno")
    casos.append(("Location relativo '/dos'", "completarlo con el dominio",
                  cadena.url_final == "https://example.com/dos", cadena.url_final))

    # 5. Cadena mas larga que el limite.
    cadena = simular({
        f"https://example.com/{n}": redireccion_a(f"https://example.com/{n + 1}")
        for n in range(1, 20)
    }, "https://example.com/1", max_saltos=5)
    casos.append(("Cadena de 20 saltos, limite de 5", "cortar al llegar al limite",
                  "Demasiadas" in (cadena.problema or ""), cadena.problema or "no la corto"))

    tabla = Table(title="Dia 4 - Situaciones peligrosas (simuladas)",
                  title_style="bold cyan", pad_edge=False)
    tabla.add_column("", width=6)
    tabla.add_column("Situacion", overflow="fold")
    tabla.add_column("Debe", overflow="fold")
    tabla.add_column("Resultado", overflow="fold")

    fallos = 0
    for descripcion, debe, bien, resultado in casos:
        if not bien:
            fallos += 1
        tabla.add_row(marca(bien), descripcion, debe,
                      resultado if bien else f"[red]{resultado}[/red]")

    console.print()
    console.print(tabla)

    # --- Cadenas reales ---
    reales = [
        ("http://github.com", "https://github.com/"),
        ("https://example.com", "https://example.com"),
        ("http://google.com", "http://www.google.com/"),
    ]

    tabla_real = Table(title="Dia 4 - Cadenas reales", title_style="bold cyan",
                       pad_edge=False)
    tabla_real.add_column("", width=6)
    tabla_real.add_column("Entrada", overflow="fold")
    tabla_real.add_column("Destino final", overflow="fold")
    tabla_real.add_column("Saltos", justify="right", width=6)

    for url, esperado in reales:
        cadena = seguir_cadena(url)
        bien = cadena.url_final == esperado
        if not bien:
            fallos += 1
        tabla_real.add_row(marca(bien), url,
                           cadena.url_final if bien else f"[red]{cadena.url_final}[/red]",
                           str(cadena.num_saltos))

    console.print()
    console.print(tabla_real)

    return fallos, len(casos) + len(reales)


# =====================================================================
#  BANCO 4 - Inteligencia de amenazas (Semana 2)
# =====================================================================
#
# Google publica URLs de prueba que SIEMPRE estan en su lista negra.
# Existen justo para esto: comprobar que tu integracion funciona sin
# tener que ir a buscar un sitio malicioso de verdad.

CASOS_AMENAZAS = [
    ("https://example.com", None, "Sitio limpio"),
    ("https://testsafebrowsing.appspot.com/s/phishing.html",
     "SOCIAL_ENGINEERING", "URL de prueba: phishing"),
    ("https://testsafebrowsing.appspot.com/s/malware.html",
     "MALWARE", "URL de prueba: malware"),
    ("https://testsafebrowsing.appspot.com/s/unwanted.html",
     "UNWANTED_SOFTWARE", "URL de prueba: software no deseado"),
]


def probar_amenazas(detalle: bool = True) -> tuple[int, int]:
    """Prueba el cliente de Safe Browsing. Devuelve (fallos, total)."""

    tabla = Table(title="Modulo 2 - Google Safe Browsing", title_style="bold cyan",
                  pad_edge=False)
    tabla.add_column("", width=6)
    tabla.add_column("Caso", overflow="fold")
    tabla.add_column("Esperado", overflow="fold")
    tabla.add_column("Obtenido", overflow="fold")

    # Una sola consulta por caso: cada llamada gasta cuota de la API.
    resultados = [
        (descripcion, tipo_esperado, consultar_safe_browsing([url]))
        for url, tipo_esperado, descripcion in CASOS_AMENAZAS
    ]

    fallos = 0
    for descripcion, tipo_esperado, resultado in resultados:
        tipos = {a.tipo for a in resultado.amenazas}

        if tipo_esperado is None:
            bien = resultado.limpio
            esperado = "limpio"
            obtenido = "limpio" if resultado.limpio else resultado.resumen
        else:
            bien = tipo_esperado in tipos
            esperado = tipo_esperado
            obtenido = ", ".join(sorted(tipos)) if tipos else resultado.resumen

        if not bien:
            fallos += 1
        tabla.add_row(marca(bien), descripcion, esperado,
                      obtenido if bien else f"[red]{obtenido}[/red]")

    # --- La regla mas importante del modulo ---
    # Sin llave, el resultado debe ser DESCONOCIDO, nunca "limpio".
    # Lo probamos quitandole la llave temporalmente.
    original = threats.config.obtener
    threats.config.obtener = lambda nombre: None
    try:
        sin_llave = consultar_safe_browsing(["https://example.com"])
    finally:
        threats.config.obtener = original

    bien = (not sin_llave.consultado) and (not sin_llave.limpio)
    if not bien:
        fallos += 1
    tabla.add_row(marca(bien), "Sin llave de API",
                  "desconocido, NO limpio",
                  f"consultado={sin_llave.consultado}, limpio={sin_llave.limpio}")

    console.print()
    console.print(tabla)

    if detalle:
        console.print("\n[bold]Que contesto Google de cada uno:[/bold]\n")
        for descripcion, _tipo, resultado in resultados:
            console.print(f"  [cyan]{descripcion}[/cyan]")
            console.print(f"     [yellow]{resultado.resumen}[/yellow]")
        console.print()

    return fallos, len(CASOS_AMENAZAS) + 1


def probar_virustotal(detalle: bool = True) -> tuple[int, int]:
    """Prueba VirusTotal, el limitador y el cache. Devuelve (fallos, total)."""

    tabla = Table(title="Modulo 2b - VirusTotal, limitador y cache",
                  title_style="bold cyan", pad_edge=False)
    tabla.add_column("", width=6)
    tabla.add_column("Caso", overflow="fold")
    tabla.add_column("Debe", overflow="fold")
    tabla.add_column("Resultado", overflow="fold")

    fallos = 0

    def anotar(descripcion: str, debe: str, bien: bool, resultado: str) -> None:
        nonlocal fallos
        if not bien:
            fallos += 1
        tabla.add_row(marca(bien), descripcion, debe,
                      resultado if bien else f"[red]{resultado}[/red]")

    # --- 1. Un sitio limpio (2 peticiones: la 2a debe venir del cache) ---
    limpio = consultar_virustotal("https://example.com")
    anotar("Sitio limpio", "sin detecciones", limpio.limpio, limpio.resumen)

    otra_vez = consultar_virustotal("https://example.com")
    anotar("Segunda consulta igual", "venir del cache", otra_vez.del_cache,
           "del cache" if otra_vez.del_cache else "volvio a preguntar")

    # --- 2. Una URL que VirusTotal si tiene marcada ---
    sucio = consultar_virustotal("https://testsafebrowsing.appspot.com/s/phishing.html")
    maliciosos = sucio.estadisticas.get("malicious", 0)
    anotar("URL de prueba de Google", "maliciosos > 0", maliciosos > 0,
           f"{maliciosos} antivirus la marcan")

    # --- 3. Sin llave: desconocido, NUNCA limpio ---
    original = threats.config.obtener
    threats.config.obtener = lambda nombre: None
    try:
        sin_llave = consultar_virustotal("https://example.com")
    finally:
        threats.config.obtener = original
    anotar("Sin llave de API", "desconocido, NO limpio",
           (not sin_llave.consultado) and (not sin_llave.limpio),
           f"consultado={sin_llave.consultado}, limpio={sin_llave.limpio}")

    # --- 4. El identificador que pide VirusTotal ---
    # Su documentacion dice: base64 seguro para URLs, sin los = del final.
    identificador = threats.id_de_url("https://example.com")
    anotar("id_de_url() sin relleno", "no termina en '='",
           not identificador.endswith("="), identificador[:24] + "...")

    # --- 5. El limitador (sin internet, con una ventana chiquita) ---
    # 2 permisos cada 0.5 s: el tercero tiene que esperar.
    limitador = Limitador(maximo=2, ventana=0.5)
    limitador.esperar()
    limitador.esperar()
    inicio = time.monotonic()
    limitador.esperar()
    tardanza = time.monotonic() - inicio
    anotar("Limitador: 3a peticion de 2 por ventana", "esperar su turno",
           tardanza >= 0.4, f"espero {tardanza:.2f} s")

    # --- 6. El cache caduca ---
    clave = "prueba:caducidad"
    vigencia_original = cache.VIGENCIA_LIMPIO
    cache.VIGENCIA_LIMPIO = 0  # todo caduca de inmediato
    try:
        cache.guardar(clave, {"x": 1}, limpio=True)
        caducado = cache.leer(clave)
    finally:
        cache.VIGENCIA_LIMPIO = vigencia_original
    anotar("Cache con vigencia agotada", "devolver None", caducado is None,
           f"devolvio {caducado}")

    console.print()
    console.print(tabla)

    if detalle and limpio.estadisticas:
        e = limpio.estadisticas
        console.print(f"\n[dim]example.com en VirusTotal: maliciosos={e['malicious']}, "
                      f"sospechosos={e['suspicious']}, inofensivos={e['harmless']}, "
                      f"sin deteccion={e['undetected']}[/dim]")
        vigentes, caducadas = cache.estado()
        console.print(f"[dim]Cache: {vigentes} entradas vigentes, "
                      f"{caducadas} caducadas[/dim]\n")

    return fallos, 7


# =====================================================================
#  BANCO 5 - El coordinador (Semana 2, Dia 4)
# =====================================================================

def probar_scanner(detalle: bool = True) -> tuple[int, int]:
    """Prueba analizar() y la seguridad con hilos. Devuelve (fallos, total)."""

    tabla = Table(title="Coordinador - analizar() y trabajo en paralelo",
                  title_style="bold cyan", pad_edge=False)
    tabla.add_column("", width=6)
    tabla.add_column("Caso", overflow="fold")
    tabla.add_column("Debe", overflow="fold")
    tabla.add_column("Resultado", overflow="fold")

    fallos = 0

    def anotar(descripcion: str, debe: str, bien: bool, resultado: str) -> None:
        nonlocal fallos
        if not bien:
            fallos += 1
        tabla.add_row(marca(bien), descripcion, debe,
                      resultado if bien else f"[red]{resultado}[/red]")

    # --- 1. Un analisis completo trae todas las piezas ---
    completo = analizar("https://example.com")
    tiene_todo = all([
        completo.paso_validacion,
        completo.cadena is not None,
        completo.google is not None,
        completo.virustotal is not None,
    ])
    anotar("Analisis completo", "traer las 4 piezas", tiene_todo,
           f"validacion+cadena+google+vt en {completo.tiempo_ms} ms")

    # --- 2. Una URL invalida NO debe gastar ni una peticion ---
    # Si la validacion falla, seguir adelante seria tirar tiempo y cuota.
    rechazada = analizar("javascript:alert(1)")
    corto_temprano = (not rechazada.paso_validacion
                      and rechazada.cadena is None
                      and rechazada.google is None)
    anotar("URL invalida", "cortar sin consultar nada", corto_temprano,
           f"cadena={rechazada.cadena}, google={rechazada.google}")

    # --- 3. Se puede pedir un analisis sin tocar las APIs ---
    sin_apis = analizar("https://example.com", consultar_amenazas=False)
    anotar("consultar_amenazas=False", "no llamar a las APIs",
           sin_apis.google is None and sin_apis.virustotal is None,
           f"google={sin_apis.google}, virustotal={sin_apis.virustotal}")

    # --- 4. El cache aguanta varios hilos escribiendo a la vez ---
    # Sin el candado, dos hilos leen el archivo, cada uno agrega SU clave
    # sobre la version vieja, y el ultimo en escribir borra lo del otro.
    claves = [f"prueba:hilo:{n}" for n in range(12)]
    with ThreadPoolExecutor(max_workers=12) as pool:
        for n, clave in enumerate(claves):
            pool.submit(cache.guardar, clave, {"n": n}, False)

    guardadas = sum(1 for clave in claves if cache.leer(clave) is not None)
    anotar("12 hilos escribiendo el cache", "no perder ninguna",
           guardadas == len(claves), f"{guardadas} de {len(claves)} sobrevivieron")

    console.print()
    console.print(tabla)

    if detalle:
        console.print(f"\n[dim]Un analisis completo de example.com tarda "
                      f"{completo.tiempo_ms} ms (las dos APIs van en paralelo)[/dim]\n")

    return fallos, 4


# =====================================================================
#  BANCO 6 - El motor de puntuacion (Semana 3)
# =====================================================================
#
# Estas pruebas NO tocan internet. Fabricamos analisis a mano y revisamos
# que el veredicto sea el correcto. Son instantaneas, nunca fallan por el
# wifi, y prueban lo unico que importa aqui: el CRITERIO.


def fabricar(google=None, virustotal=None, url_final="https://ejemplo.com",
             tipo_error=None, problema=None, cambia_dominio=False,
             baja_seguridad=False, saltos=1, valida=True, motivo=None) -> Analisis:
    """Arma un Analisis falso para probar el motor de puntuacion."""
    validacion = Validacion(ok=valida, url=url_final if valida else None,
                            motivo=motivo, ips=["93.184.216.34"] if valida else [])
    if not valida:
        return Analisis(entrada=url_final, validacion=validacion)

    salud = Salud(categoria="ERROR" if tipo_error else "OK",
                  codigo=None if tipo_error else 200,
                  razon="fabricado", tiempo_ms=1, tipo_error=tipo_error)

    cadena = Cadena(
        saltos=[Salto(numero=n + 1, url=url_final) for n in range(saltos)],
        url_final=url_final,
        salud_final=salud,
        problema=problema,
        cambia_de_dominio=cambia_dominio,
        baja_seguridad=baja_seguridad,
    )
    return Analisis(entrada=url_final, validacion=validacion, cadena=cadena,
                    google=google, virustotal=virustotal)


def fuente_limpia(nombre: str) -> ResultadoAmenazas:
    return ResultadoAmenazas(fuente=nombre, consultado=True)


def fuente_caida(nombre: str) -> ResultadoAmenazas:
    return ResultadoAmenazas(fuente=nombre, consultado=False, error="fabricado")


def fuente_google_reporta() -> ResultadoAmenazas:
    return ResultadoAmenazas(
        fuente="Google Safe Browsing", consultado=True,
        amenazas=[Amenaza("Google Safe Browsing", "SOCIAL_ENGINEERING", "x")])


def fuente_vt(maliciosos: int, sospechosos: int = 0) -> ResultadoAmenazas:
    resultado = ResultadoAmenazas(
        fuente="VirusTotal", consultado=True,
        estadisticas={"malicious": maliciosos, "suspicious": sospechosos,
                      "harmless": 60, "undetected": 30})
    if maliciosos:
        resultado.amenazas.append(Amenaza("VirusTotal", "MALICIOUS", "x"))
    elif sospechosos:
        resultado.amenazas.append(Amenaza("VirusTotal", "SUSPICIOUS", "x"))
    return resultado


def probar_scoring(detalle: bool = True) -> tuple[int, int]:
    """Prueba el criterio del motor de puntuacion. Sin internet."""

    limpio_g = fuente_limpia("Google Safe Browsing")
    limpio_v = fuente_vt(0)

    casos = [
        # (descripcion, analisis, nivel esperado)
        ("Todo limpio",
         fabricar(limpio_g, limpio_v), scoring.SEGURO),

        ("Google lo reporta",
         fabricar(fuente_google_reporta(), limpio_v), scoring.POSIBLEMENTE_PELIGROSO),

        ("2 antivirus lo marcan",
         fabricar(limpio_g, fuente_vt(2)), scoring.POSIBLEMENTE_PELIGROSO),

        ("Solo 1 antivirus (ruido)",
         fabricar(limpio_g, fuente_vt(1)), scoring.SEGURO),

        ("1 antivirus + destino sin https",
         fabricar(limpio_g, fuente_vt(1), url_final="http://ejemplo.com"),
         scoring.SOSPECHOSO),

        ("Google limpio pero VT lo marca",
         fabricar(limpio_g, fuente_vt(5)), scoring.POSIBLEMENTE_PELIGROSO),

        ("Una fuente caida, nada mas",
         fabricar(fuente_caida("Google Safe Browsing"), limpio_v),
         scoring.SIN_CONFIRMAR),

        ("Fuente caida + amenaza confirmada",
         fabricar(fuente_caida("Google Safe Browsing"), fuente_vt(3)),
         scoring.POSIBLEMENTE_PELIGROSO),

        ("Certificado invalido",
         fabricar(limpio_g, limpio_v, tipo_error="ssl"), scoring.SOSPECHOSO),

        ("Cadena bloqueada por SSRF",
         fabricar(limpio_g, limpio_v, problema="Salto 2 bloqueado: interna"),
         scoring.SOSPECHOSO),

        ("Baja de https a http + cambia de dominio",
         fabricar(limpio_g, limpio_v, url_final="http://otro.com",
                  baja_seguridad=True, cambia_dominio=True),
         scoring.SOSPECHOSO),

        ("URL invalida",
         fabricar(valida=False, motivo="Esquema no permitido"), scoring.RECHAZADA),

        # El bug que encontro la corrida real: el modo lista no consulta las
        # APIs, las fuentes llegan como None, y el veredicto decia "SEGURO"
        # sin haberle preguntado a nadie.
        ("Sin consultar amenazas (las dos en None)",
         fabricar(None, None), scoring.SIN_CONFIRMAR),

        ("Sin amenazas consultadas pero con certificado malo",
         fabricar(None, None, tipo_error="ssl"), scoring.SOSPECHOSO),
    ]

    tabla = Table(title="Modulo 3 - Motor de puntuacion (sin internet)",
                  title_style="bold cyan", pad_edge=False)
    tabla.add_column("", width=6)
    tabla.add_column("Situacion", overflow="fold")
    tabla.add_column("Esperado", overflow="fold")
    tabla.add_column("Obtenido", overflow="fold")

    fallos = 0
    for descripcion, analisis, esperado in casos:
        veredicto = scoring.evaluar(analisis)
        bien = veredicto.seguridad == esperado
        if not bien:
            fallos += 1
        obtenido = f"{veredicto.seguridad} ({veredicto.puntos}p)"
        tabla.add_row(marca(bien), descripcion, esperado,
                      obtenido if bien else f"[red]{obtenido}[/red]")

    # --- La contradiccion: nunca decir "sin señales" si hay señales ---
    con_detalles = scoring.evaluar(
        fabricar(limpio_g, limpio_v, url_final="http://ejemplo.com"))
    coherente = (con_detalles.puntos > 0
                 and "No encontramos señales" not in con_detalles.frase)
    if not coherente:
        fallos += 1
    tabla.add_row(marca(coherente), "Frase coherente con las señales",
                  "no decir 'sin señales' si las hay",
                  con_detalles.frase[:40] + "...")

    # --- La atribucion a Google solo cuando viene de Google ---
    solo_vt = scoring.evaluar(fabricar(limpio_g, fuente_vt(3)))
    sin_atribucion = not solo_vt.cita_a_google
    if not sin_atribucion:
        fallos += 1
    tabla.add_row(marca(sin_atribucion), "Amenaza solo de VirusTotal",
                  "NO citar a Google", f"cita_a_google={solo_vt.cita_a_google}")

    console.print()
    console.print(tabla)

    if detalle:
        console.print("\n[bold]Ejemplo de veredicto completo:[/bold]\n")
        ejemplo = scoring.evaluar(fabricar(fuente_google_reporta(), fuente_vt(8)))
        console.print(f"  [bold red]{ejemplo.seguridad}[/bold red] "
                      f"({ejemplo.puntos} puntos)")
        console.print(f"  {ejemplo.frase}")
        for señal in ejemplo.señales:
            etiqueta_peso = "!!" if señal.dura else f"+{señal.peso}"
            console.print(f"    {etiqueta_peso} [dim][{señal.fuente}][/dim] {señal.texto}")
        console.print()

    return fallos, len(casos) + 2


# =====================================================================
#  BANCO 7 - Heuristicas (Semana 3, Dia 2)
# =====================================================================
#
# Ninguna toca internet: todas miran la FORMA del dominio.


def probar_heuristicas(detalle: bool = True) -> tuple[int, int]:
    """Prueba el olfato propio de la herramienta. Sin internet."""

    tabla = Table(title="Heuristicas - la forma del engaño",
                  title_style="bold cyan", pad_edge=False)
    tabla.add_column("", width=6)
    tabla.add_column("Caso", overflow="fold")
    tabla.add_column("Debe", overflow="fold")
    tabla.add_column("Resultado", overflow="fold")

    fallos = 0

    def anotar(descripcion: str, debe: str, bien: bool, resultado: str) -> None:
        nonlocal fallos
        if not bien:
            fallos += 1
        tabla.add_row(marca(bien), descripcion, debe,
                      resultado if bien else f"[red]{resultado}[/red]")

    def peso_de(host: str) -> int:
        return sum(h.peso for h in heuristicas.revisar_dominio(host))

    # --- Dominio registrable: la base de casi todo lo demas ---
    casos_dominio = [
        ("www.github.com", "github.com"),
        ("mail.banco.com.mx", "banco.com.mx"),      # sufijo de dos partes
        ("paypal.com.seguro.xyz", "seguro.xyz"),    # la trampa
        ("ejemplo.co.uk", "ejemplo.co.uk"),
    ]
    for host, esperado in casos_dominio:
        obtenido = heuristicas.dominio_registrable(host)
        anotar(f"Dominio registrable de {host}", esperado,
               obtenido == esperado, obtenido)

    # --- Distancia entre palabras ---
    casos_distancia = [
        ("amazon", "amazon", 0),
        ("amazon", "arnazon", 2),
        ("google", "gooogle", 1),
        ("paypal", "paypa1", 1),
    ]
    for a, b, esperado in casos_distancia:
        obtenido = heuristicas.distancia(a, b)
        anotar(f"distancia('{a}', '{b}')", str(esperado),
               obtenido == esperado, str(obtenido))

    # --- Las cuatro trampas ---
    punycode = heuristicas.revisar_dominio("xn--80ak6aa92e.com")
    anotar("Homografo (xn--80ak6aa92e.com)", "detectar alfabetos mezclados",
           any(h.peso == 3 and "alfabetos" in h.texto for h in punycode),
           punycode[0].texto[:40] + "..." if punycode else "nada")

    marca_subdominio = heuristicas.revisar_dominio("paypal.com.seguro-x.xyz")
    anotar("Marca en el subdominio", "detectar la suplantacion",
           any(h.peso == 3 and "subdominio" in h.texto for h in marca_subdominio),
           f"{peso_de('paypal.com.seguro-x.xyz')} puntos")

    typo = heuristicas.revisar_dominio("arnazon.com")
    anotar("Typosquatting (arnazon.com)", "parecerse a amazon",
           any("amazon" in h.texto for h in typo),
           typo[0].texto[:40] + "..." if typo else "nada")

    cadena_corta = heuristicas.revisar_cadena([
        "https://bit.ly/abc", "https://tinyurl.com/xyz", "https://destino.com"])
    anotar("Dos acortadores encadenados", "peso 3",
           any(h.peso == 3 for h in cadena_corta),
           f"{sum(h.peso for h in cadena_corta)} puntos")

    un_acortador = heuristicas.revisar_cadena(["https://bit.ly/abc"])
    anotar("Un solo acortador", "peso 1",
           any(h.peso == 1 for h in un_acortador),
           f"{sum(h.peso for h in un_acortador)} puntos")

    # --- Falsos positivos: lo mas importante de una heuristica ---
    # Una heuristica que marca sitios legitimos es peor que no tenerla.
    limpios = ["github.com", "www.google.com", "example.com",
               "docs.python.org", "um.edu.mx", "mercadolibre.com.mx"]
    marcados = [h for h in limpios if peso_de(h) > 0]
    anotar("Sitios legitimos comunes", "no marcar ninguno",
           not marcados, f"marcados: {marcados}" if marcados else "ninguno marcado")

    # --- Integracion con el veredicto ---
    veredicto = scoring.evaluar(fabricar(
        fuente_limpia("Google Safe Browsing"), fuente_vt(0),
        url_final="https://paypal.com.robo.xyz/login"))
    anotar("El veredicto usa las heuristicas", "SOSPECHOSO",
           veredicto.seguridad == scoring.SOSPECHOSO,
           f"{veredicto.seguridad} ({veredicto.puntos}p)")

    console.print()
    console.print(tabla)

    if detalle:
        console.print("\n[bold]Como se ven los dominios trampa:[/bold]\n")
        for host in ["xn--80ak6aa92e.com", "xn--e1awd7f.com"]:
            visible = heuristicas.decodificar_punycode(host)
            console.print(f"  [cyan]{host}[/cyan]  ->  en pantalla: "
                          f"[bold]{visible}[/bold]")
        console.print()

    return fallos, 4 + 4 + 5 + 1 + 1


# =====================================================================
#  BANCO 8 - La salida: JSON y codigos (Semana 3, Dia 3)
# =====================================================================

def probar_salida(detalle: bool = True) -> tuple[int, int]:
    """Prueba el contrato de la salida JSON y los codigos de salida."""
    import json as _json

    import check as cli
    from checker.reporte import VERSION_FORMATO, a_diccionario

    tabla = Table(title="Salida - JSON y codigos de salida",
                  title_style="bold cyan", pad_edge=False)
    tabla.add_column("", width=6)
    tabla.add_column("Caso", overflow="fold")
    tabla.add_column("Debe", overflow="fold")
    tabla.add_column("Resultado", overflow="fold")

    fallos = 0

    def anotar(descripcion: str, debe: str, bien: bool, resultado: str) -> None:
        nonlocal fallos
        if not bien:
            fallos += 1
        tabla.add_row(marca(bien), descripcion, debe,
                      resultado if bien else f"[red]{resultado}[/red]")

    # --- Un analisis normal ---
    analisis = fabricar(fuente_google_reporta(), fuente_vt(4))
    veredicto = scoring.evaluar(analisis)
    datos = a_diccionario(analisis, veredicto)

    anotar("El JSON lleva version del formato", str(VERSION_FORMATO),
           datos.get("version") == VERSION_FORMATO, str(datos.get("version")))

    anotar("Trae el veredicto", "POSIBLEMENTE_PELIGROSO",
           datos["veredicto"]["seguridad"] == scoring.POSIBLEMENTE_PELIGROSO,
           datos["veredicto"]["seguridad"])

    anotar("Trae las razones", "2 razones",
           len(datos["veredicto"]["razones"]) == 2,
           f"{len(datos['veredicto']['razones'])} razones")

    # --- Lo mas importante: que de verdad se pueda serializar ---
    # Un objeto que json no sepa convertir revienta aqui, no en el usuario.
    try:
        texto = _json.dumps(datos, ensure_ascii=False)
        serializa = True
        detalle_serializa = f"{len(texto)} caracteres"
    except (TypeError, ValueError) as error:
        serializa = False
        detalle_serializa = str(error)
    anotar("json.dumps() no revienta", "serializar sin error",
           serializa, detalle_serializa)

    # --- Una URL invalida tambien tiene que serializar ---
    invalida = fabricar(valida=False, motivo="Esquema no permitido")
    datos_invalida = a_diccionario(invalida, scoring.evaluar(invalida))
    try:
        _json.dumps(datos_invalida)
        ok_invalida = datos_invalida["cadena"] is None
    except (TypeError, ValueError):
        ok_invalida = False
    anotar("URL invalida en JSON", "cadena en null, sin reventar",
           ok_invalida, f"cadena={datos_invalida['cadena']}")

    # --- El contrato de los codigos de salida ---
    # Si mañana alguien agrega un nivel nuevo al scoring y olvida el codigo,
    # esta prueba lo caza antes de que salga un 0 ("todo bien") por error.
    sin_codigo = [nivel for nivel in scoring.ORDEN if nivel not in cli.CODIGOS]
    anotar("Todo veredicto tiene codigo de salida", "ninguno sin codigo",
           not sin_codigo, f"sin codigo: {sin_codigo}" if sin_codigo else "todos")

    # Y que el orden tenga sentido: mas grave = numero mas alto.
    codigos = [cli.CODIGOS[n] for n in scoring.ORDEN]
    creciente = all(a < b for a, b in zip(codigos, codigos[1:]))
    anotar("Mas grave = codigo mas alto", "creciente", creciente, str(codigos))

    # --- Y que exista un estilo para cada nivel ---
    sin_estilo = [n for n in scoring.ORDEN if n not in cli.ESTILOS]
    anotar("Todo veredicto tiene color", "ninguno sin estilo",
           not sin_estilo, f"sin estilo: {sin_estilo}" if sin_estilo else "todos")

    console.print()
    console.print(tabla)

    if detalle:
        console.print("\n[bold]Asi se ve el JSON (recortado):[/bold]\n")
        recorte = {"version": datos["version"], "entrada": datos["entrada"],
                   "veredicto": datos["veredicto"]}
        console.print(f"[dim]{_json.dumps(recorte, indent=2, ensure_ascii=False)[:600]}[/dim]\n")

    return fallos, 8


# =====================================================================
#  Una sola URL
# =====================================================================

def probar_una(url: str) -> None:
    """Prueba una sola URL: validacion + cadena completa."""
    validacion = validar_url(url)

    if not validacion.ok:
        console.print()
        console.print(Panel(
            f"[bold red]RECHAZADA[/bold red]\n\nMotivo: [yellow]{validacion.motivo}[/yellow]",
            title=f"[bold]{etiqueta(url)}[/bold]", border_style="red",
        ))
        console.print()
        return

    cadena = seguir_cadena(validacion.url)

    lineas = [f"[bold green]VALIDA[/bold green]", "", "Recorrido:"]
    for salto in cadena.saltos:
        codigo = salto.codigo if salto.codigo is not None else "---"
        lineas.append(f"  {salto.numero}. [{codigo}] [cyan]{salto.url}[/cyan]")

    lineas.append("")
    if cadena.problema:
        lineas.append(f"[bold red]Cadena interrumpida:[/bold red] {cadena.problema}")
    elif cadena.salud_final:
        lineas.append(f"Salud final: [bold]{cadena.salud_final.categoria}[/bold] "
                      f"- {cadena.salud_final.razon}")
    lineas.append(f"Destino: [cyan]{cadena.url_final}[/cyan]")
    lineas.append(f"Redirecciones: {cadena.num_saltos}")

    console.print()
    console.print(Panel("\n".join(lineas), title=f"[bold]{etiqueta(url)}[/bold]",
                        border_style="green"))
    console.print()


# =====================================================================
#  Correr todo
# =====================================================================

def probar_todo() -> int:
    """Corre los tres bancos y devuelve el numero total de fallos."""
    console.rule("[bold]Banco de pruebas completo[/bold]")

    fallos_v, total_v = probar_validador(detalle=False)
    fallos_s, total_s = probar_salud(detalle=False)
    fallos_c, total_c = probar_cadena(detalle=False)
    fallos_a, total_a = probar_amenazas(detalle=False)
    fallos_t, total_t = probar_virustotal(detalle=False)
    fallos_n, total_n = probar_scanner(detalle=False)
    fallos_p, total_p = probar_scoring(detalle=False)
    fallos_h, total_h = probar_heuristicas(detalle=False)
    fallos_j, total_j = probar_salida(detalle=False)

    fallos = (fallos_v + fallos_s + fallos_c + fallos_a
              + fallos_t + fallos_n + fallos_p + fallos_h + fallos_j)
    total = (total_v + total_s + total_c + total_a
             + total_t + total_n + total_p + total_h + total_j)

    resumen = Table(title="Resumen", title_style="bold", pad_edge=False)
    resumen.add_column("Banco")
    resumen.add_column("Pruebas", justify="right", width=8)
    resumen.add_column("Fallos", justify="right", width=7)
    resumen.add_row("Modulo 0 - Validador", str(total_v),
                    "0" if not fallos_v else f"[red]{fallos_v}[/red]")
    resumen.add_row("Modulo 1 - Salud", str(total_s),
                    "0" if not fallos_s else f"[red]{fallos_s}[/red]")
    resumen.add_row("Dia 4 - Redirecciones", str(total_c),
                    "0" if not fallos_c else f"[red]{fallos_c}[/red]")
    resumen.add_row("Modulo 2 - Safe Browsing", str(total_a),
                    "0" if not fallos_a else f"[red]{fallos_a}[/red]")
    resumen.add_row("Modulo 2 - VirusTotal", str(total_t),
                    "0" if not fallos_t else f"[red]{fallos_t}[/red]")
    resumen.add_row("Coordinador (paralelo)", str(total_n),
                    "0" if not fallos_n else f"[red]{fallos_n}[/red]")
    resumen.add_row("Modulo 3 - Puntuacion", str(total_p),
                    "0" if not fallos_p else f"[red]{fallos_p}[/red]")
    resumen.add_row("Heuristicas", str(total_h),
                    "0" if not fallos_h else f"[red]{fallos_h}[/red]")
    resumen.add_row("Salida (JSON, codigos)", str(total_j),
                    "0" if not fallos_j else f"[red]{fallos_j}[/red]")

    console.print()
    console.print(resumen)

    if fallos == 0:
        console.print(f"\n[bold green]Todo bien: {total} de {total} pruebas correctas.[/bold green]\n")
    else:
        console.print(f"\n[bold red]{total - fallos} de {total}. Hay {fallos} fallo(s).[/bold red]\n")

    return fallos


if __name__ == "__main__":
    argumento = sys.argv[1] if len(sys.argv) > 1 else None

    if argumento is None:
        # Sin argumentos: corre todo y termina con codigo 1 si algo fallo.
        sys.exit(1 if probar_todo() else 0)
    elif argumento == "--validador":
        sys.exit(1 if probar_validador()[0] else 0)
    elif argumento == "--salud":
        sys.exit(1 if probar_salud()[0] else 0)
    elif argumento == "--cadena":
        sys.exit(1 if probar_cadena()[0] else 0)
    elif argumento == "--amenazas":
        sys.exit(1 if probar_amenazas()[0] else 0)
    elif argumento == "--virustotal":
        sys.exit(1 if probar_virustotal()[0] else 0)
    elif argumento == "--scanner":
        sys.exit(1 if probar_scanner()[0] else 0)
    elif argumento == "--scoring":
        sys.exit(1 if probar_scoring()[0] else 0)
    elif argumento == "--heuristicas":
        sys.exit(1 if probar_heuristicas()[0] else 0)
    elif argumento == "--salida":
        sys.exit(1 if probar_salida()[0] else 0)
    else:
        probar_una(argumento)
