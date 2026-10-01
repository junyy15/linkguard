"""
URL Health & Safety Checker - linea de comandos.

    python check.py <url>                            revisa una URL
    python check.py <url> --json                     resultado en JSON
    python check.py --lista archivo.txt              revisa muchas (sin APIs)
    python check.py --lista archivo.txt --amenazas   ...consultando las APIs

Codigos de salida (sirven para automatizar):
    0  SEGURO
    1  SIN_CONFIRMAR
    2  SOSPECHOSO
    3  POSIBLEMENTE_PELIGROSO
    4  RECHAZADA
   10  error de uso (falta un argumento, no existe el archivo)

Este archivo SOLO presenta resultados. Quien analiza es checker/scanner.py
y quien decide es checker/scoring.py.
"""

import json
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from checker.reporte import a_diccionario
from checker.scanner import Analisis, analizar
from checker.scoring import Veredicto, evaluar
from checker.threats import VT_MAXIMO, ResultadoAmenazas

console = Console()

# Google exige dar credito cuando la advertencia viene de sus datos, y que
# el usuario pueda informarse mas. Es requisito de sus terminos de uso.
AVISO_GOOGLE = ("Advisory provided by Google - "
                "https://transparencyreport.google.com/safe-browsing/search")
MAS_INFORMACION = "Mas informacion sobre phishing: https://www.antiphishing.org"

# Como se ve cada veredicto. El color es informacion, no decoracion.
ESTILOS = {
    "SEGURO":                 ("green",        "OK",  "SEGURO"),
    "SIN_CONFIRMAR":          ("yellow",       "??",  "SIN CONFIRMAR"),
    "SOSPECHOSO":             ("dark_orange",  "!!",  "SOSPECHOSO"),
    "POSIBLEMENTE_PELIGROSO": ("bold red",     "XX",  "POSIBLEMENTE PELIGROSO"),
    "RECHAZADA":              ("bold red",     "XX",  "RECHAZADA"),
}

SALUD_ESTILO = {
    "OK": "green",
    "REDIRECCION": "cyan",
    "BLOQUEADO": "yellow",
    "ROTO": "dark_orange",
    "ERROR": "red",
    "INVALIDA": "red",
}

# El codigo de salida que corresponde a cada veredicto.
CODIGOS = {
    "SEGURO": 0,
    "SIN_CONFIRMAR": 1,
    "SOSPECHOSO": 2,
    "POSIBLEMENTE_PELIGROSO": 3,
    "RECHAZADA": 4,
}


# =====================================================================
#  Una URL
# =====================================================================

def panel_veredicto(v: Veredicto) -> Panel:
    """El recuadro grande de arriba: lo unico que mucha gente va a leer."""
    color, simbolo, etiqueta = ESTILOS.get(v.seguridad, ("white", "??", v.seguridad))
    color_salud = SALUD_ESTILO.get(v.salud, "white")

    cuerpo = Text()
    cuerpo.append(v.frase + "\n")

    if v.señales:
        cuerpo.append("\nPor que:\n", style="bold")
        for señal in v.señales:
            if señal.dura:
                etiqueta_peso, estilo_peso = "!!", "bold red"
            elif señal.peso:
                etiqueta_peso, estilo_peso = f"+{señal.peso}", "dark_orange"
            else:
                etiqueta_peso, estilo_peso = "··", "dim"
            cuerpo.append(f"  {etiqueta_peso} ", style=estilo_peso)
            cuerpo.append(f"{señal.texto}\n")
            cuerpo.append(f"       {señal.fuente}\n", style="dim")

    if v.cita_a_google:
        cuerpo.append(f"\n{AVISO_GOOGLE}\n", style="dim")
        cuerpo.append(f"{MAS_INFORMACION}\n", style="dim")

    titulo = Text()
    titulo.append(f" [{simbolo}] {etiqueta} ", style=color)
    titulo.append("·", style="dim")
    titulo.append(f" Salud: {v.salud} ", style=color_salud)

    return Panel(cuerpo, title=titulo, border_style=color, padding=(1, 2))


def tabla_recorrido(a: Analisis) -> Table:
    """La cadena de redirecciones, salto por salto."""
    tabla = Table(show_header=True, header_style="dim", box=None, pad_edge=False)
    tabla.add_column("#", justify="right", width=3, style="dim")
    tabla.add_column("Cod", justify="right", width=4)
    tabla.add_column("URL", overflow="fold")

    for salto in a.cadena.saltos:
        codigo = salto.codigo
        if codigo is None:
            estilo = "red"
            texto = "---"
        else:
            texto = str(codigo)
            estilo = ("green" if 200 <= codigo < 300
                      else "cyan" if 300 <= codigo < 400
                      else "yellow" if codigo in (401, 403, 429)
                      else "dark_orange")
        tabla.add_row(str(salto.numero), Text(texto, style=estilo), salto.url)
    return tabla


def linea_fuente(resultado: ResultadoAmenazas | None) -> Text | None:
    """Una linea por base de amenazas. Aqui van DATOS, no advertencias:
    la advertencia ya salio en el recuadro de arriba. Repetirla la vuelve
    ruido, y el ruido hace que la gente deje de leer."""
    if resultado is None:
        return None

    linea = Text()
    if not resultado.consultado:
        linea.append("  ?  ", style="yellow")
        linea.append(f"{resultado.fuente}: ")
        linea.append(f"desconocido ({resultado.error})", style="dim")
        return linea

    origen = " (cache)" if resultado.del_cache else ""
    if resultado.amenazas:
        linea.append("  !  ", style="bold red")
        linea.append(f"{resultado.fuente}{origen}: ")
        linea.append("REPORTADO", style="bold red")
        detalles = ", ".join(a.descripcion for a in resultado.amenazas)
        linea.append(f" - {detalles}", style="red")
    else:
        linea.append("  OK ", style="green")
        linea.append(f"{resultado.fuente}{origen}: sin coincidencias")

    e = resultado.estadisticas
    if e:
        linea.append(f"  [{e['malicious']}/{sum(e.values())} motores]", style="dim")
    return linea


def mostrar(a: Analisis, v: Veredicto) -> None:
    """Imprime el resultado completo de una URL."""
    console.print()
    console.print(Text(a.entrada, style="bold cyan"))
    console.print(panel_veredicto(v))

    if not a.paso_validacion:
        console.print()
        return

    console.print("[dim]── Detalle tecnico " + "─" * 40 + "[/dim]")
    console.print(f"[dim]URL normalizada:[/dim] {a.validacion.url}")
    console.print(f"[dim]Apunta a:[/dim] {', '.join(a.validacion.ips)}")
    console.print()
    console.print(tabla_recorrido(a))

    salud = a.cadena.salud_final
    if salud:
        tiempo = f" · {salud.tiempo_ms} ms" if salud.tiempo_ms is not None else ""
        console.print(f"\n[dim]{salud.razon}{tiempo}[/dim]")
    if a.cadena.problema:
        console.print(f"[red]{a.cadena.problema}[/red]")

    if a.google or a.virustotal:
        console.print()
        for fuente in (a.google, a.virustotal):
            linea = linea_fuente(fuente)
            if linea:
                console.print(linea)

    console.print(f"\n[dim]Analisis completo en {a.tiempo_ms} ms[/dim]\n")


# =====================================================================
#  Modo lista
# =====================================================================

CORTO = {
    "SEGURO": ("seguro", "green"),
    "SIN_CONFIRMAR": ("sin confirmar", "yellow"),
    "SOSPECHOSO": ("SOSPECHOSO", "dark_orange"),
    "POSIBLEMENTE_PELIGROSO": ("PELIGRO?", "bold red"),
    "RECHAZADA": ("rechazada", "red"),
}


def revisar_lista(ruta: Path, con_amenazas: bool) -> int:
    """Revisa todas las URLs de un archivo, una por linea.

    Las lineas vacias y las que empiezan con # se ignoran.
    """
    if not ruta.exists():
        console.print(f"[red]No encuentro el archivo:[/red] {ruta}")
        return 10

    urls = [
        linea.strip()
        for linea in ruta.read_text(encoding="utf-8").splitlines()
        if linea.strip() and not linea.strip().startswith("#")
    ]

    if not urls:
        console.print(f"[yellow]{ruta} no tiene ninguna URL.[/yellow]")
        return 10

    console.print()
    console.rule(f"[bold]{len(urls)} URLs de {ruta.name}[/bold]")

    if con_amenazas:
        # VirusTotal solo deja 4 peticiones por minuto: avisamos antes de
        # empezar, en vez de dejar al usuario mirando una pantalla quieta.
        console.print(f"[dim]Con amenazas: puede tardar ~"
                      f"{len(urls) / VT_MAXIMO:.0f} min. "
                      f"El cache hace que la segunda vez sea casi instantanea.[/dim]")
    else:
        console.print("[dim]Sin consultar amenazas. "
                      "Agrega --amenazas para incluirlas.[/dim]")

    tabla = Table(show_header=True, header_style="bold dim", pad_edge=False)
    tabla.add_column("Veredicto", width=14)
    tabla.add_column("Salud", width=11)
    tabla.add_column("Cod", justify="right", width=4)
    tabla.add_column("URL / razones", overflow="fold")

    conteo: dict[str, int] = {}
    peor = 0

    for url in urls:
        a = analizar(url, consultar_amenazas=con_amenazas)
        v = evaluar(a)

        conteo[v.seguridad] = conteo.get(v.seguridad, 0) + 1
        peor = max(peor, CODIGOS.get(v.seguridad, 0))

        etiqueta, color = CORTO.get(v.seguridad, (v.seguridad, "white"))
        codigo = "-"
        if a.cadena and a.cadena.salud_final and a.cadena.salud_final.codigo:
            codigo = str(a.cadena.salud_final.codigo)

        detalle = Text(url)
        # Solo las señales que pesan: si se imprime todo, la tabla se vuelve
        # ilegible y entonces nadie la lee.
        for señal in v.señales:
            if señal.dura or señal.peso:
                etiqueta_peso = "!!" if señal.dura else f"+{señal.peso}"
                detalle.append(f"\n  {etiqueta_peso} {señal.texto}", style="dim")
        if a.cadena and a.cadena.num_saltos > 0:
            detalle.append(f"\n  -> {a.cadena.url_final}", style="dim cyan")

        tabla.add_row(Text(etiqueta, style=color),
                      Text(v.salud, style=SALUD_ESTILO.get(v.salud, "white")),
                      codigo, detalle)

    console.print()
    console.print(tabla)

    resumen = Text()
    for nombre, cantidad in sorted(conteo.items(), key=lambda p: -CODIGOS.get(p[0], 0)):
        etiqueta, color = CORTO.get(nombre, (nombre, "white"))
        resumen.append(f"{etiqueta}: {cantidad}   ", style=color)
    console.print()
    console.print(resumen)
    console.print()

    # Devuelve el peor veredicto de toda la lista.
    return peor


# =====================================================================

def main() -> None:
    argumentos = sys.argv[1:]

    if not argumentos:
        console.print("[bold]Uso:[/bold]")
        console.print("  python check.py <url> [--json]")
        console.print("  python check.py --lista <archivo.txt> [--amenazas]")
        sys.exit(10)

    if argumentos[0] == "--lista":
        if len(argumentos) < 2:
            console.print("[red]Falta el archivo.[/red] "
                          "Uso: python check.py --lista <archivo.txt> [--amenazas]")
            sys.exit(10)
        sys.exit(revisar_lista(Path(argumentos[1]), "--amenazas" in argumentos))

    url = argumentos[0]
    analisis = analizar(url)
    veredicto = evaluar(analisis)

    if "--json" in argumentos:
        # En modo JSON no se imprime NADA mas: la salida tiene que poder
        # pasarse por una tuberia a otro programa sin basura de por medio.
        print(json.dumps(a_diccionario(analisis, veredicto),
                         indent=2, ensure_ascii=False))
    else:
        mostrar(analisis, veredicto)

    sys.exit(CODIGOS.get(veredicto.seguridad, 0))


if __name__ == "__main__":
    main()
