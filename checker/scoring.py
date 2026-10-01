"""
Modulo 3 - El motor de puntuacion.

Toma un objeto Analisis (con todo lo que averiguaron los modulos 0, 1 y 2)
y devuelve un Veredicto: una conclusion con sus razones.

DOS EJES, NO UNO
================
Separamos SALUD y SEGURIDAD porque son preguntas distintas:

    Salud      -> ¿el enlace funciona?      OK / ROTO / BLOQUEADO / ERROR
    Seguridad  -> ¿es riesgoso abrirlo?     SEGURO / SIN_CONFIRMAR /
                                            SOSPECHOSO / POSIBLEMENTE_PELIGROSO

Un enlace puede estar roto y ser inofensivo (un 404 en un sitio legitimo),
o funcionar de maravilla y ser una pagina de phishing viva. Un solo numero
no puede decir las dos cosas.

EL LENGUAJE
===========
El nivel mas alto se llama POSIBLEMENTE_PELIGROSO, no PELIGROSO.
No es timidez: los terminos del Safe Browsing API de Google prohiben
afirmar con certeza que un sitio es malicioso. Y ademas es la verdad:
la herramienta no sabe, sabe que alguien lo reporto.

LAS REGLAS
==========
Hay dos clases de regla:

  REGLAS DURAS - una sola basta para llegar al nivel mas alto.
      - Google Safe Browsing reporta la URL
      - 2 o mas antivirus de VirusTotal la marcan como maliciosa

  PUNTOS - se suman, y al llegar al umbral cambian el nivel.
      3 puntos o mas -> SOSPECHOSO

Por que 2 antivirus y no 1: VirusTotal consulta mas de 90 motores. Que uno
solo marque algo es ruido estadistico normal (falsos positivos). Dos que
coinciden ya es una señal. Es el mismo criterio que usa la industria.
"""

from dataclasses import dataclass, field

from checker import heuristicas
from checker.health import dominio_de
from checker.scanner import Analisis
from checker.validator import normalizar

# Los niveles, del mas tranquilo al mas grave. El orden importa: se usa
# para quedarse siempre con el peor.
SEGURO = "SEGURO"
SIN_CONFIRMAR = "SIN_CONFIRMAR"
SOSPECHOSO = "SOSPECHOSO"
POSIBLEMENTE_PELIGROSO = "POSIBLEMENTE_PELIGROSO"
RECHAZADA = "RECHAZADA"

ORDEN = [SEGURO, SIN_CONFIRMAR, SOSPECHOSO, POSIBLEMENTE_PELIGROSO, RECHAZADA]

# Cuantos puntos hacen falta para pasar de tranquilo a sospechoso.
UMBRAL_SOSPECHOSO = 3

# Frases para el usuario. Fijate que ninguna afirma con certeza.
FRASES = {
    SEGURO: "No encontramos señales de riesgo.",
    SIN_CONFIRMAR: "No encontramos señales de riesgo, pero no pudimos "
                   "consultar todas las fuentes. Esto NO confirma que sea seguro.",
    SOSPECHOSO: "Este enlace tiene señales que podrian indicar riesgo. "
                "Revisalo con cuidado antes de abrirlo.",
    POSIBLEMENTE_PELIGROSO: "Este enlace fue reportado y podria ser peligroso. "
                            "Se recomienda NO abrirlo.",
    RECHAZADA: "La URL no es valida o apunta a una direccion no permitida.",
}


@dataclass
class Señal:
    """Una razon concreta, con su peso y de donde salio."""

    texto: str
    fuente: str
    peso: int = 0       # cuantos puntos suma (0 si es informativa)
    dura: bool = False  # True si por si sola basta para el nivel mas alto


@dataclass
class Veredicto:
    """La conclusion, siempre acompañada de sus razones."""

    seguridad: str
    salud: str
    señales: list[Señal] = field(default_factory=list)
    puntos: int = 0

    @property
    def frase(self) -> str:
        # Decir "no encontramos señales" justo encima de una lista de señales
        # es contradictorio, y una herramienta que se contradice no se usa.
        # Si quedaron puntos pero no alcanzaron el umbral, se dice asi.
        if self.seguridad == SEGURO and self.puntos > 0:
            return ("Encontramos algunos detalles menores, pero nada que "
                    "indique riesgo serio.")
        return FRASES.get(self.seguridad, "")

    @property
    def cita_a_google(self) -> bool:
        """Google exige su atribucion solo si la advertencia usa sus datos."""
        return any(s.fuente == "Google Safe Browsing" for s in self.señales)


def _peor(actual: str, candidato: str) -> str:
    """Devuelve el mas grave de los dos niveles."""
    return candidato if ORDEN.index(candidato) > ORDEN.index(actual) else actual


def evaluar_salud(analisis: Analisis) -> str:
    """El eje de salud: ¿el enlace funciona?"""
    if not analisis.paso_validacion:
        return "INVALIDA"
    cadena = analisis.cadena
    if cadena is None or cadena.problema:
        return "ERROR"
    if cadena.salud_final is None:
        return "ERROR"
    return cadena.salud_final.categoria


def evaluar(analisis: Analisis) -> Veredicto:
    """Convierte un analisis completo en un veredicto con sus razones."""

    salud = evaluar_salud(analisis)

    # --- Caso 1: ni siquiera paso la validacion ---
    if not analisis.paso_validacion:
        rechazo = [Señal(analisis.validacion.motivo or "URL invalida",
                         "Validador", dura=True)]

        # Aunque el dominio no exista, la FORMA del dominio sigue siendo
        # informacion util. Un dominio de phishing dado de baja sigue siendo
        # evidencia de un intento de engaño, y decir "imita a apple.com"
        # ayuda mucho mas que decir "el DNS no responde".
        host = dominio_de(normalizar(analisis.entrada))
        for hallazgo in heuristicas.revisar_dominio(host):
            rechazo.append(Señal(hallazgo.texto, "Heuristica", peso=hallazgo.peso))

        return Veredicto(seguridad=RECHAZADA, salud=salud, señales=rechazo)

    señales: list[Señal] = []
    nivel = SEGURO
    cadena = analisis.cadena

    # --- Reglas duras: las bases de datos de amenazas ---
    google = analisis.google
    if google and google.amenazas:
        for amenaza in google.amenazas:
            señales.append(Señal(amenaza.descripcion, "Google Safe Browsing", dura=True))
        nivel = _peor(nivel, POSIBLEMENTE_PELIGROSO)

    vt = analisis.virustotal
    if vt and vt.consultado:
        maliciosos = vt.estadisticas.get("malicious", 0)
        sospechosos = vt.estadisticas.get("suspicious", 0)
        total = sum(vt.estadisticas.values()) or 0

        if maliciosos >= 2:
            # Dos motores independientes coincidiendo ya no es ruido.
            señales.append(Señal(
                f"{maliciosos} de {total} antivirus la marcan como maliciosa",
                "VirusTotal", dura=True))
            nivel = _peor(nivel, POSIBLEMENTE_PELIGROSO)
        elif maliciosos == 1:
            # Con mas de 90 motores, que uno marque algo es ruido comun.
            # Cuenta, pero no alcanza para el nivel mas alto por si solo.
            señales.append(Señal(
                f"1 de {total} antivirus la marca como maliciosa "
                f"(podria ser un falso positivo)", "VirusTotal", peso=2))
        elif sospechosos >= 1:
            señales.append(Señal(
                f"{sospechosos} de {total} antivirus la marcan como sospechosa",
                "VirusTotal", peso=1))

    # --- Fuentes de las que no sabemos nada ---
    # Hay DOS formas de no saber, y las dos cuentan igual:
    #   - la fuente fallo (consultado=False)
    #   - la fuente ni se consulto (es None, porque se pidio sin amenazas)
    # Tratar la segunda como "todo bien" fue un error real de este modulo:
    # el modo lista decia "seguro" sin haberle preguntado a nadie.
    #
    # No suman puntos: la ignorancia no es evidencia de culpa. Pero impiden
    # decir "seguro", porque sencillamente no lo sabemos.
    desconocidas: list[str] = []
    for nombre, fuente in (("Google Safe Browsing", google), ("VirusTotal", vt)):
        if fuente is None:
            desconocidas.append(nombre)
            señales.append(Señal(f"No se consulto {nombre}", nombre))
        elif not fuente.consultado:
            desconocidas.append(nombre)
            señales.append(Señal(
                f"No se pudo consultar {nombre} ({fuente.error})", nombre))

    # --- Puntos por la forma del enlace ---
    if cadena:
        if cadena.problema:
            señales.append(Señal(cadena.problema, "Cadena de redirecciones", peso=3))

        if cadena.baja_seguridad:
            señales.append(Señal(
                "En algun salto pasa de https a http: ahi los datos viajan sin cifrar",
                "Cadena de redirecciones", peso=2))

        if cadena.cambia_de_dominio:
            señales.append(Señal(
                "Empieza en un dominio y termina en otro",
                "Cadena de redirecciones", peso=1))

        if cadena.num_saltos > 3:
            señales.append(Señal(
                f"Cadena larga: {cadena.num_saltos} redirecciones",
                "Cadena de redirecciones", peso=1))

        if cadena.url_final.lower().startswith("http://"):
            señales.append(Señal(
                "El destino final no usa https", "Salud del enlace", peso=1))

        salud_final = cadena.salud_final
        if salud_final and salud_final.tipo_error == "ssl":
            # Peso 3: alcanza por si solo para SOSPECHOSO. Un certificado
            # invalido no solo se ve mal: significa que NO pudimos comprobar
            # que el sitio sea quien dice ser. Muchos sitios de phishing
            # improvisados tienen exactamente este problema.
            señales.append(Señal(
                "El certificado de seguridad no es valido: no se pudo "
                "comprobar la identidad del sitio",
                "Salud del enlace", peso=3))

    # --- Heuristicas: la forma del engaño, no su reputacion ---
    # Sirven para lo que las bases de datos todavia no alcanzaron a reportar.
    # Ninguna es regla dura: se equivocan mas que las bases de datos.
    if cadena:
        urls_cadena = [s.url for s in cadena.saltos] or [cadena.url_final]

        hosts: list[str] = []
        for url in urls_cadena + [cadena.url_final]:
            host = dominio_de(url)
            if host and host not in hosts:
                hosts.append(host)

        hallazgos: list[heuristicas.Hallazgo] = []
        for host in hosts:
            hallazgos.extend(heuristicas.revisar_dominio(host))
        hallazgos.extend(heuristicas.revisar_cadena(urls_cadena))

        # Un mismo hallazgo puede salir por varios saltos; se reporta una vez.
        ya_vistos: set[str] = set()
        for hallazgo in hallazgos:
            if hallazgo.texto in ya_vistos:
                continue
            ya_vistos.add(hallazgo.texto)
            señales.append(Señal(hallazgo.texto, "Heuristica", peso=hallazgo.peso))

    # --- Suma y umbral ---
    puntos = sum(s.peso for s in señales)
    if puntos >= UMBRAL_SOSPECHOSO:
        nivel = _peor(nivel, SOSPECHOSO)

    # Si no hay nada grave pero quedaron fuentes sin consultar, no podemos
    # decir "seguro". Decimos "no lo pudimos confirmar", que es la verdad.
    if nivel == SEGURO and desconocidas:
        nivel = SIN_CONFIRMAR

    return Veredicto(seguridad=nivel, salud=salud, señales=señales, puntos=puntos)


# Para probar este archivo solo:  python -m checker.scoring <url>
if __name__ == "__main__":
    import sys

    from checker.scanner import analizar

    if len(sys.argv) < 2:
        print("Uso: python -m checker.scoring <url>")
        sys.exit(1)

    veredicto = evaluar(analizar(sys.argv[1]))
    print(f"\nSalud:     {veredicto.salud}")
    print(f"Seguridad: {veredicto.seguridad} ({veredicto.puntos} puntos)")
    print(f"{veredicto.frase}")
    for señal in veredicto.señales:
        marca = "!!" if señal.dura else f"+{señal.peso}" if señal.peso else "  "
        print(f"  {marca} [{señal.fuente}] {señal.texto}")
    print()
