"""Pruebas del modo publico.

Lo que vigilan:
  1. Que en publico NO se consulte VirusTotal (su cuota es de 500 al dia).
  2. Que apagar una fuente a proposito NO convierta todo en SIN_CONFIRMAR.
  3. Que la regla de oro siga en pie: si NINGUNA fuente contesto, no se
     puede decir "seguro" aunque la ausencia haya sido deliberada.
"""

import pytest
from conftest import fabricar, fuente_caida, fuente_limpia, fuente_vt

import checker.scanner as scanner
from checker import config, scoring


# =====================================================================
#  El interruptor
# =====================================================================

@pytest.mark.parametrize("valor, esperado", [
    ("1", True), ("true", True), ("si", True), ("TRUE", True),
    ("0", False), ("", False), ("no", False),
])
def test_la_variable_enciende_el_modo_publico(monkeypatch, valor, esperado):
    monkeypatch.setenv(config.VARIABLE_PUBLICO, valor)
    monkeypatch.setattr(config, "_ya_cargado", True)
    assert config.es_publico() is esperado


def test_por_defecto_no_es_publico(monkeypatch):
    monkeypatch.delenv(config.VARIABLE_PUBLICO, raising=False)
    monkeypatch.setattr(config, "_ya_cargado", True)
    assert config.es_publico() is False


# =====================================================================
#  En publico no se gasta VirusTotal
# =====================================================================

def test_en_publico_no_se_consulta_virustotal(monkeypatch):
    llamadas = []

    monkeypatch.setattr(scanner, "consultar_virustotal",
                        lambda url, **k: llamadas.append(url))
    monkeypatch.setattr(scanner, "consultar_safe_browsing",
                        lambda urls: fuente_limpia("Google Safe Browsing"))
    monkeypatch.setattr(scanner, "seguir_cadena", lambda url: _cadena_falsa())
    monkeypatch.setattr(scanner.config, "es_publico", lambda: True)

    resultado = scanner.analizar("https://example.com")

    assert llamadas == [], "en publico no debe consultarse VirusTotal"
    assert resultado.virustotal is None
    assert "VirusTotal" in resultado.omitidas


def test_en_local_si_se_consulta_virustotal(monkeypatch):
    llamadas = []

    monkeypatch.setattr(scanner, "consultar_virustotal",
                        lambda url, **k: llamadas.append(url) or fuente_vt(0))
    monkeypatch.setattr(scanner, "consultar_safe_browsing",
                        lambda urls: fuente_limpia("Google Safe Browsing"))
    monkeypatch.setattr(scanner, "seguir_cadena", lambda url: _cadena_falsa())
    monkeypatch.setattr(scanner.config, "es_publico", lambda: False)

    resultado = scanner.analizar("https://example.com")

    assert llamadas, "en local si debe consultarse VirusTotal"
    assert resultado.omitidas == []


def _cadena_falsa():
    from checker.health import Cadena, Salto, Salud
    return Cadena(
        saltos=[Salto(numero=1, url="https://example.com")],
        url_final="https://example.com",
        salud_final=Salud(categoria="OK", codigo=200, razon="falso"),
    )


# =====================================================================
#  Omitida a proposito != no se pudo consultar
# =====================================================================

def test_una_fuente_omitida_no_degrada_el_veredicto():
    """Si Google contesto y dijo limpio, el resultado vale.

    Sin esta distincion, apagar VirusTotal haria que TODO saliera como
    SIN_CONFIRMAR y la version publica no serviria para nada.
    """
    analisis = fabricar(fuente_limpia("Google Safe Browsing"), None)
    analisis.omitidas = ["VirusTotal"]
    assert scoring.evaluar(analisis).seguridad == scoring.SEGURO


def test_la_fuente_omitida_se_anota_igual():
    """No degrada, pero el usuario tiene derecho a saberlo."""
    analisis = fabricar(fuente_limpia("Google Safe Browsing"), None)
    analisis.omitidas = ["VirusTotal"]
    veredicto = scoring.evaluar(analisis)
    assert any("VirusTotal" in s.texto for s in veredicto.señales)


def test_si_la_fuente_que_queda_falla_no_se_dice_seguro():
    """La regla de oro, intacta: tiene que contestar AL MENOS UNA."""
    analisis = fabricar(fuente_caida("Google Safe Browsing"), None)
    analisis.omitidas = ["VirusTotal"]
    assert scoring.evaluar(analisis).seguridad == scoring.SIN_CONFIRMAR


def test_si_no_contesta_ninguna_no_se_dice_seguro():
    analisis = fabricar(None, None)
    analisis.omitidas = ["VirusTotal", "Google Safe Browsing"]
    assert scoring.evaluar(analisis).seguridad == scoring.SIN_CONFIRMAR


def test_una_amenaza_de_la_fuente_que_queda_si_cuenta():
    """Apagar una fuente no debe tapar lo que dice la otra."""
    from checker.threats import Amenaza, ResultadoAmenazas

    google = ResultadoAmenazas(
        fuente="Google Safe Browsing", consultado=True,
        amenazas=[Amenaza("Google Safe Browsing", "SOCIAL_ENGINEERING", "x")])
    analisis = fabricar(google, None)
    analisis.omitidas = ["VirusTotal"]
    assert scoring.evaluar(analisis).seguridad == scoring.POSIBLEMENTE_PELIGROSO
