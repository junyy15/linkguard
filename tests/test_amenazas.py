"""Pruebas del Modulo 2: Google Safe Browsing y VirusTotal.

Casi todas salen a internet y gastan cuota, por eso llevan las etiquetas
@pytest.mark.red y @pytest.mark.api. Para saltarselas:

    pytest -m "not red"

Google publica URLs de prueba que SIEMPRE estan en su lista negra.
Existen justo para esto: comprobar tu integracion sin ir a buscar un
sitio malicioso de verdad.
"""

import pytest

import checker.threats as threats
from checker.threats import consultar_safe_browsing, consultar_virustotal, id_de_url

PHISHING = "https://testsafebrowsing.appspot.com/s/phishing.html"
MALWARE = "https://testsafebrowsing.appspot.com/s/malware.html"
NO_DESEADO = "https://testsafebrowsing.appspot.com/s/unwanted.html"


# =====================================================================
#  Sin internet
# =====================================================================

def test_id_de_url_no_lleva_relleno():
    """VirusTotal pide base64 seguro para URLs, sin los '=' del final."""
    assert not id_de_url("https://example.com").endswith("=")


@pytest.fixture
def sin_llaves(monkeypatch):
    """Le quita las llaves al programa, para probar la regla de oro."""
    monkeypatch.setattr(threats.config, "obtener", lambda nombre: None)


def test_safe_browsing_sin_llave_es_desconocido_no_limpio(sin_llaves):
    """LA regla del modulo: no poder preguntar NO es estar limpio."""
    resultado = consultar_safe_browsing(["https://example.com"])
    assert not resultado.consultado
    assert not resultado.limpio


def test_virustotal_sin_llave_es_desconocido_no_limpio(sin_llaves):
    resultado = consultar_virustotal("https://example.com")
    assert not resultado.consultado
    assert not resultado.limpio


# =====================================================================
#  Con internet y cuota de API
# =====================================================================

@pytest.mark.red
@pytest.mark.api
def test_safe_browsing_sitio_limpio():
    resultado = consultar_safe_browsing(["https://example.com"])
    assert resultado.limpio


@pytest.mark.red
@pytest.mark.api
@pytest.mark.parametrize("url, tipo", [
    (PHISHING, "SOCIAL_ENGINEERING"),
    (MALWARE, "MALWARE"),
    (NO_DESEADO, "UNWANTED_SOFTWARE"),
])
def test_safe_browsing_detecta_las_urls_de_prueba(url, tipo):
    resultado = consultar_safe_browsing([url])
    assert tipo in {a.tipo for a in resultado.amenazas}


@pytest.mark.red
@pytest.mark.api
def test_virustotal_sitio_limpio():
    resultado = consultar_virustotal("https://example.com")
    assert resultado.limpio
    assert resultado.estadisticas["malicious"] == 0


@pytest.mark.red
@pytest.mark.api
def test_virustotal_detecta_la_url_de_prueba():
    resultado = consultar_virustotal(PHISHING)
    assert resultado.estadisticas["malicious"] > 0


@pytest.mark.red
@pytest.mark.api
def test_la_segunda_consulta_viene_del_cache():
    consultar_virustotal("https://example.com")
    segunda = consultar_virustotal("https://example.com")
    assert segunda.del_cache
