"""Pruebas del Modulo 0: el validador y el guardia anti-SSRF.

Estas si resuelven DNS, pero son rapidas y no gastan cuota de ninguna API.
"""

import pytest

from checker.validator import ip_es_interna, normalizar, validar_url


# @pytest.mark.parametrize corre la MISMA prueba con cada juego de datos,
# y si falla uno te dice exactamente cual. Es la diferencia con meter un
# for dentro de la prueba: ahi solo sabrias que "algo" fallo.
@pytest.mark.parametrize("url", [
    "https://example.com",
    "example.com",                    # sin esquema: debe agregarlo solo
    "https://github.com/anthropics",
])
def test_urls_validas_pasan(url):
    assert validar_url(url).ok


@pytest.mark.parametrize("url, pedazo_del_motivo", [
    ("javascript:alert(1)",       "Esquema no permitido"),
    ("file:///C:/Windows/",       "Esquema no permitido"),
    ("data:text/html,<h1>x</h1>", "Esquema no permitido"),
    ("https://www.banco.com@sitio-malo.com", "credenciales"),
    ("http://example.com:99999",  "mal formada"),
    ("",                          "vacia"),
    ("   ",                       "vacia"),
])
def test_urls_invalidas_se_rechazan(url, pedazo_del_motivo):
    resultado = validar_url(url)
    assert not resultado.ok
    assert pedazo_del_motivo in resultado.motivo


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8080/admin",              # tu propia maquina
    "http://192.168.1.1/",                      # tu router
    "http://10.0.0.5/",                         # red interna
    "http://169.254.169.254/latest/meta-data/", # metadatos de la nube
    "http://localhost",
    "http://[::1]/",                            # loopback en IPv6
    "http://0.0.0.0",
])
def test_guardia_ssrf_bloquea_direcciones_internas(url):
    """El guardia anti-SSRF: el corazon de la seguridad del validador."""
    resultado = validar_url(url)
    assert not resultado.ok, f"{url} deberia estar bloqueada"


def test_dominio_inexistente_se_rechaza():
    resultado = validar_url("http://dominio-que-no-existe-98765.com")
    assert not resultado.ok
    assert "DNS" in resultado.motivo


@pytest.mark.parametrize("ip, interna", [
    ("127.0.0.1", True),
    ("10.0.0.1", True),
    ("192.168.0.1", True),
    ("172.16.0.1", True),
    ("169.254.169.254", True),
    ("::1", True),
    ("::ffff:127.0.0.1", True),   # IPv4 disfrazada de IPv6
    ("8.8.8.8", False),
    ("93.184.216.34", False),
])
def test_clasificacion_de_ips(ip, interna):
    assert ip_es_interna(ip) is interna


def test_normalizar_no_disfraza_esquemas_peligrosos():
    """Si normalizar() pegara https:// a lo bruto, esconderia el peligro."""
    assert normalizar("ejemplo.com") == "https://ejemplo.com"
    assert normalizar("javascript:alert(1)") == "javascript:alert(1)"
