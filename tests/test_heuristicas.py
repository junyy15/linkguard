"""Pruebas de las heuristicas: el olfato propio.

Ninguna toca internet: todas miran la FORMA del dominio.
"""

import pytest

from checker import heuristicas


@pytest.mark.parametrize("host, esperado", [
    ("www.github.com", "github.com"),
    ("mail.banco.com.mx", "banco.com.mx"),       # sufijo de dos partes
    ("paypal.com.seguro.xyz", "seguro.xyz"),     # la trampa
    ("ejemplo.co.uk", "ejemplo.co.uk"),
    ("github.com", "github.com"),
])
def test_dominio_registrable(host, esperado):
    assert heuristicas.dominio_registrable(host) == esperado


@pytest.mark.parametrize("a, b, esperado", [
    ("amazon", "amazon", 0),
    ("amazon", "arnazon", 2),
    ("google", "gooogle", 1),
    ("paypal", "paypa1", 1),
    ("", "abc", 3),
])
def test_distancia_de_levenshtein(a, b, esperado):
    assert heuristicas.distancia(a, b) == esperado


def test_homografo_con_alfabetos_mezclados():
    """xn--80ak6aa92e.com se ve en pantalla como 'аррӏе.com' (cirilico)."""
    hallazgos = heuristicas.revisar_dominio("xn--80ak6aa92e.com")
    assert any(h.peso == 3 and "alfabetos" in h.texto for h in hallazgos)


def test_marca_en_el_subdominio():
    """El dominio real es seguro-x.xyz, pero a simple vista lees paypal.com."""
    hallazgos = heuristicas.revisar_dominio("paypal.com.seguro-x.xyz")
    assert any(h.peso == 3 and "subdominio" in h.texto for h in hallazgos)


def test_typosquatting():
    hallazgos = heuristicas.revisar_dominio("arnazon.com")
    assert any("amazon" in h.texto for h in hallazgos)


def test_acortadores_encadenados_pesan_mas():
    varios = heuristicas.revisar_cadena([
        "https://bit.ly/abc", "https://tinyurl.com/xyz", "https://destino.com"])
    uno = heuristicas.revisar_cadena(["https://bit.ly/abc"])

    assert sum(h.peso for h in varios) > sum(h.peso for h in uno)
    assert any(h.peso == 3 for h in varios)
    assert any(h.peso == 1 for h in uno)


# =====================================================================
#  Falsos positivos: lo mas importante de cualquier heuristica
# =====================================================================

@pytest.mark.parametrize("host", [
    "github.com",
    "www.google.com",
    "example.com",
    "docs.python.org",
    "um.edu.mx",
    "mercadolibre.com.mx",
    "es.wikipedia.org",
    "stackoverflow.com",
])
def test_sitios_legitimos_no_se_marcan(host):
    """Una heuristica que marca sitios normales es peor que no tenerla.

    Entrena a la gente a ignorar las alertas, y una alerta ignorada no
    protege a nadie.
    """
    hallazgos = heuristicas.revisar_dominio(host)
    assert not hallazgos, f"{host} se marco por: {[h.texto for h in hallazgos]}"
