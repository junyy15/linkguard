"""Pruebas del coordinador: analizar()."""

import pytest

from checker.scanner import analizar


def test_url_invalida_no_gasta_ni_una_peticion():
    """Si la validacion falla, seguir adelante seria tirar tiempo y cuota."""
    resultado = analizar("javascript:alert(1)")
    assert not resultado.paso_validacion
    assert resultado.cadena is None
    assert resultado.google is None
    assert resultado.virustotal is None


@pytest.mark.red
def test_se_puede_analizar_sin_tocar_las_apis():
    resultado = analizar("https://example.com", consultar_amenazas=False)
    assert resultado.paso_validacion
    assert resultado.cadena is not None
    assert resultado.google is None
    assert resultado.virustotal is None


@pytest.mark.red
@pytest.mark.api
def test_un_analisis_completo_trae_todas_las_piezas():
    resultado = analizar("https://example.com")
    assert resultado.paso_validacion
    assert resultado.cadena is not None
    assert resultado.google is not None
    assert resultado.virustotal is not None
    assert resultado.tiempo_ms > 0
