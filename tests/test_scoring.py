"""Pruebas del Modulo 3: el criterio del veredicto.

Ninguna toca internet. Se fabrican analisis a mano y se revisa que el
veredicto sea el correcto. Son las pruebas mas importantes del proyecto:
prueban lo que la herramienta DECIDE.
"""

import pytest
from conftest import (
    fabricar,
    fuente_caida,
    fuente_google_reporta,
    fuente_limpia,
    fuente_vt,
)

from checker import scoring


def test_todo_limpio_es_seguro(limpias):
    google, vt = limpias
    assert scoring.evaluar(fabricar(google, vt)).seguridad == scoring.SEGURO


def test_google_reporta_es_posiblemente_peligroso(limpias):
    _google, vt = limpias
    veredicto = scoring.evaluar(fabricar(fuente_google_reporta(), vt))
    assert veredicto.seguridad == scoring.POSIBLEMENTE_PELIGROSO


def test_dos_antivirus_bastan(limpias):
    google, _vt = limpias
    veredicto = scoring.evaluar(fabricar(google, fuente_vt(2)))
    assert veredicto.seguridad == scoring.POSIBLEMENTE_PELIGROSO


def test_un_solo_antivirus_no_basta(limpias):
    """VirusTotal consulta mas de 90 motores: que uno marque algo es ruido.

    Cuenta (suma 2 puntos) pero no alcanza para el nivel mas alto.
    """
    google, _vt = limpias
    veredicto = scoring.evaluar(fabricar(google, fuente_vt(1)))
    assert veredicto.seguridad == scoring.SEGURO
    assert veredicto.puntos == 2


def test_un_antivirus_mas_otra_señal_si_alcanza(limpias):
    google, _vt = limpias
    veredicto = scoring.evaluar(
        fabricar(google, fuente_vt(1), url_final="http://ejemplo.com"))
    assert veredicto.seguridad == scoring.SOSPECHOSO


def test_una_fuente_sola_basta_aunque_la_otra_diga_limpio(limpias):
    """Si las fuentes se contradicen, gana la mas grave."""
    google, _vt = limpias
    veredicto = scoring.evaluar(fabricar(google, fuente_vt(5)))
    assert veredicto.seguridad == scoring.POSIBLEMENTE_PELIGROSO


# =====================================================================
#  La regla de oro: no saber NO es estar limpio
# =====================================================================

def test_fuente_caida_impide_decir_seguro(limpias):
    _google, vt = limpias
    veredicto = scoring.evaluar(fabricar(fuente_caida("Google Safe Browsing"), vt))
    assert veredicto.seguridad == scoring.SIN_CONFIRMAR


def test_fuente_sin_consultar_impide_decir_seguro():
    """El bug real: el modo lista decia SEGURO sin preguntarle a nadie.

    Hay dos formas de no saber -que la fuente falle y que ni se consulte-
    y las dos cuentan igual.
    """
    veredicto = scoring.evaluar(fabricar(None, None))
    assert veredicto.seguridad == scoring.SIN_CONFIRMAR


def test_fuente_caida_no_tapa_una_amenaza_confirmada():
    """No saber de una fuente no borra lo que dijo la otra."""
    veredicto = scoring.evaluar(
        fabricar(fuente_caida("Google Safe Browsing"), fuente_vt(3)))
    assert veredicto.seguridad == scoring.POSIBLEMENTE_PELIGROSO


# =====================================================================
#  Señales de la forma del enlace
# =====================================================================

@pytest.mark.parametrize("kwargs, esperado", [
    ({"tipo_error": "ssl"}, scoring.SOSPECHOSO),
    ({"problema": "Salto 2 bloqueado: interna"}, scoring.SOSPECHOSO),
    ({"url_final": "http://otro.com", "baja_seguridad": True,
      "cambia_dominio": True}, scoring.SOSPECHOSO),
])
def test_señales_de_forma(limpias, kwargs, esperado):
    google, vt = limpias
    assert scoring.evaluar(fabricar(google, vt, **kwargs)).seguridad == esperado


def test_url_invalida_es_rechazada():
    veredicto = scoring.evaluar(
        fabricar(valida=False, motivo="Esquema no permitido"))
    assert veredicto.seguridad == scoring.RECHAZADA


# =====================================================================
#  Coherencia de lo que se le dice al usuario
# =====================================================================

def test_no_dice_sin_señales_si_hay_señales(limpias):
    """Contradecirse destruye la confianza mas rapido que cualquier bug."""
    google, vt = limpias
    veredicto = scoring.evaluar(
        fabricar(google, vt, url_final="http://ejemplo.com"))
    assert veredicto.puntos > 0
    assert "No encontramos señales" not in veredicto.frase


def test_todo_veredicto_tiene_frase():
    for nivel in scoring.ORDEN:
        assert scoring.FRASES.get(nivel), f"{nivel} no tiene frase"


def test_ningun_mensaje_afirma_con_certeza():
    """Los terminos de Google prohiben afirmar que un sitio ES peligroso.

    Y ademas es la verdad: la herramienta no sabe, sabe que lo reportaron.
    """
    prohibidas = ["es peligroso", "es malicioso", "confirmado", "seguro que"]
    for nivel, frase in scoring.FRASES.items():
        minuscula = frase.lower()
        for palabra in prohibidas:
            assert palabra not in minuscula, f"{nivel} afirma demasiado: {frase}"


def test_atribucion_a_google_solo_si_viene_de_google(limpias):
    """Sus terminos prohiben poner su credito en advertencias de otros."""
    google, _vt = limpias
    solo_vt = scoring.evaluar(fabricar(google, fuente_vt(3)))
    assert not solo_vt.cita_a_google

    con_google = scoring.evaluar(fabricar(fuente_google_reporta(), fuente_vt(0)))
    assert con_google.cita_a_google


def test_el_veredicto_usa_las_heuristicas(limpias):
    google, vt = limpias
    veredicto = scoring.evaluar(
        fabricar(google, vt, url_final="https://paypal.com.robo.xyz/login"))
    assert veredicto.seguridad == scoring.SOSPECHOSO
    assert any(s.fuente == "Heuristica" for s in veredicto.señales)
