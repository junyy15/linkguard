"""Pruebas de las traducciones.

La mas util es la de completitud: cuando agregas un texto en español y
se te olvida el ingles, esta prueba te lo dice en el momento, no un
usuario tres semanas despues.
"""

import pytest

import idiomas
from checker import scoring

OTROS = [codigo for codigo in idiomas.IDIOMAS if codigo != idiomas.POR_DEFECTO]


# =====================================================================
#  Completitud: que no falte nada
# =====================================================================

@pytest.mark.parametrize("idioma", OTROS)
def test_no_falta_ningun_texto(idioma):
    faltan = set(idiomas.TEXTOS[idiomas.POR_DEFECTO]) - set(idiomas.TEXTOS[idioma])
    assert not faltan, f"faltan en '{idioma}': {sorted(faltan)}"


@pytest.mark.parametrize("idioma", OTROS)
def test_no_sobra_ningun_texto(idioma):
    """Un texto que sobra suele ser una clave mal escrita."""
    sobran = set(idiomas.TEXTOS[idioma]) - set(idiomas.TEXTOS[idiomas.POR_DEFECTO])
    assert not sobran, f"sobran en '{idioma}': {sorted(sobran)}"


@pytest.mark.parametrize("idioma", idiomas.IDIOMAS)
def test_todos_los_veredictos_tienen_texto(idioma):
    """Si mañana se agrega un nivel y falta su traduccion, se caza aqui."""
    faltan = [n for n in scoring.ORDEN if n not in idiomas.VEREDICTOS[idioma]]
    assert not faltan, f"sin texto en '{idioma}': {faltan}"


@pytest.mark.parametrize("idioma", OTROS)
def test_todas_las_señales_estan_traducidas(idioma):
    faltan = [pedazo for pedazo, versiones in idiomas.SEÑALES
              if idioma not in versiones]
    assert not faltan, f"señales sin '{idioma}': {faltan}"


# =====================================================================
#  Que las traducciones sean de verdad distintas
# =====================================================================

@pytest.mark.parametrize("nivel", scoring.ORDEN)
def test_el_ingles_no_es_el_español_copiado(nivel):
    es = idiomas.VEREDICTOS["es"][nivel]
    en = idiomas.VEREDICTOS["en"][nivel]
    # El emoji si es el mismo; el texto no debe serlo.
    assert es[1] != en[1], f"el titulo de {nivel} esta sin traducir"
    assert es[2] != en[2], f"la explicacion de {nivel} esta sin traducir"


# =====================================================================
#  El requisito legal, en los dos idiomas
# =====================================================================

@pytest.mark.parametrize("idioma", idiomas.IDIOMAS)
def test_ningun_veredicto_afirma_con_certeza(idioma):
    """Los terminos de Google prohiben afirmar que un sitio ES peligroso.

    La traduccion tambien tiene que cumplirlo: es facil traducir
    'podria ser peligroso' como 'is dangerous' sin darse cuenta.
    """
    prohibidas = [
        "es peligroso", "es malicioso", "confirmado",
        "is dangerous", "is malicious", "is unsafe", "confirmed",
        "definitely", "guaranteed",
    ]
    for nivel, (_emoji, titulo, explicacion, que_hacer) in \
            idiomas.VEREDICTOS[idioma].items():
        completo = f"{titulo} {explicacion} {que_hacer}".lower()
        for frase in prohibidas:
            assert frase not in completo, \
                f"{idioma}/{nivel} afirma demasiado: '{frase}'"


# =====================================================================
#  Las funciones
# =====================================================================

def test_t_devuelve_cada_idioma():
    assert idiomas.t("revisar", "es") == "Revisar"
    assert idiomas.t("revisar", "en") == "Check link"


def test_t_rellena_los_huecos():
    assert "7" in idiomas.t("redirecciones", "es", n=7)
    assert "7" in idiomas.t("redirecciones", "en", n=7)


def test_un_idioma_desconocido_cae_al_español():
    """Una traduccion incompleta debe verse rara, no reventar la pagina."""
    assert idiomas.t("revisar", "xx") == idiomas.t("revisar", "es")


def test_una_clave_que_no_existe_no_revienta():
    assert idiomas.t("clave_inventada", "en") == "clave_inventada"


@pytest.mark.parametrize("idioma, pedazo", [
    ("es", "roban contraseñas"),
    ("en", "steal passwords"),
])
def test_las_señales_se_traducen(idioma, pedazo):
    traducida = idiomas.en_palabras_normales(
        "Phishing o ingenieria social", idioma)
    assert pedazo in traducida


def test_una_señal_desconocida_se_deja_igual():
    texto = "Algo que nadie previo"
    assert idiomas.en_palabras_normales(texto, "en") == texto
