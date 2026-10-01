"""Pruebas del contrato de salida: JSON, codigos de salida y colores.

Varias de estas no comprueban un comportamiento, sino que dos partes del
codigo sigan de acuerdo entre si. Son pruebas contra tu yo del futuro
distraido: si mañana agregas un nivel de veredicto y olvidas darle codigo
de salida, se reportaria como 0 ("todo bien") sin avisar.
"""

import json

from conftest import fabricar, fuente_google_reporta, fuente_vt

import check as cli
from checker import scoring
from checker.reporte import VERSION_FORMATO, a_diccionario


def analisis_reportado():
    return fabricar(fuente_google_reporta(), fuente_vt(4))


def test_el_json_lleva_version():
    analisis = analisis_reportado()
    datos = a_diccionario(analisis, scoring.evaluar(analisis))
    assert datos["version"] == VERSION_FORMATO


def test_el_json_trae_veredicto_y_razones():
    analisis = analisis_reportado()
    datos = a_diccionario(analisis, scoring.evaluar(analisis))
    assert datos["veredicto"]["seguridad"] == scoring.POSIBLEMENTE_PELIGROSO
    assert len(datos["veredicto"]["razones"]) == 2


def test_el_json_se_puede_serializar():
    """Un objeto que json no sepa convertir revienta aqui, no en el usuario."""
    analisis = analisis_reportado()
    datos = a_diccionario(analisis, scoring.evaluar(analisis))
    assert json.dumps(datos, ensure_ascii=False)


def test_una_url_invalida_tambien_serializa():
    invalida = fabricar(valida=False, motivo="Esquema no permitido")
    datos = a_diccionario(invalida, scoring.evaluar(invalida))
    assert datos["cadena"] is None
    assert json.dumps(datos)


# =====================================================================
#  Contratos entre modulos
# =====================================================================

def test_todo_veredicto_tiene_codigo_de_salida():
    faltan = [nivel for nivel in scoring.ORDEN if nivel not in cli.CODIGOS]
    assert not faltan, f"sin codigo de salida: {faltan}"


def test_mas_grave_es_codigo_mas_alto():
    codigos = [cli.CODIGOS[nivel] for nivel in scoring.ORDEN]
    assert codigos == sorted(codigos)
    assert len(set(codigos)) == len(codigos), "hay codigos repetidos"


def test_todo_veredicto_tiene_color():
    faltan = [nivel for nivel in scoring.ORDEN if nivel not in cli.ESTILOS]
    assert not faltan, f"sin color: {faltan}"


def test_todo_veredicto_tiene_etiqueta_corta_para_la_lista():
    faltan = [nivel for nivel in scoring.ORDEN if nivel not in cli.CORTO]
    assert not faltan, f"sin etiqueta corta: {faltan}"
