"""Pruebas del acortador.

Un acortador es un redirector, o sea justo lo que esta herramienta marca
como sospechoso en los enlaces ajenos. Estas pruebas vigilan que el
nuestro cumpla las mismas reglas que le exigimos a los demas.
"""

import time

import pytest

from checker import acortador
from checker.acortador import NoSePuedeAcortar
from checker.scoring import (
    POSIBLEMENTE_PELIGROSO,
    RECHAZADA,
    SEGURO,
    SIN_CONFIRMAR,
    SOSPECHOSO,
)


@pytest.fixture
def almacen(tmp_path, monkeypatch):
    """Manda el almacen de enlaces a una carpeta temporal.

    Sin esto las pruebas ensuciarian tus enlaces reales, y una prueba
    podria pasar solo por lo que dejo otra.
    """
    monkeypatch.setattr(acortador, "CARPETA", tmp_path)
    monkeypatch.setattr(acortador, "ARCHIVO", tmp_path / "enlaces.json")
    return acortador


# =====================================================================
#  La condicion: solo se acorta lo limpio
# =====================================================================

def test_un_enlace_seguro_si_se_acorta(almacen):
    enlace = almacen.acortar("https://example.com", SEGURO)
    assert enlace.url == "https://example.com"
    assert len(enlace.codigo) == almacen.LARGO_CODIGO


@pytest.mark.parametrize("veredicto", [
    SIN_CONFIRMAR, SOSPECHOSO, POSIBLEMENTE_PELIGROSO, RECHAZADA,
])
def test_lo_demas_no_se_acorta(almacen, veredicto):
    """Ni siquiera SIN_CONFIRMAR.

    Un enlace corto es una recomendacion implicita, y no se recomienda
    lo que no se pudo comprobar.
    """
    with pytest.raises(NoSePuedeAcortar):
        almacen.acortar("https://example.com", veredicto)


def test_nada_se_guarda_si_no_se_permitio(almacen):
    with pytest.raises(NoSePuedeAcortar):
        almacen.acortar("https://malo.com", SOSPECHOSO)
    assert almacen.listar() == []


# =====================================================================
#  Los codigos
# =====================================================================

def test_los_codigos_no_son_predecibles(almacen):
    """Si fueran 1, 2, 3... cualquiera podria recorrerlos todos."""
    codigos = {almacen.generar_codigo() for _ in range(500)}
    # 32^7 combinaciones: 500 al azar no deberian repetirse nunca.
    assert len(codigos) == 500


def test_los_codigos_evitan_caracteres_confusos():
    """Nada de 0/O ni 1/l/I: alguien puede copiar el enlace a mano."""
    for confuso in "01lIO":
        assert confuso not in acortador.ALFABETO


def test_la_misma_url_reusa_el_codigo(almacen):
    primero = almacen.acortar("https://example.com", SEGURO)
    segundo = almacen.acortar("https://example.com", SEGURO)
    assert primero.codigo == segundo.codigo
    assert len(almacen.listar()) == 1


def test_urls_distintas_dan_codigos_distintos(almacen):
    uno = almacen.acortar("https://example.com", SEGURO)
    dos = almacen.acortar("https://github.com", SEGURO)
    assert uno.codigo != dos.codigo


# =====================================================================
#  Guardar, leer y caducar
# =====================================================================

def test_se_puede_recuperar_por_codigo(almacen):
    enlace = almacen.acortar("https://example.com", SEGURO)
    recuperado = almacen.obtener(enlace.codigo)
    assert recuperado is not None
    assert recuperado.url == "https://example.com"


def test_un_codigo_inventado_no_devuelve_nada(almacen):
    assert almacen.obtener("noexiste") is None


def test_una_verificacion_fresca_no_necesita_revision(almacen):
    enlace = almacen.acortar("https://example.com", SEGURO)
    assert not enlace.necesita_revision


def test_una_verificacion_vieja_si_necesita_revision(almacen, monkeypatch):
    """La regla que evita el cheque en blanco.

    Sin esto, un atacante podria acortar su sitio limpio, repartir el
    enlace, y ensuciar el sitio despues.
    """
    monkeypatch.setattr(almacen, "VIGENCIA_VERIFICACION", 0)
    enlace = almacen.acortar("https://example.com", SEGURO)
    time.sleep(0.01)
    assert almacen.obtener(enlace.codigo).necesita_revision


def test_el_contador_de_usos_sube(almacen):
    enlace = almacen.acortar("https://example.com", SEGURO)
    almacen.registrar_uso(enlace.codigo)
    almacen.registrar_uso(enlace.codigo)
    assert almacen.obtener(enlace.codigo).usos == 2


def test_se_puede_borrar(almacen):
    enlace = almacen.acortar("https://example.com", SEGURO)
    assert almacen.borrar(enlace.codigo)
    assert almacen.obtener(enlace.codigo) is None
    assert not almacen.borrar(enlace.codigo)


def test_un_archivo_corrupto_no_tumba_el_programa(almacen):
    almacen.CARPETA.mkdir(exist_ok=True)
    almacen.ARCHIVO.write_text("esto no es json {{{", encoding="utf-8")
    assert almacen.obtener("loquesea") is None
    # Y se puede seguir usando: el archivo malo se reemplaza.
    assert almacen.acortar("https://example.com", SEGURO)
