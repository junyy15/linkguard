"""Pruebas del cache y del limitador de cuota.

Ninguna toca internet. El cache se manda a una carpeta temporal con la
fixture cache_aislado, para no ensuciar el cache de verdad ni depender
de lo que haya dejado otra prueba.
"""

import time
from concurrent.futures import ThreadPoolExecutor

from checker.threats import Limitador


def test_guardar_y_leer(cache_aislado):
    cache_aislado.guardar("clave:1", {"dato": 42}, limpio=True)
    assert cache_aislado.leer("clave:1") == {"dato": 42}


def test_clave_que_no_existe(cache_aislado):
    assert cache_aislado.leer("no-existe") is None


def test_una_entrada_caducada_no_se_devuelve(cache_aislado, monkeypatch):
    monkeypatch.setattr(cache_aislado, "VIGENCIA_LIMPIO", 0)
    cache_aislado.guardar("clave:2", {"dato": 1}, limpio=True)
    assert cache_aislado.leer("clave:2") is None


def test_lo_limpio_caduca_antes_que_lo_reportado(cache_aislado):
    """La decision asimetrica del Dia 3 de la Semana 2.

    Guardar "limpio" mucho tiempo es peligroso: dirias "seguro" de un sitio
    que ya se infecto. Guardar "reportado" de mas solo causa una falsa alarma.
    """
    assert cache_aislado.VIGENCIA_LIMPIO < cache_aislado.VIGENCIA_REPORTADO


def test_un_archivo_corrupto_no_tumba_el_programa(cache_aislado):
    cache_aislado.CARPETA.mkdir(exist_ok=True)
    cache_aislado.ARCHIVO.write_text("esto no es json {{{", encoding="utf-8")
    assert cache_aislado.leer("lo-que-sea") is None


def test_varios_hilos_no_se_pisan(cache_aislado):
    """Sin el candado, dos hilos leen, cada uno agrega SU clave sobre la
    version vieja, y el ultimo en escribir borra lo del otro.
    """
    claves = [f"hilo:{n}" for n in range(12)]
    with ThreadPoolExecutor(max_workers=12) as pool:
        for n, clave in enumerate(claves):
            pool.submit(cache_aislado.guardar, clave, {"n": n}, False)

    sobrevivieron = [c for c in claves if cache_aislado.leer(c) is not None]
    assert len(sobrevivieron) == len(claves)


# =====================================================================
#  El limitador de cuota
# =====================================================================

def test_las_primeras_peticiones_pasan_de_inmediato():
    """Si llevas rato sin usar la API, no tiene por que hacerte esperar."""
    limitador = Limitador(maximo=3, ventana=10.0)
    for _ in range(3):
        assert limitador.esperar() == 0


def test_la_de_mas_espera_su_turno():
    limitador = Limitador(maximo=2, ventana=0.5)
    limitador.esperar()
    limitador.esperar()

    inicio = time.monotonic()
    limitador.esperar()
    assert time.monotonic() - inicio >= 0.4
