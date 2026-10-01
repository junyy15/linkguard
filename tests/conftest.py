"""
conftest.py es un archivo especial de pytest.

Todo lo que se define aqui esta disponible automaticamente en TODOS los
archivos de prueba de esta carpeta, sin importar nada. pytest lo carga solo.

Aqui viven dos cosas:
  - Las funciones que fabrican analisis falsos (antes estaban en probar.py).
  - Las "fixtures": preparativos que pytest le pasa a una prueba con solo
    poner su nombre como parametro.
"""

import pytest

from checker.health import Cadena, Salto, Salud
from checker.scanner import Analisis
from checker.threats import Amenaza, ResultadoAmenazas
from checker.validator import Validacion


# =====================================================================
#  Fabricas de datos falsos
# =====================================================================

def fabricar(google=None, virustotal=None, url_final="https://ejemplo.com",
             tipo_error=None, problema=None, cambia_dominio=False,
             baja_seguridad=False, saltos=1, valida=True, motivo=None) -> Analisis:
    """Arma un Analisis falso, sin tocar internet."""
    validacion = Validacion(ok=valida, url=url_final if valida else None,
                            motivo=motivo, ips=["93.184.216.34"] if valida else [])
    if not valida:
        return Analisis(entrada=url_final, validacion=validacion)

    salud = Salud(categoria="ERROR" if tipo_error else "OK",
                  codigo=None if tipo_error else 200,
                  razon="fabricado", tiempo_ms=1, tipo_error=tipo_error)

    cadena = Cadena(
        saltos=[Salto(numero=n + 1, url=url_final) for n in range(saltos)],
        url_final=url_final,
        salud_final=salud,
        problema=problema,
        cambia_de_dominio=cambia_dominio,
        baja_seguridad=baja_seguridad,
    )
    return Analisis(entrada=url_final, validacion=validacion, cadena=cadena,
                    google=google, virustotal=virustotal)


def fuente_limpia(nombre: str) -> ResultadoAmenazas:
    """Una base de amenazas que contesto y no encontro nada."""
    return ResultadoAmenazas(fuente=nombre, consultado=True)


def fuente_caida(nombre: str) -> ResultadoAmenazas:
    """Una base de amenazas que no pudo contestar."""
    return ResultadoAmenazas(fuente=nombre, consultado=False, error="fabricado")


def fuente_google_reporta() -> ResultadoAmenazas:
    return ResultadoAmenazas(
        fuente="Google Safe Browsing", consultado=True,
        amenazas=[Amenaza("Google Safe Browsing", "SOCIAL_ENGINEERING", "x")])


def fuente_vt(maliciosos: int, sospechosos: int = 0) -> ResultadoAmenazas:
    resultado = ResultadoAmenazas(
        fuente="VirusTotal", consultado=True,
        estadisticas={"malicious": maliciosos, "suspicious": sospechosos,
                      "harmless": 60, "undetected": 30})
    if maliciosos:
        resultado.amenazas.append(Amenaza("VirusTotal", "MALICIOUS", "x"))
    elif sospechosos:
        resultado.amenazas.append(Amenaza("VirusTotal", "SUSPICIOUS", "x"))
    return resultado


# =====================================================================
#  Fixtures
# =====================================================================
#
# Una fixture es un preparativo. La prueba pide su nombre como parametro
# y pytest se encarga de armarlo y, si hace falta, de limpiarlo al final.

@pytest.fixture
def limpias():
    """Las dos fuentes consultadas y sin hallazgos."""
    return fuente_limpia("Google Safe Browsing"), fuente_vt(0)


@pytest.fixture
def cache_aislado(tmp_path, monkeypatch):
    """Manda el cache a una carpeta temporal.

    Sin esto, las pruebas escribirian en el cache de verdad del proyecto:
    lo ensuciarian, y ademas una prueba podria pasar solo porque otra dejo
    algo guardado. Una prueba que depende de lo que hizo otra no sirve.

    tmp_path y monkeypatch son fixtures que trae pytest:
      tmp_path    -> una carpeta vacia, distinta en cada prueba
      monkeypatch -> cambia algo y lo deja como estaba al terminar
    """
    from checker import cache

    monkeypatch.setattr(cache, "CARPETA", tmp_path)
    monkeypatch.setattr(cache, "ARCHIVO", tmp_path / "consultas.json")
    return cache
