"""Pruebas de la API HTTP.

TestClient de FastAPI levanta la aplicacion EN MEMORIA: no hace falta
arrancar un servidor ni abrir un puerto. Las peticiones son reales para
la aplicacion, pero nunca salen de la computadora.
"""

import pytest
from fastapi.testclient import TestClient

import api
from checker.reporte import VERSION_FORMATO


@pytest.fixture
def cliente(monkeypatch):
    """Un cliente de prueba con el limitador reiniciado.

    Sin reiniciarlo, la prueba numero 11 fallaria por el limite de 10 por
    minuto que dejaron las anteriores. Otra vez: una prueba nunca debe
    depender de lo que hizo otra.
    """
    monkeypatch.setattr(api, "_peticiones", api.defaultdict(list))
    return TestClient(api.app)


def test_la_raiz_responde(cliente):
    respuesta = cliente.get("/")
    assert respuesta.status_code == 200
    assert respuesta.json()["version_formato"] == VERSION_FORMATO


def test_falta_la_url(cliente):
    """Pydantic rechaza la peticion antes de llegar a nuestro codigo."""
    assert cliente.post("/check", json={}).status_code == 422


def test_url_demasiado_larga(cliente):
    respuesta = cliente.post("/check", json={"url": "h" * 5000})
    assert respuesta.status_code == 422


def test_url_invalida_responde_200_con_veredicto_rechazada(cliente):
    """Ojo: una URL invalida NO es un error de la API.

    La API funciono perfectamente: analizo y su respuesta es 'rechazada'.
    Devolver 400 aqui seria confundir "tu peticion esta mal formada" con
    "la URL que me diste es peligrosa".
    """
    respuesta = cliente.post("/check", json={"url": "javascript:alert(1)"})
    assert respuesta.status_code == 200
    assert respuesta.json()["veredicto"]["seguridad"] == "RECHAZADA"


def test_ssrf_bloqueado_por_la_api(cliente):
    """Lo mas importante de exponer esto por HTTP.

    Sin el guardia del Modulo 0, cualquiera podria usar TU servidor para
    tocar direcciones de TU red interna.
    """
    respuesta = cliente.post("/check", json={"url": "http://169.254.169.254/"})
    assert respuesta.status_code == 200
    datos = respuesta.json()
    assert datos["veredicto"]["seguridad"] == "RECHAZADA"
    assert "interna" in datos["validacion"]["motivo"]


def test_el_limitador_corta(cliente):
    """Pasado el limite, 429 y un Retry-After que diga cuanto esperar."""
    for _ in range(api.LIMITE_POR_IP):
        cliente.post("/check", json={"url": "javascript:x", "amenazas": False})

    respuesta = cliente.post("/check", json={"url": "javascript:x",
                                             "amenazas": False})
    assert respuesta.status_code == 429
    assert "Retry-After" in respuesta.headers


def test_un_error_interno_no_filtra_detalles(cliente, monkeypatch):
    """Un traceback en la respuesta le regala a un atacante las rutas de
    tu disco y la estructura de tu proyecto."""
    def explotar(*_args, **_kwargs):
        raise RuntimeError("C:\\Users\\Glee51\\secreto\\ruta.py revento")

    monkeypatch.setattr(api, "analizar", explotar)
    respuesta = cliente.post("/check", json={"url": "https://example.com"})

    assert respuesta.status_code == 500
    cuerpo = respuesta.text
    assert "secreto" not in cuerpo
    assert "RuntimeError" not in cuerpo


def test_la_documentacion_se_genera_sola(cliente):
    assert cliente.get("/docs").status_code == 200
    esquema = cliente.get("/openapi.json").json()
    assert "/check" in esquema["paths"]


@pytest.mark.red
@pytest.mark.api
def test_analisis_real_por_http(cliente):
    respuesta = cliente.post("/check", json={"url": "https://example.com"})
    assert respuesta.status_code == 200
    datos = respuesta.json()
    assert datos["veredicto"]["seguridad"] == "SEGURO"
    assert datos["version"] == VERSION_FORMATO


@pytest.mark.red
def test_se_puede_pedir_sin_consultar_amenazas(cliente):
    respuesta = cliente.post("/check", json={"url": "https://example.com",
                                             "amenazas": False})
    datos = respuesta.json()
    assert datos["amenazas"]["google_safe_browsing"] is None
    # Sin consultar fuentes, el veredicto NUNCA puede ser SEGURO.
    assert datos["veredicto"]["seguridad"] == "SIN_CONFIRMAR"
