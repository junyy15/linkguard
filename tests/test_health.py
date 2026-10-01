"""Pruebas del Modulo 1: salud del enlace y cadena de redirecciones.

La parte de logica pura (clasificar codigos) no toca internet.
La cadena se prueba con respuestas simuladas.
Lo que si sale a la red lleva la etiqueta @pytest.mark.red.
"""

import pytest

import checker.health as health
from checker.health import Salud, clasificar, dominio_de, seguir_cadena


# =====================================================================
#  Logica pura: instantanea, nunca falla por el wifi
# =====================================================================

@pytest.mark.parametrize("codigo, categoria", [
    (200, "OK"), (204, "OK"),
    (301, "REDIRECCION"), (302, "REDIRECCION"),
    (401, "BLOQUEADO"), (403, "BLOQUEADO"), (429, "BLOQUEADO"),
    (404, "ROTO"), (410, "ROTO"), (500, "ROTO"), (503, "ROTO"),
])
def test_clasificar_codigos_http(codigo, categoria):
    assert clasificar(codigo)[0] == categoria


def test_403_no_es_lo_mismo_que_roto():
    """Un sitio que no deja entrar a programas NO esta roto.

    Confundirlos es un falso positivo, y una herramienta que grita "roto"
    cuando no lo esta pierde credibilidad.
    """
    assert clasificar(403)[0] == "BLOQUEADO"
    assert clasificar(404)[0] == "ROTO"


@pytest.mark.parametrize("url, host", [
    ("https://ejemplo.com/ruta", "ejemplo.com"),
    ("http://SUB.Ejemplo.COM", "sub.ejemplo.com"),
    ("no-es-una-url", None),
])
def test_dominio_de(url, host):
    assert dominio_de(url) == (host or "")


# =====================================================================
#  La cadena, con respuestas simuladas
# =====================================================================

def redireccion_a(destino: str) -> Salud:
    return Salud(categoria="REDIRECCION", codigo=301, razon="simulado",
                 tiempo_ms=1, destino=destino, metodo="HEAD")


def llegada() -> Salud:
    return Salud(categoria="OK", codigo=200, razon="simulado",
                 tiempo_ms=1, metodo="HEAD")


@pytest.fixture
def simular(monkeypatch):
    """Devuelve una funcion que corre seguir_cadena() con respuestas dictadas.

    monkeypatch deshace el cambio al terminar la prueba, asi que no hace
    falta acordarse de restaurar nada: ese try/finally lo pone pytest.
    """
    def correr(guion: dict[str, Salud], inicio: str, max_saltos: int = 10):
        monkeypatch.setattr(
            health, "revisar_salud",
            lambda url, tiempo_limite=5.0: guion.get(url, llegada()))
        return seguir_cadena(inicio, max_saltos=max_saltos)
    return correr


def test_cadena_bloquea_salto_hacia_direccion_interna(simular):
    """El caso que da sentido a todo el Dia 4 de la Semana 1.

    Una cadena puede empezar en un dominio publico e inocente y terminar
    apuntando a 127.0.0.1. Validar solo la primera URL no sirve de nada.
    """
    cadena = simular({
        "https://example.com/inicio": redireccion_a("https://example.com/paso2"),
        "https://example.com/paso2": redireccion_a("http://127.0.0.1/admin"),
    }, "https://example.com/inicio")

    assert cadena.problema is not None
    assert "bloquead" in cadena.problema


def test_cadena_detecta_bucles(simular):
    cadena = simular({
        "https://example.com/a": redireccion_a("https://example.com/b"),
        "https://example.com/b": redireccion_a("https://example.com/a"),
    }, "https://example.com/a")
    assert "circulo" in (cadena.problema or "")


def test_cadena_detecta_bajada_a_http(simular):
    cadena = simular({
        "https://example.com/seguro": redireccion_a("http://example.com/x"),
    }, "https://example.com/seguro")
    assert cadena.baja_seguridad


def test_location_relativo_se_completa(simular):
    """El servidor puede contestar solo '/dos'. urljoin lo completa."""
    cadena = simular({
        "https://example.com/uno": redireccion_a("/dos"),
    }, "https://example.com/uno")
    assert cadena.url_final == "https://example.com/dos"


def test_cadena_corta_al_llegar_al_limite(simular):
    cadena = simular(
        {f"https://example.com/{n}": redireccion_a(f"https://example.com/{n + 1}")
         for n in range(1, 20)},
        "https://example.com/1", max_saltos=5)
    assert "Demasiadas" in (cadena.problema or "")


# =====================================================================
#  Las que si salen a internet
# =====================================================================

@pytest.mark.red
@pytest.mark.parametrize("url, categoria", [
    ("https://example.com", "OK"),
    ("http://github.com", "REDIRECCION"),
    ("https://www.google.com/pagina-que-no-existe-12345", "ROTO"),
    ("https://expired.badssl.com/", "ERROR"),
    ("https://self-signed.badssl.com/", "ERROR"),
])
def test_peticiones_reales(url, categoria):
    assert health.revisar_salud(url).categoria == categoria


@pytest.mark.red
def test_certificado_vencido_se_distingue_de_otros_errores():
    salud = health.revisar_salud("https://expired.badssl.com/")
    assert salud.tipo_error == "ssl"


@pytest.mark.red
def test_timeout():
    salud = health.revisar_salud("https://example.com", tiempo_limite=0.001)
    assert salud.tipo_error == "timeout"


@pytest.mark.red
def test_cadena_real_de_github():
    cadena = seguir_cadena("http://github.com")
    assert cadena.url_final == "https://github.com/"
    assert cadena.num_saltos == 1
