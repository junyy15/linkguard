"""Pruebas de los endpoints del acortador.

Lo que vigilan, en orden de importancia:
  1. Que no se acorte nada sucio.
  2. Que un enlace que DEJO de ser seguro ya no redirija.
  3. Que el destino salga siempre del almacen, nunca de la peticion.
"""

import pytest
from fastapi.testclient import TestClient

import api
from checker import acortador
from checker.scoring import SEGURO, SOSPECHOSO, Señal, Veredicto


@pytest.fixture
def cliente(tmp_path, monkeypatch):
    """Cliente de prueba con limitador reiniciado y almacen temporal."""
    monkeypatch.setattr(api, "_peticiones", api.defaultdict(list))
    monkeypatch.setattr(acortador, "CARPETA", tmp_path)
    monkeypatch.setattr(acortador, "ARCHIVO", tmp_path / "enlaces.json")
    return TestClient(api.app)


# =====================================================================
#  Crear
# =====================================================================

def test_no_se_acorta_una_url_invalida(cliente):
    respuesta = cliente.post("/acortar", json={"url": "javascript:alert(1)"})
    assert respuesta.status_code == 409
    assert respuesta.json()["detail"]["veredicto"] == "RECHAZADA"


def test_no_se_acorta_una_direccion_interna(cliente):
    respuesta = cliente.post("/acortar", json={"url": "http://169.254.169.254/"})
    assert respuesta.status_code == 409


def test_la_negativa_explica_por_que(cliente):
    """Decir 'no' sin motivo es inutil: el usuario no aprende nada."""
    detalle = cliente.post("/acortar",
                           json={"url": "javascript:x"}).json()["detail"]
    assert detalle["razones"]


@pytest.mark.red
@pytest.mark.api
def test_un_sitio_limpio_si_se_acorta(cliente):
    respuesta = cliente.post("/acortar", json={"url": "https://example.com"})
    assert respuesta.status_code == 200
    datos = respuesta.json()
    assert datos["veredicto"] == SEGURO
    assert datos["corto"].endswith(datos["codigo"])


# =====================================================================
#  Abrir
# =====================================================================

def test_un_codigo_inventado_da_404(cliente):
    assert cliente.get("/r/noexiste", follow_redirects=False).status_code == 404


def test_un_enlace_fresco_redirige(cliente, monkeypatch):
    enlace = acortador.acortar("https://example.com", SEGURO)
    respuesta = cliente.get(f"/r/{enlace.codigo}", follow_redirects=False)

    assert respuesta.status_code == 307
    assert respuesta.headers["location"] == "https://example.com"


def test_la_redireccion_es_temporal_no_permanente(cliente):
    """307 y no 301, y la razon es de seguridad, no de capricho.

    El 301 es permanente: los navegadores lo guardan y la proxima vez ni
    siquiera pasan por el servidor. Con 301, la re-revision dejaria de
    ocurrir para siempre. Un acortador que revisa NO puede usar 301.
    """
    enlace = acortador.acortar("https://example.com", SEGURO)
    respuesta = cliente.get(f"/r/{enlace.codigo}", follow_redirects=False)
    assert respuesta.status_code == 307


def test_el_contador_de_usos_sube_al_abrirlo(cliente):
    enlace = acortador.acortar("https://example.com", SEGURO)
    cliente.get(f"/r/{enlace.codigo}", follow_redirects=False)
    cliente.get(f"/r/{enlace.codigo}", follow_redirects=False)
    assert acortador.obtener(enlace.codigo).usos == 2


# =====================================================================
#  LA PRUEBA IMPORTANTE: el enlace se ensucia despues de creado
# =====================================================================

def test_un_enlace_que_dejo_de_ser_seguro_no_redirige(cliente, monkeypatch):
    """El ataque que esto evita:

    el atacante acorta su sitio mientras esta limpio, reparte el enlace
    corto, y DESPUES infecta el sitio. Si solo revisaramos al crear, el
    enlace seguiria mandando gente a un sitio ya infectado.
    """
    enlace = acortador.acortar("https://example.com", SEGURO)

    # Hacemos que la verificacion guardada quede vieja...
    monkeypatch.setattr(acortador, "VIGENCIA_VERIFICACION", 0)

    # ...y que la revision nueva salga mal.
    monkeypatch.setattr(api, "analizar", lambda url, **k: None)
    monkeypatch.setattr(api, "evaluar", lambda _a: Veredicto(
        seguridad=SOSPECHOSO, salud="OK",
        señales=[Señal("Ahora lo reporta VirusTotal", "VirusTotal", peso=3)],
        puntos=3))

    respuesta = cliente.get(f"/r/{enlace.codigo}", follow_redirects=False)

    assert respuesta.status_code == 403
    assert "location" not in respuesta.headers, "no debe redirigir"
    assert "bloqueado" in respuesta.text.lower()
    # La pagina explica por que, no solo dice que no.
    assert "VirusTotal" in respuesta.text


def test_el_veredicto_nuevo_se_guarda(cliente, monkeypatch):
    enlace = acortador.acortar("https://example.com", SEGURO)
    monkeypatch.setattr(acortador, "VIGENCIA_VERIFICACION", 0)
    monkeypatch.setattr(api, "analizar", lambda url, **k: None)
    monkeypatch.setattr(api, "evaluar", lambda _a: Veredicto(
        seguridad=SOSPECHOSO, salud="OK", señales=[], puntos=3))

    cliente.get(f"/r/{enlace.codigo}", follow_redirects=False)
    assert acortador.obtener(enlace.codigo).veredicto == SOSPECHOSO


# =====================================================================
#  No es un redirector abierto
# =====================================================================

def test_no_se_puede_redirigir_a_una_url_de_la_peticion(cliente):
    """Un acortador que acepta '?url=...' es un redirector abierto, y
    sirve para prestarle tu reputacion al sitio de otro: la victima ve
    TU dominio en el enlace.

    El destino sale siempre del almacen. El parametro se ignora.
    """
    enlace = acortador.acortar("https://example.com", SEGURO)
    respuesta = cliente.get(f"/r/{enlace.codigo}?url=http://sitio-malo.com",
                            follow_redirects=False)
    assert respuesta.headers["location"] == "https://example.com"


def test_un_codigo_con_barra_no_llega_al_almacen(cliente):
    """Nada de rutas raras colandose como codigo."""
    assert cliente.get("/r/../../etc/passwd",
                       follow_redirects=False).status_code in (307, 404)
