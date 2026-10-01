"""Pruebas del arreglo de DNS rebinding.

El hueco que tapan: validar el DNS y luego dejar que httpx lo resuelva
otra vez son DOS resoluciones, y entre una y otra un atacante que controle
su DNS puede cambiar la respuesta de una IP publica a 127.0.0.1.

El arreglo es resolver una sola vez y conectarse a esa IP, conservando el
nombre en el encabezado Host y en el SNI del certificado.
"""

import pytest

import checker.health as health
from checker.health import (
    DestinoNoPermitido,
    DestinoNoResoluble,
    fijar_destino,
    ordenar_ips,
    seguir_cadena,
)


# =====================================================================
#  Dobles para no tocar la red
# =====================================================================

class RespuestaFalsa:
    def __init__(self, codigo: int = 200, cabeceras: dict | None = None):
        self.status_code = codigo
        self.headers = cabeceras or {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class ClienteFalso:
    """Un cliente que solo sabe hacer stream().

    Ojo con el detalle: NO implementa .head() ni .get(). Si el codigo
    volviera a usarlos, la prueba reventaria con AttributeError. O sea,
    esta clase tambien vigila que nunca se descargue el cuerpo.
    """

    ultima: dict = {}

    def __init__(self, **_kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def stream(self, metodo, destino, headers=None, extensions=None):
        ClienteFalso.ultima = {
            "metodo": metodo,
            "destino": destino,
            "headers": headers or {},
            "extensions": extensions or {},
        }
        return RespuestaFalsa()


@pytest.fixture
def cliente_falso(monkeypatch):
    ClienteFalso.ultima = {}
    monkeypatch.setattr(health.httpx, "Client", ClienteFalso)
    return ClienteFalso


# =====================================================================
#  fijar_destino(): resolver una vez y validar
# =====================================================================

def test_la_url_de_la_peticion_lleva_la_ip(monkeypatch):
    monkeypatch.setattr(health, "resolver_dominio", lambda host: ["93.184.216.34"])
    ips, plantilla, cabeceras, extensiones = fijar_destino("https://ejemplo.com/ruta")

    assert ips == ["93.184.216.34"]
    assert plantilla.format(ip="93.184.216.34") == "https://93.184.216.34:443/ruta"
    # El servidor necesita el nombre para saber que sitio le estas pidiendo.
    assert cabeceras["Host"] == "ejemplo.com"
    # Y el certificado se verifica contra el NOMBRE, no contra la IP.
    assert extensiones["sni_hostname"] == "ejemplo.com"


def test_una_ip_interna_corta_antes_de_conectar(monkeypatch):
    monkeypatch.setattr(health, "resolver_dominio", lambda host: ["127.0.0.1"])
    with pytest.raises(DestinoNoPermitido):
        fijar_destino("https://parece-inocente.com/")


def test_basta_una_ip_interna_entre_varias(monkeypatch):
    """Un dominio puede apuntar a varias IPs. Una mala las ensucia todas."""
    monkeypatch.setattr(health, "resolver_dominio",
                        lambda host: ["93.184.216.34", "10.0.0.5"])
    with pytest.raises(DestinoNoPermitido):
        fijar_destino("https://mitad-y-mitad.com/")


def test_dominio_que_no_resuelve(monkeypatch):
    import socket

    def no_resuelve(_host):
        raise socket.gaierror("no existe")

    monkeypatch.setattr(health, "resolver_dominio", no_resuelve)
    with pytest.raises(DestinoNoResoluble):
        fijar_destino("https://no-existe-12345.com/")


def test_puerto_no_estandar_va_en_el_host(monkeypatch):
    monkeypatch.setattr(health, "resolver_dominio", lambda host: ["93.184.216.34"])
    _ips, _plantilla, cabeceras, _ext = fijar_destino("http://ejemplo.com:8080/x")
    assert cabeceras["Host"] == "ejemplo.com:8080"


def test_ipv6_va_entre_corchetes(monkeypatch):
    monkeypatch.setattr(health, "resolver_dominio",
                        lambda host: ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"])
    _ips, plantilla, _cab, _ext = fijar_destino("https://ejemplo.com/")
    destino = plantilla.format(ip="[2606:2800:21f:cb07:6820:80da:af6b:8b2c]")
    assert destino.startswith("https://[2606:")


def test_ipv4_se_intenta_antes_que_ipv6():
    """Muchas maquinas tienen IPv6 configurado pero sin salida real."""
    mezcla = ["2606:2800::1", "93.184.216.34", "2606:2800::2", "1.1.1.1"]
    assert ordenar_ips(mezcla) == ["93.184.216.34", "1.1.1.1",
                                   "2606:2800::1", "2606:2800::2"]


# =====================================================================
#  EL ATAQUE: el DNS cambia de respuesta entre una consulta y la otra
# =====================================================================

def test_el_dns_se_consulta_una_sola_vez(monkeypatch, cliente_falso):
    """Simula un DNS malicioso: publica la primera vez, interna la segunda.

    Con el diseño viejo, httpx resolvia por su cuenta al conectarse y se
    habria llevado la SEGUNDA respuesta: 127.0.0.1.

    Con el arreglo solo hay UNA resolucion, y la peticion sale hacia la
    IP ya validada. La segunda respuesta del atacante nunca se usa porque
    nunca se le vuelve a preguntar.
    """
    consultas = []

    def dns_malicioso(host):
        consultas.append(host)
        return ["93.184.216.34"] if len(consultas) == 1 else ["127.0.0.1"]

    monkeypatch.setattr(health, "resolver_dominio", dns_malicioso)
    health.revisar_salud("https://parece-inocente.com/")

    assert len(consultas) == 1, "se resolvio el DNS mas de una vez"
    assert "93.184.216.34" in cliente_falso.ultima["destino"]
    assert "127.0.0.1" not in cliente_falso.ultima["destino"]
    assert "parece-inocente.com" not in cliente_falso.ultima["destino"]


def test_la_peticion_nunca_descarga_el_cuerpo(monkeypatch, cliente_falso):
    """ClienteFalso solo implementa stream(). Si el codigo usara get() o
    head(), esta prueba reventaria con AttributeError."""
    monkeypatch.setattr(health, "resolver_dominio", lambda host: ["93.184.216.34"])
    salud = health.revisar_salud("https://ejemplo.com/")
    assert salud.codigo == 200
    assert cliente_falso.ultima["metodo"] == "HEAD"


def test_rebinding_en_medio_de_una_cadena(monkeypatch):
    """La version de la cadena completa: el ultimo salto apunta adentro."""
    import checker.validator as validator

    def dns(host):
        return ["127.0.0.1"] if host == "interno.com" else ["93.184.216.34"]

    # Hay que parchar los DOS: seguir_cadena valida cada salto con
    # validar_url(), que usa el resolver del validador, no el de health.
    monkeypatch.setattr(health, "resolver_dominio", dns)
    monkeypatch.setattr(validator, "resolver_dominio", dns)

    respuestas = {
        "https://inicio.com/": health.Salud(
            categoria="REDIRECCION", codigo=301, razon="simulado",
            destino="https://interno.com/admin", metodo="HEAD"),
    }
    monkeypatch.setattr(
        health, "revisar_salud",
        lambda url, tiempo_limite=5.0: respuestas.get(
            url, health.Salud(categoria="OK", codigo=200, razon="simulado")))

    cadena = seguir_cadena("https://inicio.com/")
    assert cadena.problema is not None
    assert "bloquead" in cadena.problema


# =====================================================================
#  Tope de tiempo de la cadena completa
# =====================================================================

def test_la_cadena_tiene_tope_de_tiempo(monkeypatch):
    """Sin esto, 10 saltos de 5 segundos son 50 segundos colgados."""
    import time

    paso = {"n": 0}

    def lenta(_url, tiempo_limite=5.0):
        time.sleep(0.15)
        # Cada destino tiene que ser distinto: si siempre mandara al mismo
        # sitio, saltaria el detector de bucles antes que el del tiempo,
        # y estariamos probando otra cosa.
        paso["n"] += 1
        return health.Salud(categoria="REDIRECCION", codigo=301,
                            razon="simulado",
                            destino=f"https://example.com/paso{paso['n']}",
                            metodo="HEAD")

    monkeypatch.setattr(health, "revisar_salud", lenta)
    cadena = seguir_cadena("https://example.com/uno", tiempo_total=0.3)

    assert cadena.problema is not None
    assert "tardo mas" in cadena.problema


# =====================================================================
#  Con red: el arreglo NO debilita el HTTPS
# =====================================================================

@pytest.mark.red
def test_un_sitio_normal_sigue_funcionando():
    salud = health.revisar_salud("https://example.com")
    assert salud.categoria == "OK"


@pytest.mark.red
@pytest.mark.parametrize("url", [
    "https://expired.badssl.com/",
    "https://self-signed.badssl.com/",
    "https://wrong.host.badssl.com/",
])
def test_los_certificados_malos_se_siguen_rechazando(url):
    """Lo mas importante de este arreglo: fijar la IP NO debe romper la
    verificacion del certificado. Si estas tres dejaran de dar error,
    habriamos cambiado un agujero por otro peor."""
    assert health.revisar_salud(url).tipo_error == "ssl"
