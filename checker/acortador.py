"""
Acortador de enlaces, con una condicion: solo acorta lo que esta limpio.

Esta es la idea con la que empezo el proyecto: revisar un enlace ANTES
de generar un enlace corto a partir de el.

=====================================================================
 POR QUE UN ACORTADOR ES DELICADO
=====================================================================

Un acortador es, por definicion, un redirector: alguien hace clic en tu
dominio y acaba en otro lado. Eso es exactamente lo que tu herramienta
marca como sospechoso en los enlaces ajenos. Asi que hay que construirlo
con las mismas reglas que le exigimos a los demas:

 1. SOLO SE ACORTA LO QUE SALIO LIMPIO.
    Ni "sospechoso", ni siquiera "sin confirmar". Si no se pudo
    comprobar, no se acorta: un enlace corto es una recomendacion
    implicita, y no se recomienda lo que no se sabe.

 2. SE VUELVE A REVISAR AL ABRIRLO.
    Un sitio limpio hoy puede estar comprometido mañana. Si solo
    revisaramos al crear el enlace, estariamos firmando un cheque en
    blanco: el atacante acorta su sitio limpio, espera, y lo infecta
    despues. Por eso cada enlace guarda cuando se verifico, y al
    abrirlo se revisa de nuevo si ya paso mucho tiempo.

 3. NUNCA REDIRIGE A ALGO QUE NO ESTE GUARDADO.
    El destino sale SIEMPRE de nuestro almacen, nunca de un parametro
    de la URL. Un acortador que acepta '?url=...' es un redirector
    abierto, y sirve para que un atacante preste tu reputacion a su
    sitio: el enlace que la victima ve es el tuyo.

 4. LOS CODIGOS NO SE PUEDEN ADIVINAR.
    Si fueran 1, 2, 3... cualquiera podria recorrer todos los enlaces
    acortados y ver a donde apuntan. Se generan al azar con `secrets`,
    que es el modulo pensado para cosas que no deben ser predecibles
    (`random` no sirve para esto: su secuencia se puede reconstruir).
"""

import json
import secrets
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

CARPETA = Path(__file__).resolve().parent.parent / ".enlaces"
ARCHIVO = CARPETA / "enlaces.json"

# Alfabeto sin caracteres que se confunden al leer o dictar:
# nada de 0/O, 1/l/I. Si alguien copia el enlace a mano, importa.
ALFABETO = "23456789abcdefghijkmnpqrstuvwxyz"
LARGO_CODIGO = 7

# Cuanto vale una verificacion antes de volver a revisar. Es la misma
# idea (y el mismo criterio) que la vigencia del cache de "limpio".
VIGENCIA_VERIFICACION = 60 * 60  # 1 hora

_candado = threading.Lock()


class NoSePuedeAcortar(Exception):
    """El enlace no cumple la condicion para ser acortado."""


@dataclass
class Enlace:
    codigo: str
    url: str
    creado: float
    verificado: float
    veredicto: str
    usos: int = 0

    @property
    def necesita_revision(self) -> bool:
        return time.time() - self.verificado > VIGENCIA_VERIFICACION


# =====================================================================
#  Almacen
# =====================================================================

def _cargar() -> dict[str, dict]:
    if not ARCHIVO.exists():
        return {}
    try:
        return json.loads(ARCHIVO.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {}


def _guardar_todo(datos: dict[str, dict]) -> None:
    CARPETA.mkdir(exist_ok=True)
    ARCHIVO.write_text(json.dumps(datos, indent=2, ensure_ascii=False),
                       encoding="utf-8")


def generar_codigo() -> str:
    """Un codigo corto e impredecible.

    secrets.choice usa el generador del sistema operativo, el mismo que
    se usa para contraseñas y llaves. random.choice NO sirve aqui: su
    secuencia se puede reconstruir viendo unos cuantos resultados.
    """
    return "".join(secrets.choice(ALFABETO) for _ in range(LARGO_CODIGO))


def obtener(codigo: str) -> Enlace | None:
    """Busca un enlace por su codigo."""
    with _candado:
        datos = _cargar()
    guardado = datos.get(codigo)
    return Enlace(**guardado) if guardado else None


def acortar(url: str, veredicto_seguridad: str,
            permitidos: set[str] | None = None) -> Enlace:
    """Crea un enlace corto, SI el veredicto lo permite.

    Lanza NoSePuedeAcortar en cualquier otro caso. Que la condicion viva
    aqui y no en la interfaz es a proposito: asi no se puede saltar
    llamando desde otro lado (la web, la API, un script).
    """
    if permitidos is None:
        from checker.scoring import SEGURO
        permitidos = {SEGURO}

    if veredicto_seguridad not in permitidos:
        raise NoSePuedeAcortar(
            f"Solo se acortan enlaces con veredicto {', '.join(sorted(permitidos))}. "
            f"Este salio como {veredicto_seguridad}."
        )

    ahora = time.time()

    with _candado:
        datos = _cargar()

        # Si ya se habia acortado esa misma URL, se reusa el codigo en vez
        # de llenar el almacen de duplicados.
        for codigo, guardado in datos.items():
            if guardado["url"] == url:
                guardado["verificado"] = ahora
                guardado["veredicto"] = veredicto_seguridad
                _guardar_todo(datos)
                return Enlace(**guardado)

        # Codigo nuevo, cuidando que no choque con uno existente.
        codigo = generar_codigo()
        while codigo in datos:
            codigo = generar_codigo()

        enlace = Enlace(codigo=codigo, url=url, creado=ahora,
                        verificado=ahora, veredicto=veredicto_seguridad)
        datos[codigo] = asdict(enlace)
        _guardar_todo(datos)
        return enlace


def registrar_uso(codigo: str) -> None:
    """Suma uno al contador de visitas."""
    with _candado:
        datos = _cargar()
        if codigo in datos:
            datos[codigo]["usos"] = datos[codigo].get("usos", 0) + 1
            _guardar_todo(datos)


def actualizar_verificacion(codigo: str, veredicto_seguridad: str) -> None:
    """Guarda el resultado de una revision posterior."""
    with _candado:
        datos = _cargar()
        if codigo in datos:
            datos[codigo]["verificado"] = time.time()
            datos[codigo]["veredicto"] = veredicto_seguridad
            _guardar_todo(datos)


def listar() -> list[Enlace]:
    """Todos los enlaces, del mas nuevo al mas viejo."""
    with _candado:
        datos = _cargar()
    enlaces = [Enlace(**g) for g in datos.values()]
    return sorted(enlaces, key=lambda e: e.creado, reverse=True)


def borrar(codigo: str) -> bool:
    with _candado:
        datos = _cargar()
        if codigo not in datos:
            return False
        del datos[codigo]
        _guardar_todo(datos)
        return True


# Para revisar los enlaces:  python -m checker.acortador
if __name__ == "__main__":
    enlaces = listar()
    if not enlaces:
        print("\nNo hay enlaces acortados todavia.\n")
    else:
        print(f"\n{len(enlaces)} enlaces:\n")
        for e in enlaces:
            edad = (time.time() - e.verificado) / 3600
            print(f"  /r/{e.codigo}  ->  {e.url}")
            print(f"      {e.veredicto} · verificado hace {edad:.1f} h · "
                  f"{e.usos} usos")
        print()
