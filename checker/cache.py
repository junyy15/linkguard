"""
Cache en disco para las respuestas de las APIs.

Para que existe: la cuota gratuita de VirusTotal es de 4 peticiones por
minuto y 500 al dia. Sin cache, correr las pruebas tres veces seguidas ya
gasta una parte seria del dia. Con cache, la segunda vez es instantanea y
no cuesta nada.

Se guarda en .cache/consultas.json, que esta en el .gitignore.

LA DECISION IMPORTANTE: cuanto tiempo vale una respuesta guardada.

No es simetrica, y vale la pena entender por que:

  - Una respuesta LIMPIA caduca rapido (1 hora). Un sitio sano hoy puede
    estar infectado en la tarde. Guardar "limpio" mucho tiempo es peligroso:
    te haria decir "seguro" de algo que ya dejo de serlo.

  - Una respuesta REPORTADA dura mas (24 horas). Un sitio marcado como
    malicioso rara vez se limpia en horas. Y si nos equivocamos, el costo
    es una falsa alarma: molesto, pero no peligroso.

La regla general: cuando dudes, que caduque antes el dato que, si se
equivoca, le dice al usuario que algo es seguro.
"""

import json
import threading
import time
from pathlib import Path
from typing import Any

CARPETA = Path(__file__).resolve().parent.parent / ".cache"
ARCHIVO = CARPETA / "consultas.json"

# Desde el Dia 4 hay hilos corriendo en paralelo. Si dos escriben el archivo
# al mismo tiempo, el JSON queda partido a la mitad y el cache se corrompe.
# El candado garantiza que solo uno entre a la vez.
_candado = threading.Lock()

# Segundos que vale cada tipo de respuesta.
VIGENCIA_LIMPIO = 60 * 60           # 1 hora
VIGENCIA_REPORTADO = 60 * 60 * 24   # 24 horas


def _cargar() -> dict[str, Any]:
    """Lee el archivo del cache. Si no existe o esta corrupto, empieza vacio."""
    if not ARCHIVO.exists():
        return {}
    try:
        return json.loads(ARCHIVO.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        # Un cache corrupto no debe tumbar el programa: se ignora y ya.
        return {}


def _guardar_todo(datos: dict[str, Any]) -> None:
    CARPETA.mkdir(exist_ok=True)
    ARCHIVO.write_text(json.dumps(datos, indent=2), encoding="utf-8")


def leer(clave: str) -> dict[str, Any] | None:
    """Devuelve lo guardado para esa clave, o None si no hay o ya caduco."""
    with _candado:
        datos = _cargar()

    entrada = datos.get(clave)
    if not entrada:
        return None

    edad = time.time() - entrada.get("guardado_en", 0)
    if edad > entrada.get("vigencia", 0):
        return None  # caduco

    return entrada.get("valor")


def guardar(clave: str, valor: dict[str, Any], limpio: bool) -> None:
    """Guarda una respuesta. 'limpio' decide cuanto tiempo va a durar."""
    # Leer y escribir tiene que ser UNA sola operacion indivisible. Si entre
    # la lectura y la escritura se cuela otro hilo, su cambio se pierde.
    with _candado:
        datos = _cargar()
        datos[clave] = {
            "valor": valor,
            "guardado_en": time.time(),
            "vigencia": VIGENCIA_LIMPIO if limpio else VIGENCIA_REPORTADO,
        }
        _guardar_todo(datos)


def limpiar() -> int:
    """Borra todo el cache. Devuelve cuantas entradas habia."""
    datos = _cargar()
    cuantas = len(datos)
    if ARCHIVO.exists():
        ARCHIVO.unlink()
    return cuantas


def estado() -> tuple[int, int]:
    """Devuelve (entradas vigentes, entradas caducadas)."""
    datos = _cargar()
    ahora = time.time()
    vigentes = caducadas = 0
    for entrada in datos.values():
        edad = ahora - entrada.get("guardado_en", 0)
        if edad > entrada.get("vigencia", 0):
            caducadas += 1
        else:
            vigentes += 1
    return vigentes, caducadas


# Para revisar el cache:  python -m checker.cache [limpiar]
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "limpiar":
        print(f"\nBorradas {limpiar()} entradas del cache.\n")
    else:
        vigentes, caducadas = estado()
        print(f"\nArchivo: {ARCHIVO}")
        print(f"  vigentes:  {vigentes}")
        print(f"  caducadas: {caducadas}")
        print("\nPara borrarlo todo:  python -m checker.cache limpiar\n")
