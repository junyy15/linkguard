"""
API HTTP de la herramienta.

Para levantarla:

    .\\api.bat
    (o: python -m uvicorn api:app --host 127.0.0.1 --port 8000)

Luego abre http://127.0.0.1:8000/docs y tienes la documentacion
interactiva, generada sola por FastAPI a partir del codigo.

=====================================================================
 LO QUE CAMBIA AL EXPONER ESTO POR HTTP
=====================================================================

En la terminal, el unico que usa la herramienta eres tu. Por HTTP,
cualquiera que alcance el puerto la usa. Eso trae cuatro problemas
que en el CLI no existen:

 1. TU CUOTA ES DE QUIEN LLAME.
    Cada peticion gasta TUS 500 consultas diarias de VirusTotal. Por eso
    hay un limitador por IP. Sin el, un solo script te deja sin cuota
    en un minuto.

 2. TU SERVIDOR SE VUELVE UN PROXY.
    Alguien te manda una URL y TU servidor la visita. Esa es justo la
    definicion de SSRF. El guardia del Modulo 0 pasa de ser buena
    practica a ser lo unico que te protege.

 3. LOS ERRORES HABLAN DE MAS.
    Un error sin controlar puede devolver rutas de tu disco, nombres de
    archivos o pedazos de configuracion. Aqui se responde un mensaje
    generico y el detalle se queda en tu consola.

 4. ESCUCHAR EN 0.0.0.0 TE EXPONE A TODA LA RED.
    Por eso el valor por defecto es 127.0.0.1: solo tu computadora.
"""

import logging
import time
from collections import defaultdict
from threading import Lock

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from checker.reporte import VERSION_FORMATO, a_diccionario
from checker.scanner import analizar
from checker.scoring import evaluar

registro = logging.getLogger("url-checker")

# Cuantas peticiones aceptamos de una misma IP por minuto.
# Es deliberadamente bajo: cada una puede costar una consulta a VirusTotal,
# y solo tenemos 500 al dia para todo el mundo.
LIMITE_POR_IP = 10
VENTANA = 60.0

# Largo maximo de la URL que aceptamos. Sin esto, alguien puede mandar
# megabytes en un campo de texto y hacerte trabajar de gratis.
LARGO_MAXIMO_URL = 2048

app = FastAPI(
    title="URL Health & Safety Checker",
    description="Revisa si un enlace esta roto, es invalido o fue reportado "
                "como peligroso. Proyecto educativo, uso no comercial.",
    version=f"1.0 (formato {VERSION_FORMATO})",
)


# =====================================================================
#  Limitador por IP
# =====================================================================

_peticiones: dict[str, list[float]] = defaultdict(list)
_candado = Lock()


def permitir(ip: str) -> bool:
    """¿Esta IP puede hacer otra peticion ahora?

    Misma idea de ventana deslizante que el limitador de VirusTotal, pero
    aqui NO esperamos: se contesta 429 de inmediato. Hacer esperar a quien
    abusa solo te llena el servidor de conexiones abiertas.
    """
    ahora = time.monotonic()
    with _candado:
        recientes = [t for t in _peticiones[ip] if ahora - t < VENTANA]
        _peticiones[ip] = recientes
        if len(recientes) >= LIMITE_POR_IP:
            return False
        recientes.append(ahora)
        return True


# =====================================================================
#  Forma de la peticion y de la respuesta
# =====================================================================

class Peticion(BaseModel):
    """Lo que hay que mandar. Pydantic valida esto ANTES de que llegue
    a nuestro codigo: si falta la url o no es texto, FastAPI responde
    solo, con un 422 y un mensaje claro."""

    url: str = Field(
        ...,
        min_length=1,
        max_length=LARGO_MAXIMO_URL,
        description="La URL a revisar",
        examples=["https://example.com"],
    )
    amenazas: bool = Field(
        True,
        description="Consultar Google Safe Browsing y VirusTotal. "
                    "Ponlo en false si solo quieres salud y redirecciones "
                    "(mucho mas rapido y no gasta cuota).",
    )


# =====================================================================
#  Rutas
# =====================================================================

@app.get("/", summary="Estado del servicio")
def raiz() -> dict:
    """Sirve para comprobar que el servicio esta vivo."""
    return {
        "servicio": "URL Health & Safety Checker",
        "version_formato": VERSION_FORMATO,
        "documentacion": "/docs",
        "uso": "POST /check con {\"url\": \"https://...\"}",
    }


@app.post("/check", summary="Revisa una URL")
def revisar(peticion: Peticion, request: Request) -> dict:
    """Analiza una URL y devuelve el veredicto con sus razones.

    El JSON que sale es EXACTAMENTE el mismo de `check.py --json`:
    los dos usan checker/reporte.py. Una sola forma publica, un solo
    contrato que mantener.
    """
    ip = request.client.host if request.client else "desconocida"

    if not permitir(ip):
        # 429 = Too Many Requests. Retry-After le dice al cliente
        # cuantos segundos esperar, en vez de dejarlo adivinar.
        raise HTTPException(
            status_code=429,
            detail=f"Demasiadas peticiones. Maximo {LIMITE_POR_IP} por minuto.",
            headers={"Retry-After": str(int(VENTANA))},
        )

    try:
        analisis = analizar(peticion.url, consultar_amenazas=peticion.amenazas)
        veredicto = evaluar(analisis)
    except Exception as error:
        # El detalle va al registro del servidor, NO a la respuesta.
        # Un traceback en la respuesta le regala a un atacante las rutas
        # de tu disco y la estructura de tu proyecto.
        registro.exception("Fallo analizando %s", peticion.url)
        raise HTTPException(
            status_code=500,
            detail="No se pudo completar el analisis.",
        ) from error

    return a_diccionario(analisis, veredicto)


# Nota sobre 'def' y no 'async def':
#
# Nuestro codigo es BLOQUEANTE: httpx sincrono, DNS, sleep del limitador.
# Si el endpoint fuera 'async def', todo eso correria en el unico hilo
# que atiende a todos, y una sola peticion lenta congelaria el servidor
# entero. Al declararlo como 'def' normal, FastAPI lo manda a un pool de
# hilos y las demas peticiones siguen atendiendose.
#
# Es un error comun: poner async porque "suena mas rapido" y terminar con
# un servidor mas lento que uno normal.
