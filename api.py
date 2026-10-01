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
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field

from checker import acortador
from checker.reporte import VERSION_FORMATO, a_diccionario
from checker.scanner import analizar
from checker.scoring import SEGURO, evaluar

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


# =====================================================================
#  Acortador
# =====================================================================

class PeticionAcortar(BaseModel):
    url: str = Field(..., min_length=1, max_length=LARGO_MAXIMO_URL,
                     examples=["https://example.com"])


@app.post("/acortar", summary="Acorta una URL, si esta limpia")
def crear_corto(peticion: PeticionAcortar, request: Request) -> dict:
    """Analiza la URL y, SOLO si sale segura, crea un enlace corto.

    La condicion no se revisa aqui sino dentro de acortador.acortar():
    asi no se puede saltar llamando desde otro lado.
    """
    ip = request.client.host if request.client else "desconocida"
    if not permitir(ip):
        raise HTTPException(429, f"Maximo {LIMITE_POR_IP} peticiones por minuto.",
                            headers={"Retry-After": str(int(VENTANA))})

    try:
        analisis = analizar(peticion.url)
        veredicto = evaluar(analisis)
    except Exception as error:
        registro.exception("Fallo analizando %s", peticion.url)
        raise HTTPException(500, "No se pudo completar el analisis.") from error

    # Se acorta la URL FINAL de la cadena, no la que escribieron: es la
    # que de verdad se reviso, y de paso le quita al enlace corto una
    # capa de redireccion.
    destino = analisis.url_final or peticion.url

    try:
        enlace = acortador.acortar(destino, veredicto.seguridad)
    except acortador.NoSePuedeAcortar as error:
        # 409 Conflict: la peticion esta bien formada, pero el estado del
        # recurso no permite la operacion. No es un 400 (tu peticion esta
        # mal) ni un 403 (no tienes permiso).
        raise HTTPException(
            status_code=409,
            detail={
                "motivo": str(error),
                "veredicto": veredicto.seguridad,
                "razones": [s.texto for s in veredicto.señales],
            },
        ) from error

    base = str(request.base_url).rstrip("/")
    return {
        "codigo": enlace.codigo,
        "corto": f"{base}/r/{enlace.codigo}",
        "destino": enlace.url,
        "veredicto": enlace.veredicto,
        "verificado_en": enlace.verificado,
    }


def _pagina_de_alerta(enlace, veredicto) -> HTMLResponse:
    """Pagina que se muestra cuando un enlace ya acortado dejo de ser seguro.

    No se redirige. El punto de todo el proyecto es no mandar a nadie a
    un sitio que acaba de ensuciarse.
    """
    razones = "".join(f"<li>{s.texto} <small>({s.fuente})</small></li>"
                      for s in veredicto.señales)
    html = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<title>Enlace bloqueado</title>
<style>
 body {{ font-family: system-ui, sans-serif; max-width: 38rem; margin: 4rem auto;
        padding: 0 1rem; line-height: 1.6; }}
 .caja {{ border: 2px solid #c00; border-radius: .5rem; padding: 1.5rem; }}
 h1 {{ color: #c00; margin-top: 0; }}
 code {{ background: #f4f4f4; padding: .15rem .35rem; border-radius: .2rem;
        word-break: break-all; }}
</style></head>
<body><div class="caja">
<h1>Enlace bloqueado</h1>
<p>Este enlace corto estaba limpio cuando se creo, pero al revisarlo
   ahora el resultado cambio a <strong>{veredicto.seguridad}</strong>.</p>
<p>Por eso no se te redirige.</p>
<ul>{razones}</ul>
<p>Destino: <code>{enlace.url}</code></p>
<p><small>Revisa el enlace tu mismo antes de abrirlo. Esta herramienta
   no afirma con certeza que el sitio sea peligroso: reporta lo que
   encontro en fuentes publicas.</small></p>
</div></body></html>"""
    return HTMLResponse(content=html, status_code=403)


@app.get("/r/{codigo}", summary="Abre un enlace corto")
def abrir_corto(codigo: str):
    """Redirige a la URL guardada, despues de volver a revisarla.

    Lo importante esta en la segunda revision: un sitio limpio hoy puede
    estar comprometido mañana. Si solo revisaramos al crear el enlace,
    un atacante podria acortar su sitio limpio, esperar, e infectarlo
    despues con el enlace corto ya repartido.

    Y fijate de donde sale el destino: de NUESTRO almacen, nunca de un
    parametro de la URL. Un acortador que acepta '?url=...' es un
    redirector abierto, y sirve para prestarle tu reputacion a otro.
    """
    enlace = acortador.obtener(codigo)
    if enlace is None:
        raise HTTPException(404, "Ese enlace corto no existe.")

    if enlace.necesita_revision:
        try:
            analisis = analizar(enlace.url)
            veredicto = evaluar(analisis)
        except Exception as error:
            registro.exception("Fallo re-revisando %s", enlace.url)
            raise HTTPException(500, "No se pudo revisar el destino.") from error

        acortador.actualizar_verificacion(codigo, veredicto.seguridad)
        if veredicto.seguridad != SEGURO:
            return _pagina_de_alerta(enlace, veredicto)

    acortador.registrar_uso(codigo)
    # 307 y no 301: el 301 es permanente y los navegadores lo guardan.
    # Si lo usaramos, la proxima vez ni siquiera pasarian por aqui, y la
    # re-revision dejaria de ocurrir. Un acortador que revisa NO puede
    # usar redirecciones permanentes.
    return RedirectResponse(enlace.url, status_code=307)


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
