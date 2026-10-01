"""
El coordinador: junta los tres modulos en un solo analisis.

Antes esta logica vivia dentro de check.py, mezclada con los print().
Separarla tiene tres ventajas:

  1. La Semana 3 (puntuacion) recibe un objeto Analisis y decide el veredicto,
     sin tener que volver a consultar nada.
  2. La Semana 4 (interfaz web) usa exactamente esta misma funcion.
  3. Se puede probar sin leer lo que se imprime en pantalla.

Regla vieja: una funcion que ademas de calcular imprime, es una funcion que
solo sirve para un lugar.
"""

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from checker.health import Cadena, seguir_cadena
from checker.threats import (
    ResultadoAmenazas,
    consultar_safe_browsing,
    consultar_virustotal,
)
from checker.validator import Validacion, validar_url


@dataclass
class Analisis:
    """Todo lo que sabemos de una URL, en un solo objeto."""

    entrada: str
    validacion: Validacion
    cadena: Cadena | None = None
    google: ResultadoAmenazas | None = None
    virustotal: ResultadoAmenazas | None = None
    tiempo_ms: int = 0

    @property
    def paso_validacion(self) -> bool:
        return self.validacion.ok

    @property
    def url_final(self) -> str:
        return self.cadena.url_final if self.cadena else ""

    @property
    def señales(self) -> list[str]:
        """Pistas que la Semana 3 va a convertir en puntos del veredicto."""
        if not self.cadena:
            return []
        pistas = []
        if self.cadena.cambia_de_dominio:
            pistas.append("Termina en un dominio distinto al que empezo")
        if self.cadena.baja_seguridad:
            pistas.append("En algun salto pasa de https a http (sin cifrar)")
        if self.cadena.num_saltos > 3:
            pistas.append(f"Cadena larga ({self.cadena.num_saltos} redirecciones)")
        if self.cadena.problema:
            pistas.append(self.cadena.problema)
        return pistas


def analizar(entrada: str, consultar_amenazas: bool = True) -> Analisis:
    """Analiza una URL de principio a fin.

    Orden de las cosas:
      1. Validar (rapido, sin red salvo el DNS). Si falla, aqui se acaba.
      2. Seguir la cadena de redirecciones.
      3. Preguntar a las dos bases de amenazas EN PARALELO.

    Los pasos 1 y 2 tienen que ir en orden: no podemos preguntar por el
    destino final antes de saber cual es. Pero las dos consultas del paso 3
    son independientes entre si, y ahi si se puede ganar tiempo.
    """
    inicio = time.perf_counter()

    validacion = validar_url(entrada)
    if not validacion.ok:
        return Analisis(
            entrada=entrada,
            validacion=validacion,
            tiempo_ms=int((time.perf_counter() - inicio) * 1000),
        )

    cadena = seguir_cadena(validacion.url)

    google = virustotal = None
    if consultar_amenazas:
        # Dos hilos, dos peticiones al mismo tiempo. No usamos asyncio
        # porque para dos llamadas no compensa reescribir todo el proyecto.
        with ThreadPoolExecutor(max_workers=2) as pool:
            # A Google le preguntamos por la URL de entrada Y por la final.
            tarea_google = pool.submit(
                consultar_safe_browsing, [validacion.url, cadena.url_final])
            # A VirusTotal solo por la final: cada peticion cuesta cuota.
            tarea_vt = pool.submit(consultar_virustotal, cadena.url_final)

            # .result() espera a que termine y devuelve lo que salio.
            # Si la funcion lanzo una excepcion, aqui vuelve a lanzarse.
            google = tarea_google.result()
            virustotal = tarea_vt.result()

    return Analisis(
        entrada=entrada,
        validacion=validacion,
        cadena=cadena,
        google=google,
        virustotal=virustotal,
        tiempo_ms=int((time.perf_counter() - inicio) * 1000),
    )


# Para probar este archivo solo:  python -m checker.scanner <url>
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Uso: python -m checker.scanner <url>")
        sys.exit(1)

    resultado = analizar(sys.argv[1])
    print(f"\nEntrada: {resultado.entrada}")
    print(f"Valida: {resultado.validacion.ok}")
    if resultado.cadena:
        print(f"Destino: {resultado.url_final} ({resultado.cadena.num_saltos} saltos)")
    if resultado.google:
        print(f"Google: {resultado.google.resumen}")
    if resultado.virustotal:
        print(f"VirusTotal: {resultado.virustotal.resumen}")
    print(f"Tardo: {resultado.tiempo_ms} ms\n")
