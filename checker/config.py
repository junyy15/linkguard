"""
Carga de llaves secretas.

Las llaves NO viven en el proyecto: viven en

    C:\\Users\\<tu usuario>\\.secrets\\url-checker.env

fuera de OneDrive y fuera de cualquier carpeta que pueda acabar en GitHub.
Si ese archivo no existe, como plan B se lee el .env del proyecto, pero
la idea es no usarlo.

Regla de oro: este modulo NUNCA imprime el valor de una llave. Ni en los
mensajes de error, ni al revisar el estado. Una llave que aparece en una
pantalla compartida, en una captura o en un log, ya esta comprometida.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# Path.home() es tu carpeta de usuario, sin importar como se llame.
RUTA_SECRETA = Path.home() / ".secrets" / "url-checker.env"

# Nombre de la variable que enciende el MODO PUBLICO.
#
# En tu computadora no existe, asi que la herramienta funciona completa.
# En un servidor (Streamlit Cloud) se pone en "1", y entonces:
#   - no se consulta VirusTotal (su cuota es de 500 al dia y la gastarian
#     desconocidos en una tarde)
#   - se esconde el acortador (sus enlaces los resuelve api.py, que en el
#     servidor no existe: darian enlaces rotos)
#   - no se muestra el estado de las llaves
VARIABLE_PUBLICO = "LINKGUARD_PUBLICO"

# El .env del proyecto, solo como plan B.
RUTA_PROYECTO = Path(__file__).resolve().parent.parent / ".env"

# Nombres de las llaves que usa el proyecto.
LLAVES = {
    "GOOGLE_SAFE_BROWSING_API_KEY": "Google Safe Browsing",
    "VIRUSTOTAL_API_KEY": "VirusTotal",
}

_ya_cargado = False


def cargar() -> None:
    """Lee los archivos .env y mete las llaves en el entorno del programa.

    Se puede llamar muchas veces sin problema: solo trabaja la primera vez.
    """
    global _ya_cargado
    if _ya_cargado:
        return

    # El archivo secreto manda. override=False significa "no pises lo que ya exista".
    if RUTA_SECRETA.exists():
        load_dotenv(RUTA_SECRETA, override=False)
    if RUTA_PROYECTO.exists():
        load_dotenv(RUTA_PROYECTO, override=False)

    _ya_cargado = True


def _de_streamlit(nombre: str) -> str | None:
    """Busca la llave en los secretos de Streamlit Cloud.

    Cuando la herramienta corre en un servidor no hay archivos .env: las
    llaves se escriben en el panel de Streamlit y llegan por st.secrets.

    El import va aqui dentro a proposito. Si estuviera arriba, check.py y
    api.py cargarian Streamlit entero sin necesitarlo para nada.
    """
    try:
        import streamlit as st

        return str(st.secrets[nombre]).strip() or None
    except Exception:
        # Si no hay Streamlit, o no hay secretos, o no esta esa llave:
        # no es un error, simplemente no es por ahi.
        return None


def obtener(nombre: str) -> str | None:
    """Devuelve el valor de una llave, o None si no esta configurada.

    Busca en este orden:
      1. El entorno (incluye lo que cargaron los archivos .env)
      2. Los secretos de Streamlit Cloud

    Una llave vacia cuenta como no configurada: asi el archivo de plantilla
    con 'VIRUSTOTAL_API_KEY=' no se confunde con una llave de verdad.
    """
    cargar()
    valor = os.environ.get(nombre, "").strip()
    return valor or _de_streamlit(nombre)


def es_publico() -> bool:
    """¿Estamos corriendo como servicio publico?"""
    cargar()
    valor = os.environ.get(VARIABLE_PUBLICO, "").strip().lower()
    if valor in ("1", "true", "si", "yes"):
        return True
    return (_de_streamlit(VARIABLE_PUBLICO) or "").lower() in ("1", "true", "si", "yes")


def estado() -> dict[str, tuple[bool, str]]:
    """Dice que llaves estan configuradas SIN revelar su contenido."""
    cargar()
    resultado = {}
    for nombre, descripcion in LLAVES.items():
        valor = obtener(nombre)
        if valor:
            # Solo el largo. Nunca el valor, ni un pedazo.
            resultado[nombre] = (True, f"configurada ({len(valor)} caracteres)")
        else:
            resultado[nombre] = (False, "NO configurada")
    return resultado


# Para revisar como va todo:  python -m checker.config
if __name__ == "__main__":
    print()
    print("Archivo secreto:", RUTA_SECRETA)
    print("  existe:", "si" if RUTA_SECRETA.exists() else "NO - hay que crearlo")
    print()
    print("Llaves:")
    for nombre, (listo, mensaje) in estado().items():
        simbolo = "[OK]" if listo else "[  ]"
        print(f"  {simbolo} {LLAVES[nombre]:<22} {mensaje}")
    print()

    faltan = [n for n, (listo, _m) in estado().items() if not listo]
    if faltan:
        print("Para completar, abre este archivo y pega tus llaves:")
        print(f"  {RUTA_SECRETA}")
        print()
    else:
        print("Todo listo para la Semana 2.")
        print()
