"""
La identidad de LinkGuard, en un solo lugar.

Si alguna vez quieres cambiar el nombre, tu credito o un color, se cambia
AQUI y se actualiza en todas partes: la pagina web, la terminal y la API.

Tener esto en un archivo aparte no es capricho. Cuando el nombre esta
copiado en cinco archivos, cambiarlo significa encontrar los cinco, y
siempre se olvida uno.
"""

NOMBRE = "LinkGuard"
EMOJI = "🛡️"
LEMA = "Revisa si un enlace es seguro antes de abrirlo"

# Quien lo hizo. Cambialo si quieres que diga otra cosa.
AUTOR = "Pierre Junior"
ANIO = 2026

VERSION = "1.0"

# Una linea para el pie de pagina.
CREDITO = f"{NOMBRE} · Hecho por {AUTOR} · {ANIO}"

DESCRIPCION_LARGA = (
    "Revisa enlaces antes de abrirlos o compartirlos. Comprueba si el "
    "enlace funciona, a donde lleva de verdad, y si fue reportado como "
    "peligroso por Google o por los antivirus de VirusTotal."
)
