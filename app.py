"""
Interfaz web con Streamlit.

Para levantarla:

    .\\web.bat
    (o: python -m streamlit run app.py)

Se abre sola en http://localhost:8501

=====================================================================
 COMO FUNCIONA STREAMLIT (el modelo mental)
=====================================================================

Streamlit NO tiene eventos ni callbacks. Cada vez que el usuario toca
algo -escribe, aprieta un boton, mueve un switch- tu script se vuelve a
ejecutar COMPLETO, de arriba a abajo, y Streamlit redibuja la pagina.

Eso tiene dos consecuencias practicas:

  1. Escribes el programa como un script normal, de corrido. No hay que
     aprender un modelo de componentes.

  2. Cualquier variable normal se PIERDE en cada interaccion. Para que
     algo sobreviva hay que guardarlo en st.session_state, que es lo
     unico que persiste entre re-ejecuciones.

Y lo importante: aqui NO hay nada de logica del proyecto. Esta pagina
solo llama a analizar() y evaluar(), las mismas funciones que usan
check.py y api.py. Si algun dia cambia el criterio, cambia en los tres
lugares a la vez porque hay un solo lugar.
"""

import streamlit as st

from checker import cache, config
from checker.scanner import analizar
from checker.scoring import (
    POSIBLEMENTE_PELIGROSO,
    RECHAZADA,
    SEGURO,
    SIN_CONFIRMAR,
    SOSPECHOSO,
    evaluar,
)

AVISO_GOOGLE = ("Advisory provided by Google — "
                "[Safe Browsing Advisory]"
                "(https://transparencyreport.google.com/safe-browsing/search)")
MAS_INFORMACION = ("Más información sobre phishing: "
                   "[antiphishing.org](https://www.antiphishing.org)")

# Como se muestra cada veredicto.
#   (emoji, titulo, que funcion de streamlit lo pinta)
PRESENTACION = {
    SEGURO:                 ("✅", "Seguro", st.success),
    SIN_CONFIRMAR:          ("❔", "Sin confirmar", st.info),
    SOSPECHOSO:             ("⚠️", "Sospechoso", st.warning),
    POSIBLEMENTE_PELIGROSO: ("⛔", "Posiblemente peligroso", st.error),
    RECHAZADA:              ("🚫", "Rechazada", st.error),
}

COLOR_SALUD = {
    "OK": "normal",
    "REDIRECCION": "normal",
    "BLOQUEADO": "off",
    "ROTO": "inverse",
    "ERROR": "inverse",
    "INVALIDA": "inverse",
}


st.set_page_config(
    page_title="URL Health & Safety Checker",
    page_icon="🔎",
    layout="centered",
)


# =====================================================================
#  Barra lateral
# =====================================================================

with st.sidebar:
    st.header("Opciones")

    consultar_amenazas = st.toggle(
        "Consultar bases de amenazas",
        value=True,
        help="Google Safe Browsing y VirusTotal. Si lo apagas es mucho más "
             "rápido y no gasta cuota, pero el veredicto nunca podrá ser "
             "'Seguro': sin preguntar, no se sabe.",
    )

    st.divider()
    st.caption("**Estado de las llaves**")
    for nombre, (listo, mensaje) in config.estado().items():
        etiqueta = config.LLAVES[nombre]
        st.caption(f"{'✅' if listo else '⬜'} {etiqueta} — {mensaje}")

    vigentes, caducadas = cache.estado()
    st.caption(f"**Caché:** {vigentes} vigentes, {caducadas} caducadas")
    if st.button("Vaciar caché", use_container_width=True):
        borradas = cache.limpiar()
        st.toast(f"Caché vaciado ({borradas} entradas)")

    st.divider()
    st.caption(
        "Proyecto educativo. Google Safe Browsing y la API pública de "
        "VirusTotal son gratuitas **solo para uso no comercial**."
    )


# =====================================================================
#  Cabecera
# =====================================================================

st.title("🔎 URL Health & Safety Checker")
st.caption(
    "Revisa si un enlace está roto, es inválido o fue reportado como "
    "peligroso, **antes** de abrirlo o acortarlo."
)

# st.form agrupa la entrada: el script no se re-ejecuta con cada letra
# que escribes, solo al enviar. Sin esto, cada tecla dispararia un
# analisis completo con sus peticiones a internet.
with st.form("formulario"):
    url = st.text_input(
        "Pega el enlace",
        placeholder="https://ejemplo.com",
        label_visibility="collapsed",
    )
    enviar = st.form_submit_button("Revisar enlace", type="primary",
                                   use_container_width=True)

if enviar and url.strip():
    with st.spinner("Analizando… (siguiendo redirecciones y consultando fuentes)"):
        analisis = analizar(url, consultar_amenazas=consultar_amenazas)
        st.session_state["analisis"] = analisis
        st.session_state["veredicto"] = evaluar(analisis)
elif enviar:
    st.warning("Escribe un enlace primero.")


# =====================================================================
#  Resultado
# =====================================================================

analisis = st.session_state.get("analisis")
veredicto = st.session_state.get("veredicto")

if analisis and veredicto:
    emoji, titulo, pintar = PRESENTACION.get(
        veredicto.seguridad, ("❔", veredicto.seguridad, st.info))

    pintar(f"### {emoji} {titulo}\n\n{veredicto.frase}")

    # --- Los dos ejes, lado a lado ---
    izquierda, derecha = st.columns(2)
    izquierda.metric("Seguridad", titulo)
    derecha.metric(
        "Salud del enlace", veredicto.salud,
        delta=None,
        help="OK = responde · ROTO = 404/500 · BLOQUEADO = no deja entrar a "
             "programas (no está roto) · ERROR = timeout o certificado malo",
    )

    # --- Las razones ---
    if veredicto.señales:
        st.subheader("Por qué")
        for señal in veredicto.señales:
            if señal.dura:
                icono = "🔴"
            elif señal.peso:
                icono = "🟠"
            else:
                icono = "⚪"
            st.markdown(f"{icono} **{señal.texto}**  \n"
                        f"<small>fuente: {señal.fuente}</small>",
                        unsafe_allow_html=True)

    if veredicto.cita_a_google:
        st.caption(AVISO_GOOGLE)
        st.caption(MAS_INFORMACION)

    # --- Detalle tecnico, plegado ---
    with st.expander("Ver detalle técnico"):
        if not analisis.paso_validacion:
            st.write("**No pasó la validación:**", analisis.validacion.motivo)
        else:
            st.write("**URL normalizada:**", analisis.validacion.url)
            st.write("**Apunta a:**", ", ".join(analisis.validacion.ips))

            cadena = analisis.cadena
            st.write(f"**Recorrido** ({cadena.num_saltos} redirecciones)")
            st.table([
                {"#": s.numero, "Código": s.codigo or "—", "URL": s.url}
                for s in cadena.saltos
            ])

            if cadena.problema:
                st.error(cadena.problema)

            for fuente in (analisis.google, analisis.virustotal):
                if fuente is None:
                    continue
                if not fuente.consultado:
                    st.write(f"**{fuente.fuente}:** desconocido ({fuente.error})")
                elif fuente.amenazas:
                    detalles = ", ".join(a.descripcion for a in fuente.amenazas)
                    st.write(f"**{fuente.fuente}:** reportado — {detalles}")
                else:
                    st.write(f"**{fuente.fuente}:** sin coincidencias")
                if fuente.estadisticas:
                    e = fuente.estadisticas
                    st.write(f"  · {e['malicious']} maliciosos, "
                             f"{e['suspicious']} sospechosos de {sum(e.values())} motores")

            st.caption(f"Análisis completo en {analisis.tiempo_ms} ms")

else:
    # Pantalla de bienvenida: ejemplos para probar sin pensar.
    st.info(
        "Pega un enlace arriba, o prueba con uno de estos:\n\n"
        "- `https://example.com` — un sitio normal\n"
        "- `https://testsafebrowsing.appspot.com/s/phishing.html` — "
        "URL de prueba oficial de Google, siempre marcada como phishing\n"
        "- `https://expired.badssl.com/` — certificado vencido\n"
        "- `http://169.254.169.254/` — dirección interna, debe ser rechazada"
    )

st.divider()
st.caption(
    "Esta herramienta **no garantiza** que un enlace sea seguro: reporta lo "
    "que encuentra en fuentes públicas y en la forma del enlace. "
    "Un resultado limpio no es un certificado de seguridad."
)
