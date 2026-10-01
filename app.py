"""
LinkGuard - la pagina web.

Para levantarla:  .\\LinkGuard.bat   (o .\\web.bat)

=====================================================================
 ESTA PAGINA ES PARA CUALQUIERA, NO PARA PROGRAMADORES
=====================================================================

Por eso:
  - El veredicto se dice en palabras normales ("Mejor no lo abras"),
    no en MAYUSCULAS_CON_GUION_BAJO.
  - Las razones se traducen a lenguaje de todos los dias.
  - Todo lo tecnico vive detras del "modo avanzado", apagado por defecto.
  - Esta en español y en ingles.

Una advertencia que nadie entiende no protege a nadie. Si una persona
lee tu alerta y no sabe que hacer, la alerta fallo aunque fuera correcta.

Todos los textos viven en idiomas.py. Aqui no hay ni una frase suelta:
asi, agregar un idioma nuevo es copiar un bloque de ese archivo, no
rastrear ochenta frases repartidas por el codigo.

Nota legal: los terminos de Google prohiben afirmar con CERTEZA que un
sitio es peligroso. Ninguna frase, en ningun idioma, dice "es
peligroso": dicen "mejor no lo abras", "ten cuidado", "podria ser".
"""

import streamlit as st

import idiomas
import marca
from checker import acortador, cache, config
from checker.scanner import analizar
from checker.scoring import SEGURO, evaluar

# Donde vive la API que resuelve los enlaces cortos.
BASE_CORTA = "http://127.0.0.1:8000"

# ¿Esto corre en un servidor publico o en la computadora del dueño?
# Lo decide la variable LINKGUARD_PUBLICO (ver checker/config.py).
PUBLICO = config.es_publico()

# En publico, cuantas revisiones se permiten por visitante.
LIMITE_POR_VISITA = 20

# La atribucion a Google va en ingles tal cual: sus terminos piden ESA
# linea. No se traduce.
AVISO_GOOGLE = ("Advisory provided by Google — "
                "[Safe Browsing Advisory]"
                "(https://transparencyreport.google.com/safe-browsing/search)")

# Como se pinta cada veredicto.
PINTAR = {
    "SEGURO": st.success,
    "SIN_CONFIRMAR": st.info,
    "SOSPECHOSO": st.warning,
    "POSIBLEMENTE_PELIGROSO": st.error,
    "RECHAZADA": st.error,
}


st.set_page_config(
    page_title=marca.NOMBRE,
    page_icon=marca.EMOJI,
    layout="centered",
)


# =====================================================================
#  Barra lateral
# =====================================================================

with st.sidebar:
    st.markdown(f"## {marca.EMOJI} {marca.NOMBRE}")

    # El selector de idioma va PRIMERO y sin etiqueta traducida: si
    # alguien no entiende la pagina, lo primero que necesita encontrar
    # es justo esto.
    lang = st.radio(
        "Idioma / Language",
        options=list(idiomas.IDIOMAS.keys()),
        format_func=lambda codigo: idiomas.IDIOMAS[codigo],
        horizontal=True,
        label_visibility="collapsed",
    )

    def t(clave: str, **formato) -> str:
        """Atajo: traduce al idioma que eligio el usuario."""
        return idiomas.t(clave, lang, **formato)

    st.caption(t("lema"))
    st.divider()

    avanzado = st.toggle(t("modo_avanzado"), value=False,
                         help=t("modo_avanzado_ayuda"))
    consultar_amenazas = st.toggle(t("consultar"), value=True,
                                   help=t("consultar_ayuda"))

    # El estado de las llaves y el boton de vaciar cache son cosas del
    # dueño, no del visitante. En publico no se muestran.
    if avanzado and not PUBLICO:
        st.divider()
        st.caption(t("llaves"))
        for nombre, (listo, mensaje) in config.estado().items():
            st.caption(f"{'✅' if listo else '⬜'} {config.LLAVES[nombre]} — {mensaje}")

        vigentes, caducadas = cache.estado()
        st.caption(t("cache", vigentes=vigentes, caducadas=caducadas))
        if st.button(t("vaciar_cache"), use_container_width=True):
            st.toast(t("cache_vaciado", n=cache.limpiar()))

    st.divider()
    st.caption(f"{marca.NOMBRE} · {t('hecho_por')} {marca.AUTOR} · {marca.ANIO}")


# =====================================================================
#  Lo que ve todo el mundo
# =====================================================================

st.markdown(f"# {marca.EMOJI} {marca.NOMBRE}")
st.markdown(f"#### {t('lema')}")
st.write("")

with st.form("formulario"):
    url = st.text_input(
        "URL",
        placeholder=t("pega_aqui"),
        label_visibility="collapsed",
    )
    enviar = st.form_submit_button(t("revisar"), type="primary",
                                   use_container_width=True)

if enviar and url.strip():
    revisiones = st.session_state.get("revisiones", 0)
    if PUBLICO and revisiones >= LIMITE_POR_VISITA:
        st.error(t("limite", n=LIMITE_POR_VISITA))
    else:
        with st.spinner(t("revisando")):
            analisis = analizar(url, consultar_amenazas=consultar_amenazas)
            st.session_state["analisis"] = analisis
            st.session_state["veredicto"] = evaluar(analisis)
            st.session_state["revisiones"] = revisiones + 1
            st.session_state.pop("enlace_corto", None)
elif enviar:
    st.warning(t("pega_primero"))


analisis = st.session_state.get("analisis")
veredicto = st.session_state.get("veredicto")

if analisis and veredicto:
    emoji, titulo, explicacion, que_hacer = idiomas.veredicto(
        veredicto.seguridad, lang)
    pintar = PINTAR.get(veredicto.seguridad, st.info)

    pintar(f"## {emoji} {titulo}\n\n**{explicacion}**\n\n{que_hacer}")

    # --- Las razones, en palabras normales ---
    if veredicto.señales:
        st.write("")
        st.markdown(t("que_encontramos"))
        for señal in veredicto.señales:
            icono = "🔴" if señal.dura else ("🟠" if señal.peso else "⚪")
            frase = idiomas.en_palabras_normales(señal.texto, lang)
            st.markdown(f"{icono} {frase}")
            if avanzado:
                # En modo avanzado tambien se ve el texto crudo del motor,
                # que siempre esta en español, y de donde salio.
                st.markdown(
                    f"<small style='margin-left:1.6rem;opacity:.6'>"
                    f"{señal.texto} — {t('fuente')}: {señal.fuente}</small>",
                    unsafe_allow_html=True)

    # --- A donde lleva de verdad ---
    if analisis.cadena and analisis.cadena.num_saltos > 0:
        st.write("")
        st.markdown(f"{t('a_donde_lleva')} `{analisis.url_final}`")
        st.caption(t("redirecciones", n=analisis.cadena.num_saltos))

    if veredicto.cita_a_google:
        st.caption(AVISO_GOOGLE)
        st.caption(t("mas_info"))

    # --- Acortar: solo si salio limpio, y solo en la version local ---
    # En el servidor publico no existe api.py, que es quien resuelve los
    # enlaces cortos. Ofrecerlo ahi seria repartir enlaces rotos.
    st.divider()
    if PUBLICO:
        pass
    elif veredicto.seguridad == SEGURO:
        st.markdown(t("compartir"))
        st.caption(t("compartir_ayuda"))
        if st.button(t("crear_corto"), use_container_width=True):
            destino = analisis.url_final or analisis.validacion.url
            try:
                st.session_state["enlace_corto"] = acortador.acortar(
                    destino, veredicto.seguridad)
            except acortador.NoSePuedeAcortar as error:
                st.error(str(error))

        enlace = st.session_state.get("enlace_corto")
        if enlace:
            st.code(f"{BASE_CORTA}/r/{enlace.codigo}", language=None)
            st.caption(t("corto_nota"))
    else:
        st.caption(t("no_se_acorta"))

    # --- Detalle tecnico: solo en modo avanzado ---
    if avanzado:
        with st.expander(t("detalle")):
            st.write(t("veredicto_interno"), veredicto.seguridad,
                     f"({veredicto.puntos})")
            st.write(t("salud"), veredicto.salud)

            if not analisis.paso_validacion:
                st.write(t("no_paso"), analisis.validacion.motivo)
            else:
                st.write(t("url_normalizada"), analisis.validacion.url)
                st.write(t("apunta_a"), ", ".join(analisis.validacion.ips))
                st.write(t("recorrido", n=analisis.cadena.num_saltos))
                st.table([{"#": s.numero, "HTTP": s.codigo or "—", "URL": s.url}
                          for s in analisis.cadena.saltos])
                if analisis.cadena.problema:
                    st.error(analisis.cadena.problema)

                for fuente in (analisis.google, analisis.virustotal):
                    if fuente is None:
                        continue
                    st.write(f"**{fuente.fuente}:** {fuente.resumen}")
                    if fuente.estadisticas:
                        e = fuente.estadisticas
                        st.write(f"  · {e['malicious']} / {sum(e.values())}")

            st.caption(t("analizado_en", ms=analisis.tiempo_ms))

else:
    st.info(t("bienvenida"))
    with st.expander(t("ejemplos_titulo")):
        st.markdown(t("ejemplos"))

st.divider()
st.caption(t("descargo"))

if PUBLICO:
    # Decirle a la gente que pasa con lo que escribe no es un tramite
    # legal: es lo minimo. Nadie deberia tener que adivinarlo.
    with st.expander(t("privacidad_titulo")):
        st.markdown(t("privacidad", n=LIMITE_POR_VISITA))

st.caption(f"{marca.NOMBRE} · {t('hecho_por')} {marca.AUTOR} · {marca.ANIO}")
