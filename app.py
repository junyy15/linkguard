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

Una advertencia que nadie entiende no protege a nadie. Si una persona
lee tu alerta y no sabe que hacer, la alerta fallo aunque fuera correcta.

Nota legal: los terminos de Google prohiben afirmar con CERTEZA que un
sitio es peligroso. Por eso ninguna frase dice "es peligroso": dicen
"mejor no lo abras", "ten cuidado", "podria ser". Eso tambien es la
verdad: la herramienta no sabe, sabe que alguien lo reporto.
"""

import streamlit as st

import marca
from checker import acortador, cache, config
from checker.scanner import analizar
from checker.scoring import (
    POSIBLEMENTE_PELIGROSO,
    RECHAZADA,
    SEGURO,
    SIN_CONFIRMAR,
    SOSPECHOSO,
    evaluar,
)

# Donde vive la API que resuelve los enlaces cortos.
BASE_CORTA = "http://127.0.0.1:8000"

# ¿Esto corre en un servidor publico o en la computadora del dueño?
# Lo decide la variable LINKGUARD_PUBLICO (ver checker/config.py).
PUBLICO = config.es_publico()

# En publico, cuantas revisiones se permiten por visitante y por hora.
# No es una defensa fuerte -quien quiera se puede saltar esto- pero evita
# que una pestaña olvidada o un script torpe gasten la cuota de todos.
LIMITE_POR_VISITA = 20

AVISO_GOOGLE = ("Advisory provided by Google — "
                "[Safe Browsing Advisory]"
                "(https://transparencyreport.google.com/safe-browsing/search)")
MAS_INFORMACION = ("Más sobre estafas por enlace: "
                   "[antiphishing.org](https://www.antiphishing.org)")


# Como se le dice a cada veredicto EN PALABRAS NORMALES.
#   (emoji, titulo, explicacion, que hacer, funcion de streamlit)
PRESENTACION = {
    SEGURO: (
        "✅", "Se ve bien",
        "Revisamos este enlace y no encontramos nada raro.",
        "Puedes abrirlo con normalidad. Aun así, nunca escribas "
        "contraseñas ni datos de tu tarjeta en un sitio al que llegaste "
        "por un enlace que no esperabas.",
        st.success,
    ),
    SIN_CONFIRMAR: (
        "❔", "No pudimos revisarlo bien",
        "No encontramos nada raro, pero tampoco pudimos consultar todas "
        "nuestras fuentes.",
        "Esto NO quiere decir que sea seguro: quiere decir que no sabemos. "
        "Si no esperabas este enlace, mejor no lo abras.",
        st.info,
    ),
    SOSPECHOSO: (
        "⚠️", "Ten cuidado",
        "Este enlace tiene cosas que no cuadran.",
        "No es seguro afirmar que sea peligroso, pero algo no está bien. "
        "Si no sabes exactamente quién te lo mandó y por qué, no lo abras.",
        st.warning,
    ),
    POSIBLEMENTE_PELIGROSO: (
        "⛔", "Mejor no lo abras",
        "Este enlace fue reportado como peligroso.",
        "No lo abras y no se lo reenvíes a nadie. Si te lo mandó un "
        "conocido, avísale: es posible que le hayan robado la cuenta.",
        st.error,
    ),
    RECHAZADA: (
        "🚫", "Este enlace no sirve",
        "No es un enlace válido, o apunta a un lugar que no se puede revisar.",
        "Revisa que lo hayas copiado completo. Si lo copiaste bien y aun "
        "así sale esto, desconfía.",
        st.error,
    ),
}

# Traduccion de las señales tecnicas a lenguaje normal.
# Se busca por un pedacito del texto original.
TRADUCCIONES = [
    ("Phishing", "Está en la lista de sitios que roban contraseñas"),
    ("Malware", "Está en la lista de sitios que instalan virus"),
    ("Software no deseado", "Instala programas que no pediste"),
    ("antivirus la marcan", "Varios antivirus lo reconocen como peligroso"),
    ("antivirus la marca", "Un antivirus lo reconoce como peligroso"),
    ("certificado de seguridad", "El candado de seguridad del sitio no es válido"),
    ("direccion interna", "Apunta a una dirección privada, no a un sitio real"),
    ("credenciales antes del dominio", "Usa un truco para aparentar ser otro sitio"),
    ("mezcla alfabetos", "Usa letras de otro alfabeto para imitar a un sitio conocido"),
    ("subdominio", "Pone el nombre de una marca conocida donde no corresponde"),
    ("se parece mucho a", "El nombre se parece sospechosamente a un sitio conocido"),
    ("acortadores", "Pasa por varios acortadores, lo que esconde el destino real"),
    ("enlace acortado", "Es un enlace acortado: no se ve a dónde lleva"),
    ("https a http", "A medio camino deja de ir cifrado"),
    ("dominio distinto", "Empieza en un sitio y termina en otro"),
    ("no usa https", "El sitio final no va cifrado"),
    ("No se pudo consultar", "No pudimos preguntarle a una de nuestras fuentes"),
    ("No se consulto", "No consultamos todas las fuentes"),
    ("Esquema no permitido", "No es una página web: es otra cosa"),
    ("no existe o no responde", "Ese sitio no existe"),
    ("bloquead", "La cadena de redirecciones termina en un lugar no permitido"),
    ("circulo", "El enlace da vueltas sin llegar a ningún lado"),
    ("Demasiadas redirecciones", "Pasa por demasiados sitios antes de llegar"),
]


def en_palabras_normales(texto: str) -> str:
    """Traduce una señal tecnica. Si no la conoce, la deja como esta."""
    for pedazo, traduccion in TRADUCCIONES:
        if pedazo.lower() in texto.lower():
            return traduccion
    return texto


st.set_page_config(
    page_title=marca.NOMBRE,
    page_icon=marca.EMOJI,
    layout="centered",
)


# =====================================================================
#  Barra lateral: casi vacia a proposito
# =====================================================================

with st.sidebar:
    st.markdown(f"## {marca.EMOJI} {marca.NOMBRE}")
    st.caption(marca.LEMA)
    st.divider()

    avanzado = st.toggle(
        "Modo avanzado",
        value=False,
        help="Muestra el detalle técnico: redirecciones, códigos HTTP, "
             "estado de las fuentes y del caché.",
    )

    consultar_amenazas = st.toggle(
        "Consultar listas de peligro",
        value=True,
        help="Apagarlo es más rápido, pero entonces no se puede decir que "
             "un enlace esté limpio.",
    )

    # El estado de las llaves y el boton de vaciar cache son cosas del
    # dueño, no del visitante. En publico no se muestran: decirle a un
    # desconocido como esta configurado tu servidor nunca ayuda.
    if avanzado and not PUBLICO:
        st.divider()
        st.caption("**Llaves de API**")
        for nombre, (listo, mensaje) in config.estado().items():
            st.caption(f"{'✅' if listo else '⬜'} {config.LLAVES[nombre]} — {mensaje}")

        vigentes, caducadas = cache.estado()
        st.caption(f"**Caché:** {vigentes} vigentes, {caducadas} caducadas")
        if st.button("Vaciar caché", use_container_width=True):
            st.toast(f"Caché vaciado ({cache.limpiar()} entradas)")

    st.divider()
    st.caption(marca.CREDITO)


# =====================================================================
#  Lo que ve todo el mundo
# =====================================================================

st.markdown(f"# {marca.EMOJI} {marca.NOMBRE}")
st.markdown(f"#### {marca.LEMA}")
st.write("")

with st.form("formulario"):
    url = st.text_input(
        "Pega el enlace",
        placeholder="Pega aquí el enlace que te mandaron…",
        label_visibility="collapsed",
    )
    enviar = st.form_submit_button("Revisar", type="primary",
                                   use_container_width=True)

if enviar and url.strip():
    # Tope por visitante, solo en la version publica.
    revisiones = st.session_state.get("revisiones", 0)
    if PUBLICO and revisiones >= LIMITE_POR_VISITA:
        st.error(
            f"Llegaste al límite de {LIMITE_POR_VISITA} revisiones por "
            f"visita. LinkGuard usa cuotas gratuitas y compartidas; "
            f"vuelve más tarde o instálalo en tu computadora "
            f"(el código es libre)."
        )
    else:
        with st.spinner("Revisando el enlace…"):
            analisis = analizar(url, consultar_amenazas=consultar_amenazas)
            st.session_state["analisis"] = analisis
            st.session_state["veredicto"] = evaluar(analisis)
            st.session_state["revisiones"] = revisiones + 1
            st.session_state.pop("enlace_corto", None)
elif enviar:
    st.warning("Primero pega un enlace.")


analisis = st.session_state.get("analisis")
veredicto = st.session_state.get("veredicto")

if analisis and veredicto:
    emoji, titulo, explicacion, que_hacer, pintar = PRESENTACION.get(
        veredicto.seguridad,
        ("❔", "Resultado", veredicto.frase, "", st.info))

    pintar(f"## {emoji} {titulo}\n\n**{explicacion}**\n\n{que_hacer}")

    # --- Las razones, en palabras normales ---
    if veredicto.señales:
        st.write("")
        st.markdown("**Qué encontramos:**")
        for señal in veredicto.señales:
            icono = "🔴" if señal.dura else ("🟠" if señal.peso else "⚪")
            if avanzado:
                st.markdown(f"{icono} {señal.texto}  \n"
                            f"<small>fuente: {señal.fuente}</small>",
                            unsafe_allow_html=True)
            else:
                st.markdown(f"{icono} {en_palabras_normales(señal.texto)}")

    # --- A donde lleva de verdad ---
    if analisis.cadena and analisis.cadena.num_saltos > 0:
        st.write("")
        st.markdown(f"**A dónde lleva en realidad:** `{analisis.url_final}`")
        st.caption(f"Pasa por {analisis.cadena.num_saltos} redirección(es) "
                   f"antes de llegar ahí.")

    if veredicto.cita_a_google:
        st.caption(AVISO_GOOGLE)
        st.caption(MAS_INFORMACION)

    # --- Acortar: solo si salio limpio, y solo en la version local ---
    # En el servidor publico no existe api.py, que es quien resuelve los
    # enlaces cortos. Ofrecer el boton ahi seria repartir enlaces rotos.
    st.divider()
    if PUBLICO:
        pass
    elif veredicto.seguridad == SEGURO:
        st.markdown("**¿Quieres compartirlo?**")
        st.caption("Como este enlace salió limpio, puedes generar una "
                   "versión corta que se vuelve a revisar sola cada vez "
                   "que alguien la abre.")
        if st.button("🔗 Crear enlace corto", use_container_width=True):
            destino = analisis.url_final or analisis.validacion.url
            try:
                st.session_state["enlace_corto"] = acortador.acortar(
                    destino, veredicto.seguridad)
            except acortador.NoSePuedeAcortar as error:
                st.error(str(error))

        enlace = st.session_state.get("enlace_corto")
        if enlace:
            st.code(f"{BASE_CORTA}/r/{enlace.codigo}", language=None)
            st.caption(
                "Si el sitio se ensucia después, el enlace corto deja de "
                "funcionar solo y avisa. Funciona mientras LinkGuard esté "
                "abierto en tu computadora."
            )
    else:
        st.caption("🔗 Este enlace no se puede acortar: solo acortamos los "
                   "que salen limpios.")

    # --- Detalle tecnico: solo en modo avanzado ---
    if avanzado:
        with st.expander("Detalle técnico"):
            st.write("**Veredicto interno:**", veredicto.seguridad,
                     f"({veredicto.puntos} puntos)")
            st.write("**Salud:**", veredicto.salud)

            if not analisis.paso_validacion:
                st.write("**No pasó la validación:**", analisis.validacion.motivo)
            else:
                st.write("**URL normalizada:**", analisis.validacion.url)
                st.write("**Apunta a:**", ", ".join(analisis.validacion.ips))
                st.write(f"**Recorrido** ({analisis.cadena.num_saltos} saltos)")
                st.table([{"#": s.numero, "Código": s.codigo or "—", "URL": s.url}
                          for s in analisis.cadena.saltos])
                if analisis.cadena.problema:
                    st.error(analisis.cadena.problema)

                for fuente in (analisis.google, analisis.virustotal):
                    if fuente is None:
                        continue
                    st.write(f"**{fuente.fuente}:** {fuente.resumen}")
                    if fuente.estadisticas:
                        e = fuente.estadisticas
                        st.write(f"  · {e['malicious']} maliciosos, "
                                 f"{e['suspicious']} sospechosos de "
                                 f"{sum(e.values())} motores")

            st.caption(f"Analizado en {analisis.tiempo_ms} ms")

else:
    st.info(
        "**¿Te mandaron un enlace y no sabes si abrirlo?** Pégalo arriba.\n\n"
        "LinkGuard revisa si funciona, a dónde lleva de verdad, y si "
        "alguien ya lo reportó como peligroso."
    )
    with st.expander("Enlaces de ejemplo para probar"):
        st.markdown(
            "- `https://example.com` — un sitio normal\n"
            "- `https://testsafebrowsing.appspot.com/s/phishing.html` — "
            "enlace de prueba de Google, siempre marcado como peligroso\n"
            "- `https://expired.badssl.com/` — un sitio con el candado vencido\n"
            "- `http://169.254.169.254/` — una dirección interna, se rechaza"
        )

st.divider()
st.caption(
    "LinkGuard **no garantiza** que un enlace sea seguro. Revisa fuentes "
    "públicas y la forma del enlace, y te dice lo que encuentra. "
    "Que salga limpio no es un certificado de seguridad."
)

if PUBLICO:
    # Decirle a la gente que pasa con lo que escribe no es un tramite
    # legal: es lo minimo. Nadie deberia tener que adivinarlo.
    with st.expander("Privacidad y límites de esta versión"):
        st.markdown(
            "- **Los enlaces que pegas se envían** a Google Safe Browsing "
            "para revisarlos, y se guardan temporalmente en el servidor "
            "para no repetir consultas. No pegues enlaces que contengan "
            "información privada (por ejemplo, con tu sesión o tus datos "
            "dentro de la dirección).\n"
            "- **El servidor visita el enlace** para ver si funciona y a "
            "dónde lleva. No descarga ni guarda el contenido de la página.\n"
            "- No se usan cookies de seguimiento ni se piden datos tuyos.\n"
            f"- Esta versión pública usa **solo Google Safe Browsing** y "
            f"permite **{LIMITE_POR_VISITA} revisiones por visita**, porque "
            "funciona con cuotas gratuitas y compartidas.\n"
            "- Si quieres la versión completa (con VirusTotal y el "
            "acortador), instálala en tu computadora: el código es libre."
        )

st.caption(marca.CREDITO)
