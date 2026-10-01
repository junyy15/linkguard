"""
Los textos de LinkGuard, en español y en ingles.

TODO el texto que ve el usuario vive aqui. En el codigo de la pagina no
queda ni una frase suelta.

Por que asi y no frases regadas por app.py:
  - Agregar un idioma nuevo es copiar un bloque, no rastrear 80 frases.
  - Se ve de un vistazo si falta una traduccion.
  - Cambiar como se dice algo no obliga a tocar la logica.

El motor (checker/) sigue hablando español: sus mensajes son tecnicos y
los traduce la tabla SEÑALES de aqui abajo, buscando un pedacito del
texto original.
"""

IDIOMAS = {"es": "Español", "en": "English"}
POR_DEFECTO = "es"


# =====================================================================
#  Textos de la interfaz
# =====================================================================

TEXTOS: dict[str, dict[str, str]] = {
    "es": {
        "lema": "Revisa si un enlace es seguro antes de abrirlo",
        "idioma": "Idioma",

        # Barra lateral
        "modo_avanzado": "Modo avanzado",
        "modo_avanzado_ayuda": "Muestra el detalle técnico: redirecciones, "
                               "códigos HTTP, estado de las fuentes y del caché.",
        "consultar": "Consultar listas de peligro",
        "consultar_ayuda": "Apagarlo es más rápido, pero entonces no se puede "
                           "decir que un enlace esté limpio.",
        "llaves": "**Llaves de API**",
        "cache": "**Caché:** {vigentes} vigentes, {caducadas} caducadas",
        "vaciar_cache": "Vaciar caché",
        "cache_vaciado": "Caché vaciado ({n} entradas)",

        # Formulario
        "pega_aqui": "Pega aquí el enlace que te mandaron…",
        "revisar": "Revisar",
        "pega_primero": "Primero pega un enlace.",
        "revisando": "Revisando el enlace…",

        # Resultado
        "que_encontramos": "**Qué encontramos:**",
        "a_donde_lleva": "**A dónde lleva en realidad:**",
        "redirecciones": "Pasa por {n} redirección(es) antes de llegar ahí.",
        "fuente": "fuente",
        "mas_info": "Más sobre estafas por enlace: "
                    "[antiphishing.org](https://www.antiphishing.org)",

        # Acortador
        "compartir": "**¿Quieres compartirlo?**",
        "compartir_ayuda": "Como este enlace salió limpio, puedes generar una "
                           "versión corta que se vuelve a revisar sola cada vez "
                           "que alguien la abre.",
        "crear_corto": "🔗 Crear enlace corto",
        "corto_nota": "Si el sitio se ensucia después, el enlace corto deja de "
                      "funcionar solo y avisa. Funciona mientras LinkGuard esté "
                      "abierto en tu computadora.",
        "no_se_acorta": "🔗 Este enlace no se puede acortar: solo acortamos los "
                        "que salen limpios.",

        # Detalle tecnico
        "detalle": "Detalle técnico",
        "veredicto_interno": "**Veredicto interno:**",
        "salud": "**Salud:**",
        "no_paso": "**No pasó la validación:**",
        "url_normalizada": "**URL normalizada:**",
        "apunta_a": "**Apunta a:**",
        "recorrido": "**Recorrido** ({n} saltos)",
        "analizado_en": "Analizado en {ms} ms",

        # Bienvenida
        "bienvenida": "**¿Te mandaron un enlace y no sabes si abrirlo?** "
                      "Pégalo arriba.\n\nLinkGuard revisa si funciona, a dónde "
                      "lleva de verdad, y si alguien ya lo reportó como peligroso.",
        "ejemplos_titulo": "Enlaces de ejemplo para probar",
        "ejemplos": "- `https://example.com` — un sitio normal\n"
                    "- `https://testsafebrowsing.appspot.com/s/phishing.html` — "
                    "enlace de prueba de Google, siempre marcado como peligroso\n"
                    "- `https://expired.badssl.com/` — un sitio con el candado "
                    "vencido\n"
                    "- `http://169.254.169.254/` — una dirección interna, se rechaza",

        # Pie
        "descargo": "LinkGuard **no garantiza** que un enlace sea seguro. Revisa "
                    "fuentes públicas y la forma del enlace, y te dice lo que "
                    "encuentra. Que salga limpio no es un certificado de seguridad.",
        "hecho_por": "Hecho por",

        # Modo publico
        "limite": "Llegaste al límite de {n} revisiones por visita. LinkGuard usa "
                  "cuotas gratuitas y compartidas; vuelve más tarde o instálalo "
                  "en tu computadora (el código es libre).",
        "privacidad_titulo": "Privacidad y límites de esta versión",
        "privacidad": "- **Los enlaces que pegas se envían** a Google Safe "
                      "Browsing para revisarlos, y se guardan temporalmente en el "
                      "servidor para no repetir consultas. No pegues enlaces que "
                      "contengan información privada.\n"
                      "- **El servidor visita el enlace** para ver si funciona y a "
                      "dónde lleva. No descarga ni guarda el contenido de la página.\n"
                      "- No se usan cookies de seguimiento ni se piden datos tuyos.\n"
                      "- Esta versión pública usa **solo Google Safe Browsing** y "
                      "permite **{n} revisiones por visita**, porque funciona con "
                      "cuotas gratuitas y compartidas.\n"
                      "- Si quieres la versión completa (con VirusTotal y el "
                      "acortador), instálala en tu computadora: el código es libre.",
    },

    "en": {
        "lema": "Check whether a link is safe before you open it",
        "idioma": "Language",

        # Sidebar
        "modo_avanzado": "Advanced mode",
        "modo_avanzado_ayuda": "Shows the technical detail: redirects, HTTP "
                               "status codes, source status and cache.",
        "consultar": "Check threat databases",
        "consultar_ayuda": "Turning this off is faster, but then we cannot say "
                           "a link is clean.",
        "llaves": "**API keys**",
        "cache": "**Cache:** {vigentes} valid, {caducadas} expired",
        "vaciar_cache": "Clear cache",
        "cache_vaciado": "Cache cleared ({n} entries)",

        # Form
        "pega_aqui": "Paste the link you were sent…",
        "revisar": "Check link",
        "pega_primero": "Paste a link first.",
        "revisando": "Checking the link…",

        # Result
        "que_encontramos": "**What we found:**",
        "a_donde_lleva": "**Where it actually goes:**",
        "redirecciones": "It passes through {n} redirect(s) before getting there.",
        "fuente": "source",
        "mas_info": "More about link scams: "
                    "[antiphishing.org](https://www.antiphishing.org)",

        # Shortener
        "compartir": "**Want to share it?**",
        "compartir_ayuda": "Since this link came back clean, you can create a "
                           "short version that re-checks itself every time "
                           "someone opens it.",
        "crear_corto": "🔗 Create short link",
        "corto_nota": "If the site turns bad later, the short link stops working "
                      "on its own and warns instead. It works while LinkGuard is "
                      "running on your computer.",
        "no_se_acorta": "🔗 This link cannot be shortened: we only shorten links "
                        "that come back clean.",

        # Technical detail
        "detalle": "Technical detail",
        "veredicto_interno": "**Internal verdict:**",
        "salud": "**Health:**",
        "no_paso": "**Failed validation:**",
        "url_normalizada": "**Normalised URL:**",
        "apunta_a": "**Resolves to:**",
        "recorrido": "**Redirect chain** ({n} hops)",
        "analizado_en": "Analysed in {ms} ms",

        # Welcome
        "bienvenida": "**Were you sent a link and you are not sure about it?** "
                      "Paste it above.\n\nLinkGuard checks whether it works, "
                      "where it really leads, and whether anyone has already "
                      "reported it as dangerous.",
        "ejemplos_titulo": "Example links to try",
        "ejemplos": "- `https://example.com` — an ordinary site\n"
                    "- `https://testsafebrowsing.appspot.com/s/phishing.html` — "
                    "Google's official test link, always flagged as phishing\n"
                    "- `https://expired.badssl.com/` — a site with an expired "
                    "certificate\n"
                    "- `http://169.254.169.254/` — an internal address, rejected",

        # Footer
        "descargo": "LinkGuard **does not guarantee** that a link is safe. It "
                    "checks public sources and the shape of the link, and tells "
                    "you what it finds. A clean result is not a safety certificate.",
        "hecho_por": "Made by",

        # Public mode
        "limite": "You have reached the limit of {n} checks per visit. LinkGuard "
                  "runs on free, shared quotas; come back later or install it on "
                  "your own computer (the code is open).",
        "privacidad_titulo": "Privacy and limits of this version",
        "privacidad": "- **The links you paste are sent** to Google Safe Browsing "
                      "to be checked, and are stored temporarily on the server to "
                      "avoid repeat lookups. Do not paste links that contain "
                      "private information.\n"
                      "- **The server visits the link** to see whether it works "
                      "and where it leads. It never downloads or stores the page "
                      "content.\n"
                      "- No tracking cookies, and no personal data is requested.\n"
                      "- This public version uses **Google Safe Browsing only** "
                      "and allows **{n} checks per visit**, because it runs on "
                      "free, shared quotas.\n"
                      "- If you want the full version (with VirusTotal and the "
                      "link shortener), install it on your own computer: the code "
                      "is open.",
    },
}


# =====================================================================
#  Los veredictos
# =====================================================================
#
# (emoji, titulo, explicacion, que hacer)
#
# Ojo con el ingles: los terminos de Google prohiben afirmar con certeza
# que un sitio es peligroso. Por eso dice "best not to open it" y no
# "this site is dangerous". La traduccion tambien tiene que cumplirlo.

VEREDICTOS: dict[str, dict[str, tuple[str, str, str, str]]] = {
    "es": {
        "SEGURO": (
            "✅", "Se ve bien",
            "Revisamos este enlace y no encontramos nada raro.",
            "Puedes abrirlo con normalidad. Aun así, nunca escribas "
            "contraseñas ni datos de tu tarjeta en un sitio al que llegaste "
            "por un enlace que no esperabas.",
        ),
        "SIN_CONFIRMAR": (
            "❔", "No pudimos revisarlo bien",
            "No encontramos nada raro, pero tampoco pudimos consultar todas "
            "nuestras fuentes.",
            "Esto NO quiere decir que sea seguro: quiere decir que no sabemos. "
            "Si no esperabas este enlace, mejor no lo abras.",
        ),
        "SOSPECHOSO": (
            "⚠️", "Ten cuidado",
            "Este enlace tiene cosas que no cuadran.",
            "No hay un reporte en su contra, pero varias señales no encajan. "
            "Si no sabes exactamente quién te lo mandó y por qué, no lo abras.",
        ),
        "POSIBLEMENTE_PELIGROSO": (
            "⛔", "Mejor no lo abras",
            "Este enlace fue reportado como peligroso.",
            "No lo abras y no se lo reenvíes a nadie. Si te lo mandó un "
            "conocido, avísale: es posible que le hayan robado la cuenta.",
        ),
        "RECHAZADA": (
            "🚫", "Este enlace no sirve",
            "No es un enlace válido, o apunta a un lugar que no se puede revisar.",
            "Revisa que lo hayas copiado completo. Si lo copiaste bien y aun "
            "así sale esto, desconfía.",
        ),
    },
    "en": {
        "SEGURO": (
            "✅", "Looks fine",
            "We checked this link and found nothing unusual.",
            "You can open it normally. Even so, never type passwords or card "
            "details on a site you reached through a link you were not "
            "expecting.",
        ),
        "SIN_CONFIRMAR": (
            "❔", "We could not check it properly",
            "We found nothing unusual, but we could not reach all of our "
            "sources either.",
            "This does NOT mean it is safe: it means we do not know. If you "
            "were not expecting this link, better not to open it.",
        ),
        "SOSPECHOSO": (
            "⚠️", "Be careful",
            "There are things about this link that do not add up.",
            "There is no report against it, but several signs do not fit. "
            "If you do not know exactly who sent it and why, do not open it.",
        ),
        "POSIBLEMENTE_PELIGROSO": (
            "⛔", "Best not to open it",
            "This link has been reported as dangerous.",
            "Do not open it and do not forward it to anyone. If someone you "
            "know sent it, let them know: their account may have been stolen.",
        ),
        "RECHAZADA": (
            "🚫", "This link does not work",
            "It is not a valid link, or it points somewhere we cannot check.",
            "Check that you copied the whole thing. If you did and this still "
            "comes up, be suspicious.",
        ),
    },
}


# =====================================================================
#  Las señales tecnicas, en palabras normales
# =====================================================================
#
# Se busca un pedacito del texto que produce el motor (en español) y se
# devuelve la frase en el idioma elegido.

SEÑALES: list[tuple[str, dict[str, str]]] = [
    ("Phishing", {
        "es": "Está en la lista de sitios que roban contraseñas",
        "en": "It is on the list of sites that steal passwords"}),
    ("Malware", {
        "es": "Está en la lista de sitios que instalan virus",
        "en": "It is on the list of sites that install viruses"}),
    ("Software no deseado", {
        "es": "Instala programas que no pediste",
        "en": "It installs software you did not ask for"}),
    ("antivirus la marcan", {
        "es": "Varios antivirus lo reconocen como peligroso",
        "en": "Several antivirus engines flag it as dangerous"}),
    ("antivirus la marca", {
        "es": "Un antivirus lo reconoce como peligroso",
        "en": "One antivirus engine flags it as dangerous"}),
    ("certificado de seguridad", {
        "es": "El candado de seguridad del sitio no es válido",
        "en": "The site's security certificate is not valid"}),
    ("direccion interna", {
        "es": "Apunta a una dirección privada, no a un sitio real",
        "en": "It points to a private address, not a real site"}),
    ("credenciales antes del dominio", {
        "es": "Usa un truco para aparentar ser otro sitio",
        "en": "It uses a trick to look like a different site"}),
    ("mezcla alfabetos", {
        "es": "Usa letras de otro alfabeto para imitar a un sitio conocido",
        "en": "It uses letters from another alphabet to imitate a known site"}),
    ("subdominio", {
        "es": "Pone el nombre de una marca conocida donde no corresponde",
        "en": "It puts a well-known brand name where it does not belong"}),
    ("se parece mucho a", {
        "es": "El nombre se parece sospechosamente a un sitio conocido",
        "en": "The name is suspiciously similar to a well-known site"}),
    ("acortadores", {
        "es": "Pasa por varios acortadores, lo que esconde el destino real",
        "en": "It goes through several URL shorteners, hiding the real "
              "destination"}),
    ("enlace acortado", {
        "es": "Es un enlace acortado: no se ve a dónde lleva",
        "en": "It is a shortened link: you cannot see where it leads"}),
    ("https a http", {
        "es": "A medio camino deja de ir cifrado",
        "en": "Partway through, it stops being encrypted"}),
    ("dominio distinto", {
        "es": "Empieza en un sitio y termina en otro",
        "en": "It starts at one site and ends up at another"}),
    ("no usa https", {
        "es": "El sitio final no va cifrado",
        "en": "The final site is not encrypted"}),
    ("apagado en esta version", {
        "es": "No consultamos una de nuestras fuentes en esta versión",
        "en": "One of our sources is not used in this version"}),
    ("No se pudo consultar", {
        "es": "No pudimos preguntarle a una de nuestras fuentes",
        "en": "We could not reach one of our sources"}),
    ("No se consulto", {
        "es": "No consultamos todas las fuentes",
        "en": "We did not check every source"}),
    ("Esquema no permitido", {
        "es": "No es una página web: es otra cosa",
        "en": "This is not a web page: it is something else"}),
    ("no existe o no responde", {
        "es": "Ese sitio no existe",
        "en": "That site does not exist"}),
    ("bloquead", {
        "es": "La cadena de redirecciones termina en un lugar no permitido",
        "en": "The redirect chain ends somewhere that is not allowed"}),
    ("circulo", {
        "es": "El enlace da vueltas sin llegar a ningún lado",
        "en": "The link goes round in circles without arriving anywhere"}),
    ("Demasiadas redirecciones", {
        "es": "Pasa por demasiados sitios antes de llegar",
        "en": "It goes through too many sites before arriving"}),
    ("tardo mas", {
        "es": "El enlace tardó demasiado en responder",
        "en": "The link took too long to respond"}),
    ("mal formada", {
        "es": "La dirección está mal escrita",
        "en": "The address is malformed"}),
]


# =====================================================================
#  Funciones
# =====================================================================

def t(clave: str, idioma: str = POR_DEFECTO, **formato) -> str:
    """Devuelve un texto en el idioma pedido.

    Si falta la traduccion, cae al español en vez de reventar o de
    mostrar la clave cruda. Una traduccion incompleta no debe romper la
    pagina: debe verse rara, y nada mas.
    """
    texto = TEXTOS.get(idioma, {}).get(clave) or TEXTOS[POR_DEFECTO].get(clave, clave)
    return texto.format(**formato) if formato else texto


def veredicto(nivel: str, idioma: str = POR_DEFECTO) -> tuple[str, str, str, str]:
    """El emoji, titulo, explicacion y que hacer, para un nivel."""
    tabla = VEREDICTOS.get(idioma, VEREDICTOS[POR_DEFECTO])
    return tabla.get(nivel, ("❔", nivel, "", ""))


def en_palabras_normales(texto: str, idioma: str = POR_DEFECTO) -> str:
    """Traduce una señal tecnica. Si no la conoce, la deja como esta."""
    for pedazo, versiones in SEÑALES:
        if pedazo.lower() in texto.lower():
            return versiones.get(idioma, versiones[POR_DEFECTO])
    return texto
