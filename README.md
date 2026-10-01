# 🛡️ LinkGuard

**Revisa si un enlace es seguro antes de abrirlo.**

Hecho por Pierre Junior · 2026

---

## Para usarlo (no necesitas saber programar)

**Doble clic en el icono de LinkGuard en tu escritorio.**

Se abre solo en tu navegador. Pegas el enlace, le das a *Revisar*, y te dice
una de cinco cosas, en palabras normales:

| | Significa |
|---|---|
| ✅ **Se ve bien** | No encontramos nada raro |
| ❔ **No pudimos revisarlo bien** | No sabemos. No es lo mismo que "seguro" |
| ⚠️ **Ten cuidado** | Hay cosas que no cuadran |
| ⛔ **Mejor no lo abras** | Fue reportado como peligroso |
| 🚫 **Este enlace no sirve** | No es un enlace valido |

Siempre te explica **por que** y **que hacer**.

La pagina esta en **español e ingles**: el selector esta arriba a la
izquierda. *(The page is available in Spanish and English — the selector
is at the top left.)*

Mientras lo uses, **no cierres la ventana negra** que se abre: ahi esta
corriendo el programa. Para apagarlo, cierra esa ventana.

¿Quieres ver los datos tecnicos? Prende **Modo avanzado** en el menu de la
izquierda.

---

## Lo demas de este README es para programadores

Si solo quieres usar LinkGuard, con lo de arriba basta.

---

## Instalarlo en otra computadora

```
git clone https://github.com/TU-USUARIO/linkguard.git
cd linkguard
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Hacen falta dos llaves gratuitas, que se consiguen en 15 minutos:

- **Google Safe Browsing** — busca *"Safe Browsing API get started"*,
  crea un proyecto en Google Cloud, habilita la API y crea una clave.
- **VirusTotal** — registrate en virustotal.com, la llave esta en tu perfil.

Se guardan en `C:\Users\<tu usuario>\.secrets\url-checker.env`
(fuera del proyecto, para que nunca acaben en git):

```
GOOGLE_SAFE_BROWSING_API_KEY=tu-llave
VIRUSTOTAL_API_KEY=tu-llave
```

Comprueba con `.\llaves.bat`.

## Publicarlo en internet

Ver [PUBLICAR.md](PUBLICAR.md). La version publica se ajusta sola con la
variable `LINKGUARD_PUBLICO=1`: apaga VirusTotal (su cuota gratuita es de
500 al dia), esconde el acortador, oculta el estado de las llaves, limita
las revisiones por visitante y muestra un aviso de privacidad.

---

## Las otras formas de usarlo

Primero entra a la carpeta:

```
cd "ruta\a\url-checker"
```

Luego, cualquiera de estos (los `.bat` no necesitan activar nada):

| Comando | Que hace |
|---|---|
| `.\check.bat <url>` | Revisa una URL y da el veredicto completo |
| `.\check.bat <url> --json` | Lo mismo, pero en JSON (para otros programas) |
| `.\check.bat --lista urls-de-prueba.txt` | Revisa muchas URLs, rapido (sin APIs) |
| `.\check.bat --lista urls-de-prueba.txt --amenazas` | ...consultando tambien las APIs |
| `.\LinkGuard.bat` | **Todo junto:** web + servidor de enlaces cortos. Es lo que hace el acceso directo del escritorio. |
| `.\web.bat` | Solo la página web, en http://localhost:8501 |
| `.\api.bat` | Levanta la API en http://127.0.0.1:8000 (docs en `/docs`) |
| `.\pruebas.bat` | Corre las 135 pruebas automaticas (pytest) |
| `.\pruebas.bat -m "not red"` | Solo las 116 que no usan internet (1 segundo) |
| `.\probar.bat` | Demo visual: ve la herramienta trabajando, con tablas |
| `.\llaves.bat` | Revisa si las llaves de API estan puestas |

**`pruebas.bat` verifica, `probar.bat` muestra.** El primero te dice si algo
se rompio; el segundo te enseña como funciona cada modulo.

### Codigos de salida

Sirven para automatizar: un script puede reaccionar sin leer la pantalla.

| Codigo | Significa |
|---|---|
| `0` | SEGURO |
| `1` | SIN_CONFIRMAR |
| `2` | SOSPECHOSO |
| `3` | POSIBLEMENTE_PELIGROSO |
| `4` | RECHAZADA |
| `10` | Error de uso (falta un argumento, no existe el archivo) |

En modo lista devuelve el **peor** veredicto de todas las URLs.

Si prefieres usar `python` directo, activa primero el entorno:
`.\.venv\Scripts\Activate.ps1` (el prompt debe mostrar `(.venv)`).

Los archivos de la carpeta `checker/` se corren con `-m`:
`python -m checker.scoring <url>`. Con la ruta
(`python checker/scoring.py`) falla, porque Python pierde de vista el paquete.

---

## Que archivo hace que

### Lo que ejecutas tu

| Archivo | Para que sirve |
|---|---|
| **`check.py`** | La herramienta. Es el `main` del proyecto. SOLO imprime: quien analiza es `scanner.py`. |
| **`api.py`** | La API HTTP (FastAPI). `POST /check` devuelve el mismo JSON que `check.py --json`. Trae limitador por IP y documentacion automatica en `/docs`. |
| **`app.py`** | La interfaz web (Streamlit). Cero logica propia: llama a `analizar()` y `evaluar()` como todo lo demas. Traduce los veredictos a lenguaje de todos los dias. |
| **`marca.py`** | El nombre, el autor y el lema, en un solo lugar. Cambialo ahi y cambia en toda la herramienta. |
| **`idiomas.py`** | TODOS los textos de la pagina, en español y en ingles. Agregar un idioma es copiar un bloque de ahi, no rastrear frases por el codigo. |
| **`LinkGuard.bat`** | El lanzador de un clic: levanta la web y el servidor de enlaces, y apaga los dos al cerrarse. |
| **`docs/`** | Cuatro diagramas en PlantUML: arquitectura, flujo, criterio del veredicto y modelo de datos. Ver `docs/README.md` para abrirlos. |
| **`tests/`** | Las pruebas de verdad (pytest). 125 en total; 108 no tocan internet. `conftest.py` tiene las fabricas de datos falsos y las fixtures. |
| **`probar.py`** | Demo visual del proyecto. Ya no es la autoridad: si se contradice con `tests/`, manda `tests/`. |
| **`pytest.ini`** | Configuracion de pytest: donde estan las pruebas y las etiquetas `red` (usa internet) y `api` (gasta cuota). |
| **`requirements-dev.txt`** | Librerias que solo hacen falta para desarrollar (pytest). Quien solo use la herramienta no las necesita. |
| **`check.bat`**, **`probar.bat`**, **`llaves.bat`** | Atajos de Windows para no tener que activar el entorno cada vez. |
| **`urls-de-prueba.txt`** | Tu lista de URLs para revisar en lote. **Agrega aqui las tuyas.** Las lineas con `#` son comentarios. |

### El motor (carpeta `checker/`)

Cada archivo es un modulo con un solo trabajo. Este es el orden en que se usan:

| Archivo | Modulo | Que hace |
|---|---|---|
| **`validator.py`** | 0 | Primera defensa. Revisa sintaxis, rechaza esquemas peligrosos (`javascript:`, `file:`), y el **guardia anti-SSRF**: resuelve el DNS y bloquea IPs internas. |
| **`health.py`** | 1 | Sale a internet. Hace la peticion HTTP, lee el codigo de estado, verifica el certificado TLS, y **sigue la cadena de redirecciones salto por salto** revalidando cada uno. |
| **`threats.py`** | 2 | Pregunta a **Google Safe Browsing** y a **VirusTotal**. Incluye el limitador de cuota (4 peticiones/min). |
| **`heuristicas.py`** | 2b | El olfato propio: detecta dominios que **imitan** a otros (punycode, typosquatting, marca en el subdominio, acortadores encadenados). No depende de que alguien los haya reportado. |
| **`scoring.py`** | 3 | El criterio. Convierte todas las señales en un veredicto con sus razones. |
| **`scanner.py`** | — | El coordinador. `analizar(url)` corre los modulos en orden y las dos APIs **en paralelo**, y devuelve un objeto `Analisis` con todo. |
| **`reporte.py`** | — | Convierte el resultado a JSON. Se escribe a mano (no `asdict()`) porque el JSON es un **contrato** con quien lo consume. |
| **`config.py`** | — | Carga las llaves de API. **Nunca imprime su valor**, solo si existen. |
| **`cache.py`** | — | Guarda las respuestas de las APIs en disco para no gastar cuota. |
| **`acortador.py`** | — | Genera enlaces cortos, **solo** para URLs con veredicto `SEGURO`, y los vuelve a revisar al abrirlos. |
| **`__init__.py`** | — | Archivo vacio que le dice a Python que `checker/` es un paquete. |

### Configuracion y secretos

| Archivo | Que es |
|---|---|
| **`.gitignore`** | Lista de lo que NUNCA se sube a GitHub: `.env`, `.venv/`, `.cache/`. |
| **`.env.example`** | Plantilla sin secretos. Esta si se puede compartir. |
| **`.env`** | Plan B para las llaves. **Se deja vacio**: las llaves de verdad viven fuera (ver abajo). |
| **`requirements.txt`** | Las librerias que usa el proyecto: `httpx`, `python-dotenv`, `rich`. |
| **`.venv/`** | El entorno virtual: una copia privada de Python para este proyecto. |
| **`.cache/`** | Respuestas guardadas de las APIs. Se puede borrar sin problema. |
| **`PROGRESS.md`** | El tablero: que se hizo cada dia, que decisiones se tomaron y por que. |

### Las llaves de API (fuera del proyecto)

```
C:\Users\<tu-usuario>\.secrets\url-checker.env
```

Viven **fuera de esta carpeta** porque Documentos se sincroniza con el
OneDrive de la escuela. Ahi van `GOOGLE_SAFE_BROWSING_API_KEY` y
`VIRUSTOTAL_API_KEY`. Para comprobar que estan bien: `.\llaves.bat`.

---

## Que reporta

El resultado tiene **dos ejes separados**, porque son preguntas distintas:

### Salud: ¿el enlace funciona?

| | Significa |
|---|---|
| `OK` | Responde correctamente (2xx) |
| `ROTO` | No existe o el servidor falla (404, 500) |
| `BLOQUEADO` | El sitio no deja entrar a programas (401, 403, 429). **No esta roto.** |
| `ERROR` | Timeout, certificado invalido, o no se pudo conectar |
| `INVALIDA` | Ni siquiera paso la validacion |

### Seguridad: ¿es riesgoso abrirlo?

| | Significa |
|---|---|
| `SEGURO` | Se consulto todo y no hay señales de riesgo |
| `SIN_CONFIRMAR` | No hay señales, pero faltaron fuentes por consultar. **No confirma que sea seguro.** |
| `SOSPECHOSO` | Hay señales que podrian indicar riesgo (3 puntos o mas) |
| `POSIBLEMENTE_PELIGROSO` | Fue reportado por Google, o por 2+ antivirus |
| `RECHAZADA` | La URL es invalida o apunta a una direccion no permitida |

Un enlace puede estar **roto y ser inofensivo** (un 404 en un sitio legitimo)
o **funcionar de maravilla y ser phishing**. Un solo numero no puede decir
las dos cosas: por eso van separados.

---

## La API HTTP

```
.\api.bat
```

Luego abre **http://127.0.0.1:8000/docs**: FastAPI genera la documentacion
interactiva a partir del codigo, y desde ahi puedes probar la API sin
escribir nada.

```
POST /check
{"url": "https://ejemplo.com", "amenazas": true}
```

Devuelve el mismo JSON que `check.py --json`.

⚠️ **Escucha solo en 127.0.0.1** (tu computadora). Cambiarlo a `0.0.0.0`
expone tus llaves de API a toda la red: cada peticion de un desconocido
gasta tu cuota, y tu servidor visita las URLs que le manden. Hay un
limitador de 10 peticiones por minuto por IP, pero eso no sustituye a
entender lo que estas exponiendo.

---

## El acortador

La idea con la que empezo el proyecto: **solo se acorta lo que salio limpio.**

Desde la web, el boton "Generar enlace corto" aparece unicamente cuando el
veredicto es `SEGURO`. Desde la API:

```
POST /acortar   {"url": "https://ejemplo.com"}
GET  /r/{codigo}
```

Cuatro reglas, y ninguna es decoracion:

1. **Solo se acorta lo limpio.** Ni siquiera `SIN_CONFIRMAR`: un enlace
   corto es una recomendacion implicita, y no se recomienda lo que no se
   pudo comprobar. Si no se puede, la respuesta explica por que (409).

2. **Se vuelve a revisar al abrirlo.** Si paso mas de una hora desde la
   ultima verificacion, se analiza otra vez antes de redirigir. Sin esto,
   un atacante podria acortar su sitio limpio, repartir el enlace, y
   ensuciar el sitio despues. Si el veredicto cambio, no redirige:
   muestra una pagina de alerta explicando que paso.

3. **Redireccion 307, nunca 301.** El 301 es permanente y los navegadores
   lo guardan: la proxima vez ni pasarian por el servidor, y la
   re-revision dejaria de ocurrir. Un acortador que revisa no puede usar
   redirecciones permanentes.

4. **El destino sale del almacen, nunca de la peticion.** Un acortador
   que acepta `?url=...` es un **redirector abierto**, y sirve para
   prestarle tu reputacion al sitio de otro: la victima ve tu dominio.

Los codigos se generan con `secrets` (no con `random`) y usan un alfabeto
sin caracteres confusos: nada de `0`/`O` ni `1`/`l`/`I`.

Los enlaces se guardan en `.enlaces/`, que esta en el `.gitignore`. Para
verlos: `python -m checker.acortador`.

⚠️ El enlace corto **solo funciona mientras la API este corriendo**
(`.\api.bat`): es ella la que atiende las redirecciones.

---

## Reglas de diseño del proyecto

Tres que se aplican en todo el codigo:

**1. No saber no es estar limpio.**
Si una API falla, o no se consulta, el resultado es `SIN_CONFIRMAR`, nunca
`SEGURO`. Un error de red no es una constancia de limpieza.

**2. Las llaves nunca se imprimen.**
Ni en mensajes de error. En `threats.py` se usa `type(error).__name__` y no
`str(error)`, porque httpx incluye la URL completa en sus errores y la llave
de Google viaja dentro de la URL.

**3. El veredicto nunca afirma con certeza.**
Se dice "podria ser peligroso", no "es peligroso". Lo exigen los terminos de
uso de Google Safe Browsing, y ademas es la verdad: la herramienta no sabe
que un sitio sea malicioso, sabe que alguien lo reporto. Cuando la advertencia
viene de datos de Google, se incluye la linea "Advisory provided by Google".

---

## Licencia de uso de las APIs

Google Safe Browsing y la API publica de VirusTotal son gratuitas
**solo para uso no comercial**. Si esto llegara a venderse o generar
ingresos, habria que pasar a Google Web Risk y a un plan de pago de
VirusTotal.

---

## Hoja de ruta

- **Semana 1** — ✅ Motor: validacion, anti-SSRF, redirecciones, salud
- **Semana 2** — ✅ Amenazas: Google + VirusTotal, cache, cuota, paralelo
- **Semana 3** — ✅ Veredicto, heuristicas, CLI a color, JSON, API HTTP
- **Semana 4** — ✅ Interfaz web con Streamlit + diagramas

El detalle dia por dia, con las decisiones y por que se tomaron, esta en
[PROGRESS.md](PROGRESS.md).

### Pendientes opcionales

- Boton de "acortar enlace" que solo funcione si el veredicto es seguro
- Recortar `probar.py` para que solo muestre y no verifique (hoy duplica
  comprobaciones que ya estan en `tests/`)
- Cambiar `dominio_registrable()` por la Public Suffix List (`tldextract`)
