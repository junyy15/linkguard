# URL Health & Safety Checker

Herramienta que revisa si un enlace esta roto, es invalido o es peligroso
(phishing / malware) antes de usarlo o acortarlo.

Da un veredicto con sus razones, consultando Google Safe Browsing y
VirusTotal, y revisando la cadena completa de redirecciones.

---

## Como usarlo

Primero entra a la carpeta:

```
cd "$env:USERPROFILE\OneDrive - um.edu.mx\Documentos\url-checker"
```

Luego, cualquiera de estos (los `.bat` no necesitan activar nada):

| Comando | Que hace |
|---|---|
| `.\check.bat <url>` | Revisa una URL y da el veredicto completo |
| `.\check.bat <url> --json` | Lo mismo, pero en JSON (para otros programas) |
| `.\check.bat --lista urls-de-prueba.txt` | Revisa muchas URLs, rapido (sin APIs) |
| `.\check.bat --lista urls-de-prueba.txt --amenazas` | ...consultando tambien las APIs |
| `.\web.bat` | **La página web.** Se abre sola en http://localhost:8501 |
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
| **`app.py`** | La interfaz web (Streamlit). Cero logica propia: llama a `analizar()` y `evaluar()` como todo lo demas. |
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
C:\Users\Glee51\.secrets\url-checker.env
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
