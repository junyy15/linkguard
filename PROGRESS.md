# Progreso - URL Health & Safety Checker

> Este archivo es el tablero del proyecto. Se actualiza cada vez que avanzamos.
> Ultima actualizacion: 29 de septiembre de 2026

## Estado actual

**LAS CUATRO SEMANAS, TERMINADAS. 179 pruebas, todas en verde.**
**+ Repositorio git inicializado.**
**+ DNS rebinding tapado.**
**+ Acortador que solo acorta lo limpio: la idea original, cerrada.**
(Todo eso en "Mejoras despues del plan", al final.)

La herramienta tiene cuatro formas de usarse:
  terminal · JSON por tuberia · API HTTP · pagina web

Pendientes opcionales: el boton de "acortar enlace" para enlaces seguros,
y recortar `probar.py` para que solo muestre y no verifique.

Progreso total: 19 de 19 dias. `[####################] 100%`

## Como correr las pruebas

    cd "ruta\a\url-checker"

    .\probar.bat                          -> TODO (43 pruebas)
    .\probar.bat --validador              -> solo el Modulo 0
    .\probar.bat --salud                  -> solo el Modulo 1
    .\probar.bat --cadena                 -> solo las redirecciones
    .\probar.bat --amenazas               -> solo Google Safe Browsing
    .\probar.bat --virustotal             -> solo VirusTotal, limitador, cache
    .\probar.bat --scanner                -> solo el coordinador y los hilos
    .\llaves.bat                          -> revisa si las llaves estan puestas

    python -m checker.cache               -> ver el estado del cache
    python -m checker.cache limpiar       -> borrarlo
    .\probar.bat https://algo.com         -> una sola URL

    .\check.bat https://algo.com          -> la herramienta, una URL
    .\check.bat --lista urls-de-prueba.txt            -> muchas URLs, rapido
    .\check.bat --lista urls-de-prueba.txt --amenazas -> ...consultando las APIs

---

## SEMANA 1 - Diagnostico del enlace (Motor principal)

- [x] **Dia 1 - Setup del proyecto**
  - [x] Python 3.14.4 verificado
  - [x] Carpeta del proyecto en `Documentos\url-checker` (OneDrive)
  - [x] Entorno virtual `.venv` creado
  - [x] Librerias instaladas: httpx, python-dotenv, rich
  - [x] `.gitignore` protegiendo `.env` y `.venv`
  - [x] `check.py` corre y responde
- [x] **Dia 2 - Modulo 0: Validador** (`checker/validator.py`)
  - [x] Revisar sintaxis de la URL y normalizar (agregar https:// si falta)
  - [x] Limite de largo (2048 caracteres)
  - [x] Rechazar esquemas peligrosos: `javascript:`, `file:`, `data:`
  - [x] Rechazar credenciales `usuario@dominio` (truco de phishing)
  - [x] Guardia anti-SSRF: resolver DNS y bloquear IPs internas
        (127.0.0.1, 10.x, 192.168.x, 169.254.169.254, IPv6 mapeadas)
  - [x] `check.py` conectado al validador y probado con 10 URLs
  - [x] `probar.py` - banco de pruebas con 18 casos en tabla de colores
  - [x] `probar.bat` y `check.bat` - atajos para correr sin activar el entorno
  - [x] BUG CERRADO: puerto invalido (`:99999`) ahora se rechaza.
        `partes.port` es una propiedad: el acto de pedirla dispara la revision.
  - [x] **18 de 18 casos en verde**

**DIA 2 CERRADO.** El validador bloquea 15 tipos de entrada peligrosa o invalida.
- [x] **Dia 3 - Modulo 1: Peticion HTTP** (`checker/health.py`)
  - [x] Peticion con timeout de 5 segundos
  - [x] HEAD primero, GET solo si el servidor contesta 403/405/501
  - [x] `follow_redirects=False` (los redirects los seguimos nosotros el Dia 4)
  - [x] `verify=True`: el certificado TLS se verifica y los fallos se REPORTAN
  - [x] Clasificar codigos en OK / REDIRECCION / ROTO
  - [x] Manejar errores: timeout, certificado SSL, conexion, red
  - [x] `probar.py --salud` con 9 casos de logica + 6 peticiones reales
  - [ ] **Detalle pendiente (ejercicio de Giovanni):** con un limite de 0.001 s
        el mensaje dice "no respondio en 0 segundos". El formato `:.0f` redondea.
        Esta en `health.py`, en el `except httpx.TimeoutException`.
- [x] **Dia 4 - Cadena de redirecciones**
  - [x] Seguir redirecciones a mano, salto por salto (maximo 10)
  - [x] **Revalidar anti-SSRF en CADA salto** (el punto de todo el dia)
  - [x] Detectar bucles (A manda a B, B manda a A)
  - [x] `urljoin` para los Location relativos ("/destino")
  - [x] Detectar bajada de https a http
  - [x] Detectar cambio de dominio de inicio a fin
  - [x] Guardar la cadena completa y la URL final
  - [x] `probar.py --cadena`: 5 situaciones simuladas + 3 cadenas reales
  - [x] Aprendido: `python -m checker.health` (con -m), no la ruta del archivo
- [x] **Dia 5 - Cierre de la semana**
  - [x] Un solo comando corre los tres bancos: `.\probar.bat` (43 pruebas)
  - [x] Codigo de salida 1 si algo falla (para automatizar mas adelante)
  - [x] Modo lote: `check.py --lista archivo.txt`
  - [x] `urls-de-prueba.txt` con 16 URLs reales de todo tipo
  - [x] Arreglado el formato del timeout (`:g` en vez de `:.0f`)
  - [x] **Categoria nueva BLOQUEADO** (401/403/429): un sitio que no deja
        entrar a programas NO esta roto. Lo descubrimos con Wikipedia, que
        contesta 403 y pide en el cuerpo que se respete su politica de bots.
        Decision: no disfrazamos el User-Agent para evadirlo. Se reporta la verdad.

**Meta de la semana: CUMPLIDA.** El motor valida, sigue cadenas y reporta salud.

---

## SEMANA 2 - Inteligencia de amenazas

- [ ] **Dia 1 - Llaves de API**
  - [x] Archivo secreto creado FUERA de OneDrive:
        `C:\Users\<tu-usuario>\.secrets\url-checker.env`
  - [x] `checker/config.py` que lee de ahi y NUNCA imprime el valor de una llave
  - [x] `.\llaves.bat` para revisar si ya estan puestas
  - [x] Llave de Google Safe Browsing obtenida y restringida a esa sola API
  - [x] Llave de VirusTotal obtenida
  - [x] Las dos puestas y verificadas con `.\llaves.bat`

### REQUISITO LEGAL descubierto al leer los terminos de Google

Los terminos del Safe Browsing API obligan a que las advertencias al usuario:

  1. NO afirmen con certeza que un sitio es peligroso. Hay que usar palabras
     como "posible", "probable", "sospechoso", "podria ser".
  2. Incluyan la linea "Advisory provided by Google" con enlace al
     Safe Browsing Advisory, SOLO en las advertencias que vengan de Google.
  3. Dejen al usuario informarse mas (antiphishing.org para phishing).

Esto cambia el diseño de la Semana 3: el veredicto NO puede decir
"PELIGROSO" a secas. Tiene que decir algo como "POSIBLEMENTE PELIGROSO"
y citar la fuente de cada señal.
- [x] **Dia 2 - Cliente de Google Safe Browsing** (`checker/threats.py`)
  - [x] Consultar URL original y URL final en una sola peticion
  - [x] Probar con las URLs de prueba oficiales de Google (phishing, malware,
        software no deseado): las tres detectadas
  - [x] Regla: sin llave o con error, el resultado es DESCONOCIDO, no "limpio"
  - [x] La llave nunca aparece en mensajes de error (se usa
        `type(error).__name__`, no `str(error)`, porque httpx incluye la
        URL completa y la llave viaja dentro de la URL)
  - [x] Advertencias con el lenguaje que exige Google ("podria ser") y con
        la atribucion "Advisory provided by Google"
  - [x] `probar.py --amenazas`: 5 casos, incluido el de "sin llave"
- [x] **Dia 3 - Cliente de VirusTotal**
  - [x] Leer `last_analysis_stats` (malicious / suspicious / harmless)
  - [x] `id_de_url()`: base64 seguro para URLs, sin los `=` del final
  - [x] La llave va en el ENCABEZADO `x-apikey`, no en la URL (mas seguro
        que Safe Browsing, que la pide como parametro)
  - [x] 404 de VirusTotal = "no hay analisis", NO significa limpio
  - [x] Limitador de ventana deslizante: 4 peticiones por minuto
  - [x] Cache en disco (`checker/cache.py`), en `.cache/` que esta en .gitignore
  - [x] VirusTotal solo se consulta para el destino FINAL, no cada eslabon
  - [x] `probar.py --virustotal`: 7 casos (incluye limitador y caducidad
        del cache, ambos sin internet)

### Decision del cache: vigencias asimetricas

  - Respuesta LIMPIA: vale 1 hora. Un sitio sano hoy puede infectarse en la
    tarde; guardar "limpio" mucho tiempo haria decir "seguro" de algo que
    ya dejo de serlo.
  - Respuesta REPORTADA: vale 24 horas. Un sitio marcado rara vez se limpia
    en horas, y si nos equivocamos el costo es una falsa alarma, no un riesgo.

  Regla general: que caduque antes el dato que, si se equivoca, le dice al
  usuario que algo es seguro.
- [x] **Dia 4 - Paralelo y reorganizacion**
  - [x] `checker/scanner.py`: `analizar()` devuelve un objeto `Analisis` con
        validacion + cadena + google + virustotal. check.py SOLO imprime.
  - [x] Las dos APIs se consultan en paralelo con `ThreadPoolExecutor`
        (1287 ms en serie -> 769 ms en paralelo)
  - [x] Decidido NO usar asyncio: obligaba a reescribir health.py y
        threats.py enteros para ganar en dos peticiones. No se paga.
  - [x] Candado (`threading.Lock`) en el cache y en el limitador: sin el,
        dos hilos escribiendo el JSON al mismo tiempo se pisan
  - [x] Si una API falla, el resultado dice "desconocido", NUNCA "seguro"
  - [x] Modo lista con amenazas: `check.py --lista archivo.txt --amenazas`
        (avisa cuanto va a tardar por el limite de 4 por minuto)
  - [x] Una URL invalida corta ahi mismo: no gasta ni una peticion

**Meta de la semana: CUMPLIDA.** Dos fuentes de amenazas, en paralelo,
con cache y control de cuota.

---

## SEMANA 3 - Puntuacion y terminal

- [x] **Dia 1 - Modulo 3: Motor de puntuacion** (`checker/scoring.py`)
  - [x] Cuatro niveles: SEGURO / SIN_CONFIRMAR / SOSPECHOSO /
        POSIBLEMENTE_PELIGROSO (+ RECHAZADA si no paso la validacion)
  - [x] Reglas DURAS (una basta): Google reporta, o VT malicious >= 2
  - [x] Reglas de PUNTOS (umbral 3): 1 antivirus=+2, certificado malo=+3,
        cadena bloqueada=+3, https->http=+2, cambio de dominio=+1,
        cadena larga=+1, destino sin https=+1
  - [x] Cada veredicto trae su LISTA DE RAZONES con fuente y peso
  - [x] El veredicto se imprime ARRIBA; abajo queda el detalle tecnico
  - [x] Modo lista con columna de veredicto
  - [x] `probar.py --scoring`: 16 casos, TODOS sin internet (se fabrican
        analisis a mano). Prueban el criterio, no la red.

### Por que 2 antivirus y no 1

VirusTotal consulta mas de 90 motores. Que uno solo marque algo es ruido
estadistico normal. Dos coincidiendo ya es señal. Un antivirus solo suma
2 puntos: cuenta, pero no alcanza por si mismo.

### Dos errores de diseño que encontro la corrida real

1. El veredicto decia "No encontramos señales de riesgo" mientras listaba
   señales abajo. Una herramienta que se contradice deja de usarse.
   Arreglado: frase distinta cuando hay puntos pero no llegan al umbral.

2. El modo lista decia "SEGURO" sin haber consultado ninguna API, porque
   las fuentes llegaban como None y el codigo solo revisaba `consultado`.
   Arreglado: fuente en None cuenta igual que fuente caida.
   Ahora dice "sin confirmar", que es la verdad.
- [x] **Dia 2 - Heuristicas extra** (`checker/heuristicas.py`)
  - [x] Punycode / homografos: decodifica `xn--` y detecta alfabetos
        mezclados (peso 3). `xn--80ak6aa92e.com` se ve como 'аррӏе.com'
  - [x] Marca conocida en el subdominio (peso 3):
        `paypal.com.seguro.xyz` -> el dominio real es `seguro.xyz`
  - [x] Typosquatting con distancia de Levenshtein (peso 3):
        `arnazon.com` esta a 2 letras de `amazon`
  - [x] Acortadores encadenados: 2 o mas = peso 3, uno solo = peso 1
  - [x] Señales debiles: muchos niveles de dominio, muchos guiones
  - [x] `dominio_registrable()` con sufijos compuestos (.com.mx, .co.uk)
  - [x] Las heuristicas corren TAMBIEN cuando la validacion falla: un
        dominio de phishing dado de baja sigue siendo evidencia
  - [x] `probar.py --heuristicas`: 15 casos, ninguno toca internet
  - [x] Prueba anti-falsos-positivos: 6 sitios legitimos comunes
        (github, google, python.org, ejemplo.edu.mx, mercadolibre.com.mx)
        y ninguno se marca

### Limite conocido: el dominio registrable es una aproximacion

`dominio_registrable()` usa una lista corta de sufijos compuestos. La
solucion correcta es la Public Suffix List de Mozilla (libreria
`tldextract`). Para este proyecto alcanza, pero en produccion habria
que cambiarlo.

### Por que ninguna heuristica es regla dura

Las heuristicas se equivocan mas que las bases de datos. Un dominio raro
no es un dominio malicioso. Todas suman puntos; ninguna dispara sola el
nivel mas alto. Una heuristica que marca sitios legitimos es peor que no
tenerla: entrena a la gente a ignorar las alertas.
- [x] **Dia 3 - Salida a color con `rich`**
  - [x] `check.py` reescrito con `rich`: panel de veredicto con color
        segun el nivel, tabla del recorrido, codigos HTTP coloreados
  - [x] El color es informacion, no decoracion (verde/amarillo/naranja/rojo)
  - [x] Bandera `--json` que imprime SOLO json (se puede encadenar)
  - [x] `checker/reporte.py`: el JSON se escribe a mano, con
        `version: 1`. No se usa `dataclasses.asdict()` porque eso volcaria
        las tripas y cualquier renombre interno rompería a quien lo consuma.
  - [x] Codigos de salida: 0 seguro, 1 sin confirmar, 2 sospechoso,
        3 posiblemente peligroso, 4 rechazada, 10 error de uso
  - [x] El modo lista devuelve el PEOR veredicto de toda la lista
  - [x] `probar.py --salida`: 8 casos, incluye dos pruebas de contrato
        (que ningun nivel se quede sin codigo de salida ni sin color)
- [x] **Dia 4 - Pruebas unitarias con pytest**
  - [x] `pytest` instalado, en `requirements-dev.txt` aparte (quien solo
        use la herramienta no necesita pytest)
  - [x] `pytest.ini` con testpaths y las etiquetas `red` y `api`
  - [x] `tests/conftest.py`: fabricas de datos falsos + fixtures
        (`limpias`, `cache_aislado`)
  - [x] 7 archivos de prueba: validator, health, scoring, heuristicas,
        cache, salida, amenazas, scanner
  - [x] **125 pruebas. Las 108 sin red corren en 1 segundo.**
  - [x] `.\pruebas.bat` para correrlas
  - [x] `@pytest.mark.parametrize` en vez de bucles: si falla un caso,
        pytest dice exactamente cual
  - [x] `monkeypatch` en vez de try/finally a mano: pytest deshace el
        cambio al terminar, aunque la prueba reviente
  - [x] `cache_aislado` manda el cache a una carpeta temporal: ninguna
        prueba ensucia el cache real ni depende de lo que dejo otra

### Como correr solo una parte

    .\pruebas.bat -m "not red"   -> las 108 rapidas, sin internet (1 seg)
    .\pruebas.bat -m red         -> solo las que salen a la red
    .\pruebas.bat -k scoring     -> solo las que digan 'scoring'
    .\pruebas.bat -v             -> con el nombre de cada prueba

### Deuda conocida: probar.py duplica comprobaciones

`probar.py` se queda porque sirve para VER la herramienta trabajando, pero
varias de sus comprobaciones ahora estan duplicadas en `tests/`. Si alguna
vez se contradicen, la buena es la de `tests/`. Convendria recortar
`probar.py` para que solo muestre y no verifique.
- [x] **Dia 5 - Endpoint FastAPI `POST /check`** (`api.py`)
  - [x] `POST /check` con `{"url": "...", "amenazas": true}`
  - [x] `GET /` para comprobar que el servicio vive
  - [x] Documentacion interactiva automatica en `/docs` (Swagger UI)
  - [x] Devuelve EXACTAMENTE el mismo JSON que `check.py --json`
        (los dos usan `checker/reporte.py`): un solo contrato publico
  - [x] Pydantic valida la entrada antes de que llegue a nuestro codigo
  - [x] `.\api.bat` para levantarla
  - [x] 10 pruebas mas con `TestClient` (la app corre en memoria, sin
        abrir puerto ni levantar servidor)

### Las cuatro cosas que cambian al exponer esto por HTTP

 1. **Tu cuota es de quien llame.** Cada peticion gasta TUS 500 consultas
    diarias de VirusTotal. Por eso hay limitador por IP (10/min), y
    responde 429 de inmediato en vez de hacer esperar: dejar esperando a
    quien abusa solo te llena el servidor de conexiones abiertas.
 2. **Tu servidor se vuelve un proxy.** Alguien manda una URL y TU
    servidor la visita: eso es SSRF. El guardia del Modulo 0 deja de ser
    buena practica y pasa a ser lo unico que protege. Hay una prueba
    dedicada a eso (`test_ssrf_bloqueado_por_la_api`).
 3. **Los errores hablan de mas.** Un traceback en la respuesta regala
    rutas del disco y estructura del proyecto. El detalle va al registro
    del servidor; al cliente solo un mensaje generico. Tambien probado.
 4. **Escuchar en 0.0.0.0 expone a toda la red.** Por defecto 127.0.0.1.

### Detalle importante: `def` y no `async def`

El endpoint se declara con `def` normal. Nuestro codigo es bloqueante
(httpx sincrono, DNS, el sleep del limitador). Con `async def`, todo eso
correria en el unico hilo que atiende a todos y una peticion lenta
congelaria el servidor entero. Con `def`, FastAPI lo manda a un pool de
hilos. Es un error comun: poner async porque "suena mas rapido".

**Meta de la semana: CUMPLIDA.** CLI presentable + API funcionando.

---

## SEMANA 4 - Interfaz web (Streamlit)

- [x] **Pagina de Streamlit** (`app.py`), se levanta con `.\web.bat`
  - [x] Caja de texto + boton, dentro de un `st.form` para que el script
        no se re-ejecute con cada letra escrita
  - [x] Veredicto con color y emoji segun el nivel
  - [x] Los dos ejes por separado: Seguridad y Salud, en dos columnas
  - [x] Lista de razones, cada una con su fuente y su peso
  - [x] Atribucion a Google solo cuando la advertencia viene de Google
  - [x] Detalle tecnico plegado (`st.expander`) con la cadena completa
  - [x] Barra lateral: interruptor de amenazas, estado de las llaves
        (sin mostrar su valor), estado del cache y boton para vaciarlo
  - [x] Aviso al pie: un resultado limpio NO es un certificado de seguridad
  - [x] CERO logica nueva: llama a `analizar()` y `evaluar()`, las mismas
        funciones que usan check.py y api.py
- [x] **Diagramas en PlantUML** (`docs/`)
  - [x] `arquitectura.puml` - componentes y quien usa a quien
  - [x] `flujo-analisis.puml` - secuencia, con lo que va en paralelo
  - [x] `decision-veredicto.puml` - el criterio completo en una hoja
  - [x] `modelo-de-datos.puml` - los objetos que se pasan entre modulos
- [x] Extra: boton de "acortar enlace" que solo funciona si el veredicto
      es Seguro (ver "Acortador" al final del archivo)

**Meta de la semana: CUMPLIDA.** Alguien que no sea programador puede usarlo.

### El modelo mental de Streamlit

No hay eventos ni callbacks: cada interaccion vuelve a ejecutar el script
COMPLETO, de arriba a abajo. Por eso:
 - Las variables normales se pierden en cada interaccion; lo que debe
   sobrevivir va en `st.session_state`.
 - Sin `st.form`, cada tecla que escribes dispararia un analisis entero
   con sus peticiones a internet.

---

## Decisiones que ya tomamos

| Tema | Decision | Por que |
|---|---|---|
| Lenguaje | Python | Sintaxis clara, buenas librerias de red y seguridad |
| Cliente HTTP | `httpx` | Control manual de redirecciones y timeouts |
| Interfaz final | Streamlit (Semana 4) | Interfaz web sin escribir HTML ni CSS |
| Estructura del resultado | Dos ejes separados: Salud y Seguridad | Un enlace puede estar roto pero ser seguro, o funcionar y ser malicioso |
| Secretos | `.env` + `python-dotenv`, fuera de OneDrive | La carpeta puede estar sincronizada con una cuenta ajena |
| Licencias de API | GSB y VirusTotal gratis = solo uso NO comercial | Si algun dia se vende, hay que pasar a Google Web Risk |

---

# MEJORAS DESPUES DEL PLAN

## Git (1 de octubre de 2026)

- Repositorio inicializado, rama `main`, primer commit con 44 archivos.
- `.gitignore` reescrito por secciones, con los secretos hasta arriba.
- `.gitattributes` para normalizar los finales de linea.
- Verificado que `.env`, `.venv` y `.cache` NO estan rastreados.
- Identidad configurada SOLO para este repositorio, no global.
- Pendiente: el repo vive dentro de OneDrive, que sincroniza tambien la
  carpeta `.git` y puede corromper el historial si sincroniza a media
  operacion. El arreglo real es subirlo a GitHub o sacarlo de OneDrive.

## DNS rebinding tapado (1 de octubre de 2026)

### El hueco

Habia DOS resoluciones de DNS para una misma peticion:

    1. validator.py resuelve  ->  "93.184.216.34, publica, OK"
    2. httpx resuelve OTRA VEZ al conectarse  ->  127.0.0.1

Un atacante con su propio servidor DNS y TTL 0 puede contestar distinto
cada vez. La validacion aprueba y la conexion acaba en tu maquina. Es el
bypass clasico de los filtros anti-SSRF. En la terminal casi no importa;
en `api.py` expuesto por HTTP, era LA vulnerabilidad del proyecto.

### El arreglo: `fijar_destino()` en `checker/health.py`

- Resuelve el DNS UNA sola vez y valida todas las IPs.
- La peticion va a la IP ya validada, no al nombre.
- El encabezado `Host` lleva el nombre original (si no, el servidor no
  sabe que sitio le estas pidiendo).
- La extension `sni_hostname` lleva el nombre original, para que el
  certificado TLS se verifique contra el NOMBRE y no contra la IP.
  Sin eso habriamos cambiado un agujero por otro peor. Tres pruebas de
  red lo vigilan (expired / self-signed / wrong.host de badssl.com).
- Las IPs se prueban en orden, IPv4 primero: muchas maquinas tienen
  IPv6 configurado pero sin salida real.

### De paso, dos cosas mas

- **Nunca se descarga el cuerpo.** Todas las peticiones usan
  `cliente.stream()`: encabezados, codigo, y se cierra. Antes, el GET de
  respaldo bajaba la pagina entera a memoria y un servidor malicioso
  podia mandar gigabytes.
- **Tope de tiempo para la cadena completa** (20 s). Antes, 10 saltos de
  5 segundos eran 50 segundos colgados.

### Pruebas nuevas: `tests/test_ssrf.py`, 15 casos

La mas importante simula el ataque: un DNS que contesta publica la
primera vez e interna la segunda. Comprueba que solo hay UNA consulta y
que la peticion sale hacia la IP publica.

Sutileza: `ClienteFalso` solo implementa `stream()`. Si alguien volviera
a usar `get()` o `head()`, las pruebas revientan. Asi tambien se vigila
que nunca se descargue el cuerpo.

## Acortador: solo se acorta lo limpio (1 de octubre de 2026)

La idea con la que empezo el proyecto, ya construida: `checker/acortador.py`,
`POST /acortar`, `GET /r/{codigo}` y el boton en la web.

Se decidio construir el acortador en casa en vez de usar bit.ly: eso
habria obligado a otra llave de API y a confiar en un tercero para el
enlace final.

### Las cuatro reglas, y por que cada una

1. **Solo se acorta lo limpio.** Ni siquiera `SIN_CONFIRMAR`. Un enlace
   corto es una recomendacion implicita, y no se recomienda lo que no se
   pudo comprobar. La condicion vive dentro de `acortador.acortar()`, no
   en la interfaz, para que no se pueda saltar llamando desde otro lado.

2. **Se vuelve a revisar al abrirlo** (si paso mas de 1 hora). Sin esto
   el acortador firma un cheque en blanco: el atacante acorta su sitio
   limpio, reparte el enlace, y lo infecta despues. Si el veredicto
   cambio, no redirige: muestra una pagina de alerta que explica que paso.

3. **307 y nunca 301.** El 301 es permanente y el navegador lo guarda:
   la proxima vez ni pasaria por el servidor y la re-revision dejaria de
   ocurrir. Un acortador que revisa no puede usar redirecciones
   permanentes.

4. **El destino sale del almacen, nunca de la peticion.** Un acortador
   que acepta `?url=...` es un redirector abierto, y sirve para prestarle
   tu reputacion al sitio de otro: la victima ve tu dominio en el enlace.

### Detalles

- Codigos con `secrets`, no con `random`: la secuencia de `random` se
  puede reconstruir, y con codigos adivinables cualquiera recorreria
  todos los enlaces guardados.
- Alfabeto sin caracteres confusos: nada de `0`/`O` ni `1`/`l`/`I`.
- Se acorta la URL FINAL de la cadena, no la que escribio el usuario:
  es la que de verdad se reviso, y le quita una capa de redireccion.
- Almacen en `.enlaces/`, con candado, igual que el cache.
- 29 pruebas nuevas (`test_acortador.py` y `test_api_acortador.py`),
  incluidas la del enlace que se ensucia despues y la del redirector
  abierto. **179 pruebas en total.**

## Lo que sigue pendiente

- Fuga de memoria en el limitador de `api.py`: las IPs nunca se borran
- Cachear tambien Google Safe Browsing (su respuesta trae `cacheDuration`)
- Borrar del cache las entradas ya caducadas
- Lista de marcas mas grande para el typosquatting
- Public Suffix List en vez de la lista corta de sufijos
- Recortar `probar.py` para que solo muestre y no verifique
