# Como publicar LinkGuard

Guia paso a paso. El codigo ya esta preparado; falta la parte que solo
puedes hacer tu, porque son tus cuentas.

Tiempo: unos 25 minutos la primera vez.

---

## Antes de empezar: que va a pasar

Al publicarlo, **cualquiera con el enlace puede usar LinkGuard**. Eso
significa:

- Las revisiones gastan **tu cuota** de Google Safe Browsing
  (~10,000 al dia, suficiente).
- **Tu servidor visita** los enlaces que le manden. El guardia anti-SSRF
  es lo que impide que lo usen para espiar redes internas.
- Los enlaces que pegue la gente **pasan por tu servidor**. Por eso la
  version publica trae un aviso de privacidad.

La version publica ya viene ajustada para eso:

| | Local (tu compu) | Publica (servidor) |
|---|---|---|
| Google Safe Browsing | si | si |
| VirusTotal | si | **no** (cuota de 500/dia) |
| Acortador | si | **no** (lo resuelve api.py, que no esta en el servidor) |
| Estado de las llaves | visible | **oculto** |
| Limite por visitante | ninguno | 20 revisiones |
| Aviso de privacidad | no hace falta | **visible** |

Todo eso lo controla UNA variable: `LINKGUARD_PUBLICO`.

---

## Paso 1 — Crear el repositorio en GitHub

1. Entra a <https://github.com> y crea una cuenta si no tienes.
2. Arriba a la derecha: **+** → **New repository**.
3. Llenalo asi:
   - **Repository name:** `linkguard`
   - **Description:** `Revisa si un enlace es seguro antes de abrirlo`
   - **Public**
   - **NO** marques "Add a README file", "Add .gitignore" ni "Choose a
     license": ya los tienes y chocarian.
4. **Create repository**.

GitHub te va a mostrar una pagina con comandos. Ignorala: usa los de abajo.

---

## Paso 2 — Subir el codigo

En tu terminal, dentro de la carpeta del proyecto. Cambia `TU-USUARIO`
por tu nombre de usuario de GitHub:

    git remote add origin https://github.com/TU-USUARIO/linkguard.git
    git push -u origin main

La primera vez se va a abrir una ventana para que inicies sesion en
GitHub. Es normal: esa ventana es de Windows y de GitHub, no del
programa.

Para comprobar que las llaves NO se subieron, entra a tu repositorio en
GitHub y busca el archivo `.env`. **No debe existir.** Si aparece, avisa
antes de seguir.

---

## Paso 3 — Publicar la pagina

1. Entra a <https://share.streamlit.io> y haz clic en **Sign in with
   GitHub**. Acepta los permisos que pida (necesita leer tu repositorio).
2. **Create app** → **Deploy a public app from GitHub**.
3. Llena:
   - **Repository:** `TU-USUARIO/linkguard`
   - **Branch:** `main`
   - **Main file path:** `app.py`
   - **App URL:** elige la direccion que quieras, por ejemplo
     `linkguard`. Quedaria `linkguard.streamlit.app`.
4. Abre **Advanced settings**:
   - **Python version:** elige **3.12** o **3.13**.
   - En **Secrets**, pega esto, con tu llave de verdad:

         LINKGUARD_PUBLICO = "1"
         GOOGLE_SAFE_BROWSING_API_KEY = "pega-aqui-tu-llave"

     **NO pongas la de VirusTotal.** La version publica no la usa, y una
     llave que no esta en el servidor no se puede filtrar desde ahi.

     Tu llave de Google la sacas de tu archivo local:
     `C:\Users\<tu usuario>\.secrets\url-checker.env`

5. **Deploy**. Tarda unos minutos la primera vez.

---

## Paso 4 — Comprobar que quedo bien

Abre tu pagina y revisa:

- [ ] Abajo aparece **"Privacidad y limites de esta version"**
      (si no aparece, `LINKGUARD_PUBLICO` no se guardo bien)
- [ ] Revisa `https://testsafebrowsing.appspot.com/s/phishing.html`
      y sale **"Mejor no lo abras"**
- [ ] **NO** aparece el boton de crear enlace corto
- [ ] Con "Modo avanzado" prendido, **NO** se ve el estado de las llaves
- [ ] En las razones dice que VirusTotal no se consulto

---

## Si algo sale mal

**"Error installing requirements"**
Cambia la version de Python a 3.12 en Advanced settings y vuelve a
desplegar.

**Todo sale como "No pudimos revisarlo bien"**
La llave de Google no llego. Revisa en Settings → Secrets que este
escrita con comillas y con el nombre exacto
`GOOGLE_SAFE_BROWSING_API_KEY`.

**Sigue apareciendo el acortador**
`LINKGUARD_PUBLICO` no se guardo. Tiene que estar en Secrets, con
comillas: `LINKGUARD_PUBLICO = "1"`.

---

## Despues de publicar

- Cada vez que hagas `git push`, **Streamlit vuelve a desplegar solo**.
- Para cambiar una llave: Settings → Secrets, sin tocar el codigo.
- Para bajarla: Settings → Delete app.

### Si se te acaba la cuota de Google

Entra a la consola de Google Cloud, busca **Safe Browsing API** →
**Quotas** y ahi ves cuanto llevas. Se puede pedir mas, gratis, llenando
un formulario.

### Si alguien abusa

Streamlit Cloud no deja bloquear por IP. Si pasara:

1. Baja el limite `LIMITE_POR_VISITA` en `app.py`.
2. Si sigue, Settings → Delete app y lo vuelves a subir despues.

No es una herramienta critica: apagarla un rato no le hace daño a nadie.
