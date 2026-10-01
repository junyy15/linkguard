# Diagramas del proyecto

Cuatro diagramas en PlantUML. El codigo fuente de cada uno es un archivo
`.puml` de texto: se puede versionar en git y ver los cambios, cosa que
con una imagen no se puede.

| Archivo | Que muestra | Cuando sirve |
|---|---|---|
| `arquitectura.puml` | Que modulo usa a cual | Para entender el proyecto completo de un vistazo |
| `flujo-analisis.puml` | Que pasa y en que orden al revisar una URL | Para ver donde se paraleliza y donde no |
| `decision-veredicto.puml` | El criterio completo del Modulo 3 | **El mas util:** la regla de decision entera, sin leer codigo |
| `modelo-de-datos.puml` | Los objetos que se pasan entre modulos | Para saber que trae cada cosa |

## Como verlos

### Opcion 1 — VS Code (la mas comoda)

1. Instala la extension **PlantUML** (de jebbs).
2. Abre cualquier `.puml`.
3. `Alt + D` y se abre la vista previa, que se actualiza sola al editar.

   La extension necesita **Java** instalado. Si no lo tienes, en los
   ajustes de la extension pon `plantuml.render` en `PlantUMLServer`,
   y renderiza usando el servidor publico en vez de tu maquina.

### Opcion 2 — En el navegador, sin instalar nada

1. Entra a <https://www.plantuml.com/plantuml/uml/>
2. Copia el contenido del `.puml` y pegalo ahi.

   Ojo: eso manda el texto del diagrama a un servidor publico. Para
   diagramas de arquitectura de un proyecto educativo da igual, pero
   piensalo dos veces antes de pegar ahi algo de un trabajo real.

### Opcion 3 — Generar las imagenes tu

Con Java instalado, baja `plantuml.jar` de plantuml.com y corre:

    java -jar plantuml.jar docs/*.puml

Te deja un `.png` junto a cada `.puml`.

## Por que PlantUML y no dibujarlos

Un diagrama dibujado a mano queda desactualizado el primer dia que
alguien toca el codigo, y nadie lo arregla porque es trabajoso. Uno en
texto se edita en segundos, se revisa en un pull request y vive junto al
codigo que describe.
