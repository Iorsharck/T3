# Reporte de Hallazgos: Análisis Estático Manual

## 1. Extracción de Cadenas (Strings)
Para iniciar el análisis, buscamos texto legible dentro del binario utilizando comandos de filtrado en **PowerShell** (ante la ausencia de herramientas externas como `strings.exe`). Logramos identificar tres indicadores clave que revelan la funcionalidad del programa sin necesidad de ejecución:

* **`MAGIC: edu-malware-sim`**: Funciona como una firma o marca de agua para identificar que el archivo pertenece a nuestro proyecto académico.
* **`calc.exe`**: Indica que el programa intentará interactuar con el sistema para abrir la calculadora.
* **`C:\temp\dummy.txt`**: Revela la ruta específica donde el programa planea realizar una operación de escritura.

## 2. Extracción de Importaciones (Imports)
Utilizando la herramienta `dumpbin /imports`, analizamos las funciones que el binario solicita a las librerías dinámicas de Windows (específicamente a `KERNEL32.dll`). Confirmamos la presencia de las funciones programadas:

| Función API | Propósito Detectado |
| :--- | :--- |
| **`WinExec`** | Utilizada para lanzar la calculadora (`calc.exe`). |
| **`CreateFileA`** | Utilizada para la creación y manipulación del archivo en disco. |
| **`Sleep`** | Utilizada para pausar la ejecución del hilo principal. |

> **Nota:** Se identificó la importación de `IsDebuggerPresent`. Aunque no fue codificada explícitamente, fue añadida por el compilador de Visual Studio como parte de las funciones de soporte estándar.

## 3. Revisión de Secciones PE (Portable Executable)
Se verificó la organización interna del binario, confirmando que sigue la estructura estándar de Windows:

* **`.text`**: Sección donde reside el código ejecutable (instrucciones).
* **`.rdata`**: Sección de solo lectura donde se almacenan las constantes, strings y la Tabla de Direcciones de Importación (IAT).
* **`.data`**: Espacio reservado para variables globales y datos que pueden cambiar durante la ejecución.

## 4. Identificación de Estructuras en .data o .rdata
Se confirmó que las rutas y nombres críticos (como la ruta del archivo temporal y el comando de ejecución) están almacenados como constantes dentro de la sección **`.rdata`**. Esto es un comportamiento típico de binarios compilados en C++, ya que los parámetros no se generan dinámicamente, sino que están "quemados" en el binario para ser leídos directamente por las funciones de la API de Windows.

## 5. Hipótesis Inicial del Comportamiento
Con base en los hallazgos anteriores, definimos la siguiente hipótesis:
El archivo `team_sample.exe` actúa como un **simulador de dropper o launcher**. El flujo esperado de ejecución consiste en:
1.  **Identificación:** Emisión de un mensaje de control en la consola.
2.  **Ejecución:** Lanzamiento de un proceso externo (`calc.exe`) para demostrar persistencia o ejecución de código.
3.  **Evasión/Temporización:** Una pausa programada de 1.5 segundos.
4.  **Rastro (Artifact):** Escritura de un archivo en la carpeta temporal del sistema para confirmar actividad en el disco.