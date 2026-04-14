# Reporte de Análisis Estático con Ghidra

## Información del Archivo
* **Nombre:** team_sample.exe
* **Formato:** Portable Executable (PE) para x86_64
* **Herramienta:** Ghidra 12.0.4

## Proceso de Ingeniería Inversa
Se realizó la ingesta del binario en Ghidra, utilizando los analizadores por defecto para identificar funciones, strings y referencias cruzadas (XREFs).

## Análisis de la Función Principal (`main`)
Se localizó la función `main` (ubicada en la dirección de memoria base del segmento `.text`). El proceso de descompilación permitió recuperar la lógica del programa original:

### 1. Indicadores de Compromiso (IoCs)
* **Cadenas de texto:** Se identificó el string `"MAGIC: edu-malware-sim"` en el flujo de salida estándar, utilizado para verificación del binario.
* **Rutas de archivos:** Se detectó la ruta absoluta `C:\temp\dummy.txt` hardcodeada en el binario.

### 2. Llamadas a la API de Windows
El análisis de las funciones importadas reveló el uso de las siguientes APIs críticas:

| Función | Parámetro Detectado | Propósito |
| :--- | :--- | :--- |
| `WinExec` | `"calc.exe"` | Ejecución de procesos externos. |
| `Sleep` | `0x5dc` (1500ms) | Introducción de retardos para evasión básica o temporización. |
| `CreateFileA` | `dummy.txt` | Interacción con el sistema de archivos (Escritura). |

## Evidencia Visual
(anexada)

## Conclusión
El análisis estático confirma que el binario realiza acciones de creación de archivos y ejecución de procesos sin interacción del usuario, características típicas de un dropper o malware de etapa inicial.