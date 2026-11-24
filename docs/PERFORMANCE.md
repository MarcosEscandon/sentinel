# Rendimiento del escáner

Este documento describe la metodología del benchmark incluido en
`tools/benchmark.py`, los resultados reales obtenidos y las recomendaciones
derivadas de ellos. Los datos sin procesar están en
`docs/benchmark-results.json`.

## Metodología

El script genera un árbol temporal con `tempfile` (no se incluye en el
repositorio) y lo elimina al terminar salvo que se use `--keep`. Por defecto
crea 2000 archivos repartidos en 8 subdirectorios, con tamaños aleatorios
uniformes entre 1 KiB y 64 KiB (63,0 MiB en total). La semilla es fija
(`20261123`) para que el experimento sea reproducible. Cada 50 archivos se
inserta el marcador `SENTINEL_TEST_MARKER`, reconocido por la base de firmas
real `sentinel/data/signatures.json` (40 archivos marcados en esta ejecución).

Para cada valor de `--jobs` se crea un `Scanner` nuevo con un `ScanConfig`
idéntico salvo el número de hilos, y se mide una única pasada completa con
`time.perf_counter()`:

- configuración por defecto: `hash_all=True` (SHA-256 de todo el archivo),
  heurística activada, análisis de contenedores activado y `sample_size=1 MiB`;
- YARA no se ejerce porque el benchmark no inyecta un motor YARA;
- se mide enumeración + lectura + hash + detección + fusión de resultados;
  no se mide la generación del árbol ni la escritura del JSON de resultados;
- `MB/s` usa MiB (1024² bytes) y `archivos/s` usa `files_scanned`.

Comando ejecutado:

```powershell
python tools/benchmark.py --files 2000 --output docs/benchmark-results.json
```

Entorno: Python 3.10.11, Windows 10 (10.0.26200), 2000 archivos, 66109688
bytes, generado el 2026-11-23T12:59:48+00:00.

## Resultados reales

| Hilos | Tiempo (s) | MB/s | Archivos/s | Hallazgos | Aceleración vs. 1 hilo |
| ----: | ---------: | ---: | ---------: | --------: | ---------------------: |
|     1 |     2,3863 | 26,42 |     838,12 |      1948 |                  1,00× |
|     2 |     2,2431 | 28,11 |     891,64 |      1948 |                  1,06× |
|     4 |     2,2036 | 28,61 |     907,61 |      1948 |                  1,08× |
|     8 |     2,2148 | 28,47 |     903,02 |      1948 |                  1,08× |

Los cuatro escaneos procesaron los 2000 archivos y los 66109688 bytes, con
0 errores. El número de hallazgos es idéntico en todas las configuraciones,
lo que confirma que el paralelismo no altera el resultado.

## Interpretación

El paso de 1 a 2 hilos reduce el tiempo un 6 % (2,3863 s → 2,2431 s) y de 1
a 4 hilos un 8 % (2,2036 s). A 8 hilos no hay mejora adicional: el tiempo
incluso sube ligeramente (2,2148 s) respecto a 4 hilos.

Este comportamiento es esperable en archivos pequeños:

- el trabajo por archivo es mayoritariamente CPU (SHA-256, expresiones
  regulares de firmas y heurística) y el GIL impide que esos hilos ejecuten
  bytecode Python simultáneamente;
- las operaciones de lectura son cortas (1–64 KiB), así que el hilo de E/S se
  bloquea poco y queda poco tiempo solapable mientras otro hilo hace CPU;
- hay coste fijo por archivo (llamadas al sistema de archivos, creación del
  `ScanResult` parcial, envío de futuros, fusión de hallazgos y emisión de
  progreso). Con archivos de ~33 KiB de media, ese coste domina;
- a partir de 4 hilos, la contention sobre el GIL y la sobrecarga del
  `ThreadPoolExecutor` compensan la pequeña ganancia de solapamiento.

La cifra de 1948 hallazgos no indica malware real: los datos son aleatorios y
las heurísticas de entropía y puntuación marcan la mayoría de ellos. Lo
importante para el benchmark es que el recuento sea constante entre hilos.

## Recomendaciones para producción

1. Usar `--jobs 4` como punto de partida en máquinas de 4 u 8 núcleos con
   discos SSD. Es el valor con mejor tiempo medido y deja margen para el
   sistema operativo.
2. No subir por encima de 8 hilos en este tipo de carga: no aporta y consume
   más memoria y cambios de contexto. El máximo permitido por `ScanConfig` es
   64, pero está pensado para cargas con mucha más espera en E/S.
3. Mantener `--jobs 1` para árboles muy pequeños, depuración, o cuando se
   necesite un orden de progreso determinista (el modo paralelo emite los
   eventos en orden de finalización, no de entrada).
4. En unidades de red o discos con alta latencia, volver a medir: allí el
   solapamiento de E/S puede justificar 8 o más hilos.
5. Ajustar la configuración antes que los hilos cuando el cuello esté en la
   CPU: reducir `sample_size`, desactivar `hash_all` si no se necesitan hashes
   de todos los archivos, o pasar `--no-containers` en directorios sin
   archivos comprimidos.
6. Excluir de antemano directorios de caché y dependencias (`node_modules`,
   `.venv`, `__pycache__`) para no pagar el coste de archivos que no aportan
   señal.
7. Repetir la medición en el equipo de destino y con datos representativos
   antes de fijar un valor en `config.json`.

## Límites conocidos

- Una sola ejecución por configuración: no hay media, desviación típica ni
  warm-up. Diferencias inferiores al 5 % (como 4 frente a 8 hilos) no son
  estadísticamente significativas.
- Los tamaños están limitados a 1–64 KiB. Los resultados no extrapolan a
  archivos grandes, donde el hash secuencial y la lectura dominan y el
  solapamiento de E/S puede comportarse distinto.
- El árbol se crea en el directorio temporal del sistema (`%TEMP%` en
  Windows). La caché del sistema de archivos y el antivirus pueden influir;
  no se controla ni se mide ese efecto.
- No se ejercen YARA, reglas `regex` con timeout reales ni contenedores
  comprimidos (los archivos generados son `.bin`), aunque la configuración
  los tenga activados.
- No se mide consumo de memoria, uso de CPU por núcleo ni latencia por
  archivo: solo tiempo total y throughput agregado.
- El equipo de medida puede estar compartido; los números son orientativos y
  deben compararse solo entre filas de la misma ejecución.
