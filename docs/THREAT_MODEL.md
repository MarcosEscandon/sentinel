# Modelo de amenazas de Sentinel (prototipo)

Este documento describe qué protege hoy Sentinel, qué no protege y qué queda
pendiente. Se basa en el código del repositorio, no en un producto certificado.
**No hay control de kernel ni verificación de confianza de ejecutables**: el
escáner es un proceso de usuario que lee archivos y aplica reglas.

## Alcance

- Python 3.10, objetivo Windows; los módulos puros funcionan también en otros SO.
- Análisis bajo demanda (`scan`), monitorización en tiempo real (`monitor` /
  servicio de Windows opcional) y cuarentena reversible.
- Base de firmas JSON (`sentinel/data/signatures.json`, revisión 3) con 11
  hashes (EICAR y diez IOCs públicos) y 2 reglas de contenido, una de ellas
  sintética (`SENTINEL_TEST_MARKER`), con firma `.sig` y clave pública `.pub`.
- Autoevaluación `sentinel/audit.py`, integrada como subcomando `sentinel audit`
  (diez comprobaciones).

Fuera de alcance: protección contra un atacante que ya es administrador,
prevención de ejecución, sandboxing, reputación en la nube y respuesta
automática a incidentes.

## Activos

| Activo | Ubicación / forma | Por qué importa |
| --- | --- | --- |
| Base de firmas | `signatures.json`, revisión, hashes y reglas | Define qué se detecta; manipularla genera falsos negativos |
| Firma y ancla de confianza | `<base>.sig`, clave pública PEM | Cadena de confianza de las actualizaciones |
| Clave de cuarentena | `<home>/quarantine.key` (HMAC-SHA256) | Detecta manipulación del índice de cuarentena |
| Cuarentena | `<home>/quarantine/index.json`, `files/*.qtn` | Contiene malware real; su integridad decide si una restauración es segura |
| Registro de auditoría | `<home>/audit.jsonl` | Evidencia de escaneos, hallazgos y acciones |
| Historial | `<home>/history.db` (SQLite) | Resultados y métricas pasadas |
| Exclusiones | `allowlist.json` y `AllowList.for_self()` | Evitan falsos positivos y auto-detección; también pueden ocultar malware |
| Configuración del escáner | `--config-file` / `ScanConfig` | Límites anti-bomba; valores erróneos permiten abusos de recursos |
| Código y dependencias instaladas | paquete `sentinel`, extras opcionales | Superficie de *supply chain* |
| Servicio y monitor | `RealtimeMonitor`, servicio de Windows | Proceso con acceso continuo a las rutas vigiladas |

## Actores

- **Usuario local**: ejecuta escaneos, puede configurar exclusiones y restaurar
  archivos de la cuarentena si tiene acceso a la home.
- **Proceso malicioso con privilegios del usuario**: puede escribir en la home,
  borrar logs, modificar la allowlist o terminar el proceso del monitor.
- **Administrador local**: puede instalar el servicio, cambiar ACLs y parar la
  protección; asumir lo contrario sería engañarse.
- **Atacante que entrega archivos** (descargas, correo, USB): controla el
  contenido analizado, no el equipo.
- **Atacante de red / servidor de actualizaciones**: puede servir un JSON
  modificado o una revisión antigua si la cadena de confianza falla.
- **Operador/auditor**: consume informes y decide si el equipo puede operar.

## Superficie de ataque

1. **Datos analizados**: PE (`engine/heuristics.py`), OLE2/CFB (`engine/ole.py`),
   ZIP/TAR/GZ/BZ2/XZ
   (`engine/containers.py`), OLE, expresiones regulares de contenido, reglas
   YARA opcionales y cálculo de entropía.
2. **Rutas**: symlinks, junctions y reparse points; rutas relativas, nombres
   largos y directorios excluidos.
3. **Archivos de configuración**: JSON de firmas, feeds importados
   (`feeds.py`), allowlist, `ScanConfig` y `config.example.json`.
4. **Canal de actualización**: HTTP/HTTPS y firma separada
   (`updates.py`).
5. **Estado persistente**: índice y clave de cuarentena, `audit.jsonl`,
   `history.db`, informes JSON.
6. **Interfaz y servicio**: GUI tkinter, notificaciones y servicio de Windows.

## Amenazas mitigadas (controles que existen realmente)

| Amenaza | Control implementado | Dónde | Límite honesto |
| --- | --- | --- | --- |
| Malware conocido por hash/contenido/nombre | Coincidencia de SHA-256, regex sobre bytes y nombres | `engine/signatures.py` | Solo cubre lo que contenga la base; no hay detección en la nube |
| Archivo EICAR/IOC sintético de prueba | Hash y regla de contenido incluidos | `data/signatures.json` | Es una prueba funcional, no cobertura de malware real |
| Ofuscación por contenedores | Descompresión con límites de entradas, tamaño, ratio y profundidad | `engine/containers.py`, `ScanConfig` | No analiza formatos anidados más allá de `container_max_depth` |
| ReDoS en reglas de contenido | `regex` con `timeout` por regla y envío de `RULE-TIMEOUT` | `engine/signatures.py` | Sin el extra `hardening` se usa `re`, sin límite de tiempo |
| Bucles y evasión por enlaces | `follow_symlinks=False` y rechazo de reparse points en el monitor nativo | `config.py`, `realtime.py` | La decisión depende de las API de Windows disponibles |
| Auto-detección del propio producto | `AllowList.for_self([home, raíz del paquete])` | `core/allowlist.py`, CLI | Una allowlist mal editada puede eximir rutas maliciosas |
| Modificación del índice de cuarentena | HMAC-SHA256 con clave fuera del directorio y `verify_all()` | `core/quarantine.py` | La clave se guarda en texto plano; un atacante con acceso a la home puede leerla y recalcular el MAC |
| Restauración de un archivo alterado | `verify_entry()` compara tamaño y SHA-256 almacenado | `core/quarantine.py` | No cifra el contenido; `delete()`/`prune()` siguen funcionando aunque haya alteración |
| Rollback de firmas | `check_rollback()` y revisión creciente en actualizaciones | `engine/signatures.py`, `updates.py` | `SignatureDatabase.load()` por sí solo **no** exige firma ni revisión |
| Actualización no firmada o corrupta | Firma Ed25519 obligatoria con clave pública, hash opcional y sustitución atómica con `.bak` | `updates.py` | La clave pública se distribuye a mano; no hay rotación, pinning por builds ni Transparency Log |
| Errores de parseo de un archivo hostile | Captura de errores por archivo y límites de tamaño | `engine/scanner.py`, `ScanConfig` | Un error se registra como `errors`, no mata el escaneo |
| Pérdida de visibilidad | Eventos JSONL de escaneo, hallazgos, cuarentena y comandos | `core/logging.py` | Sin firma, cifrado, rotación ni retención inmutable |
| Configuración insegura detectada tarde | `audit.py` valida base, firma, cuarentena, logs, exclusiones, backend y límites | `sentinel/audit.py` | Es una comprobación puntual, no un control en tiempo de ejecución |

## Amenazas pendientes o no mitigadas

- **Filtro de kernel**: no existe. `RealtimeMonitor` usa
  `ReadDirectoryChangesW`, `watchdog` o sondeo desde espacio de usuario. Un
  atacante con el mismo privilegio puede terminar el proceso, saturar la cola o
  actuar antes de que venza el *grace period*. No hay prevención de ejecución.
  La propuesta de minifiltro está en `docs/KERNEL_FILTER_DESIGN.md`.
- **Authenticode**: no se comprueba la firma de los PE. Un binario firmado por
  una entidad legítima o robada se analiza como cualquier otro archivo; no hay
  listas de editores de confianza ni reputación.
- **Desofuscación de macros**: `engine/ole.py` extrae flujos OLE y
  `engine/vba.py` descomprime el proyecto MS-OVBA para aplicar reglas `VBA-*`,
  pero no interpreta macros, no desofusca estrategias arbitrarias y no hay
  sandbox. Un documento con código ofuscado puede evadir las reglas.
- **Supply chain de firmas**: la clave privada se genera en disco
  (`crypto.generate_keypair`) sin cifrado ni HSM. La clave pública se entrega
  manualmente con `--public-key`; no hay pinning, cadena de certificados,
  rotación ni firma de la propia herramienta. La base incluida sí lleva
  `signatures.json.sig` y `signatures.json.pub`, pero `SignatureDatabase.load()`
  no los exige: una instalación que copie solo `signatures.json` carga sin
  verificar localmente. `SENTINEL_PUBLIC_KEY` / `signing.pub` es la convención
  que usa `audit.py` para comprobar esa firma.
- **Falsos positivos**: las reglas `SENTINEL_TEST_MARKER` y la heurística de
  entropía son sintéticas. La auto-exclusión cubre directorios completos, así
  que una exclusión mal puesta crea un punto ciego. No hay *sandbox*,
  reputación ni confirmación por proveedor.
- **Permisos en Windows**: `os.stat` no expone ACLs y suele mostrar modo `0666`
  incluso con una ACL restrictiva. `quarantine.key_permissions` declara
  explícitamente la limitación y **nunca cambia permisos**: la ACL debe
  revisarse con `icacls`.
- **Persistencia del atacante**: `audit.jsonl`, `history.db` y los informes no
  están firmados; un usuario con acceso a la home puede borrarlos o editarlos.
- **Cuarentena**: los archivos se renombran a UUID, no se cifran. Cualquier
  proceso del usuario puede leerlos directamente desde `quarantine/files`.

## Uso de la autoevaluación

El flujo mínimo es:

```powershell
# 1. Generar claves (la privada debe quedar fuera del equipo escaneado).
sentinel keys generate --private C:\seguro\private.pem --public C:\seguro\public.pem

# 2. Firmar la base instalada (la ruta global --signatures va antes del subcomando).
sentinel --signatures C:\ProgramData\Sentinel\signatures.json signatures sign `
  --key C:\seguro\private.pem `
  --output C:\ProgramData\Sentinel\signatures.json.sig

# 3. Configurar el ancla de confianza para la auditoría.
$env:SENTINEL_PUBLIC_KEY = 'C:\ProgramData\Sentinel\signing.pub'

# 4. Ejecutar la autoevaluación: salida 0 si todo pasa, 2 si hay fallos.
sentinel audit
```

`run_security_audit(home, signatures)` devuelve `SecurityAudit` con diez checks:

| Check | Qué comprueba |
| --- | --- |
| `signatures.valid` | Carga/validación de la base y revisión entera > 0 |
| `signatures.signed` | Firma `.sig` Ed25519 con la clave pública configurada |
| `quarantine.integrity` | MAC e hashes de todas las entradas; "sin entradas" si no hay índice |
| `quarantine.key_permissions` | Bits de lectura de `quarantine.key`; limitación de ACL documentada en Windows |
| `logging.enabled` | Escritura y posterior lectura de un evento `audit.check` en JSONL válido |
| `allowlist.self` | Auto-exclusión no vacía y aplicable a la home |
| `realtime.backend` | Backend no-polling en Windows; `polling` en otros SO |
| `config.sane` | Límites anti-bomba > 0 y `container_max_depth >= 1` |
| `home.location` | Home fuera de `Windows` / `Program Files`; `ProgramData` permitido |
| `iocs.minimum` | Al menos un hash y una regla de contenido |

Las excepciones se convierten en fallos con el mensaje en `detail`; la
puntuación es el porcentaje de checks superados. **Un 100/100 no implica que
el equipo esté libre de malware**: solo dice que estos controles están
presentes y son coherentes. El alcance de una revisión independiente está en
`docs/EXTERNAL_AUDIT_SCOPE.md`.

## Análisis estático del código

Además de la autoevaluación en tiempo de ejecución se ejecutaron:

* `python -m ruff check .`: sin avisos.
* `python -m bandit -r sentinel -x tests`: **0 avisos** sobre 6026 líneas
  (`docs/bandit-results.json`). Bandit señaló tres puntos que se corrigieron en
  lugar de silenciarse: la consulta SQL con marcadores dinámicos en
  `database.mark_quarantined()` se sustituyó por SQL estático con parámetros
  enlazados; un `assert` en el backend nativo se cambió por una comprobación
  explícita; y `updates._download()` valida ahora el esquema `http`/`https`
  antes de llamar a `urlopen`; la alerta residual de Bandit sobre esa llamada
  se documentó con `# nosec B310` porque el esquema ya está restringido. Las
  pruebas de actualización simulan HTTPS con `urlopen` falsificado en lugar de
  usar `file://`.
* `git ls-files`: ni la clave privada (`packaging/keys/private.pem`), ni
  `packaging/tools/`, ni `dist/`, `build/` o la home de pruebas están
  versionados.
* Análisis de dependencias (SCA) con `pip-audit` sobre los extras declarados
  en `pyproject.toml` (24 paquetes resueltos): **0 vulnerabilidades**
  (`docs/pip-audit-results.json`). El entorno principal quedó con 44 paquetes
  y 0 vulnerabilidades tras retirar la herramienta de auditoría.
  `setuptools` se actualizó a 84.2.1. La herramienta SCA se ejecutó en un venv
  aislado con Python 3.14: en Python 3.10 su dependencia transitiva `filelock`
  no tiene versión corregida (el arreglo exige ≥3.11), por lo que no se añadió
  `pip-audit` a los extras `dev`.

Esto no sustituye a una revisión externa: `bandit` detecta patrones inseguros y
`pip-audit` compara versiones con bases de vulnerabilidades; ninguno encuentra
fallos lógicos ni garantiza la seguridad del producto.

## Checklist de despliegue

- [ ] Instalar la home en `%ProgramData%\Sentinel` (o carpeta del usuario con
      ACL restrictiva), nunca bajo `C:\Windows` o `C:\Program Files`.
- [ ] Aplicar la ACL manualmente con `icacls` a la home, `quarantine.key` y
      `quarantine/`; verificar quién puede leer y escribir.
- [ ] Guardar la clave privada fuera del equipo (o en un almacén protegido) y
      distribuir la pública por un canal verificado.
- [ ] Firmar `signatures.json` y comprobar que existe `<base>.sig` con 64 bytes.
- [ ] Configurar `SENTINEL_PUBLIC_KEY` (o `signing.pub`) antes de auditar.
- [ ] Actualizar solo mediante `sentinel signatures update --public-key ...`
      con HTTPS y, si es posible, `--sha256`; revisar revisiones y `.bak`.
- [ ] Ejecutar `sentinel audit` y exigir salida 0, puntuación 100 y cero
      `failures`; investigar cada `remediation` antes de aceptar excepciones.
- [ ] Verificar `sentinel quarantine verify` y la integridad de `audit.jsonl`.
- [ ] Revisar `allowlist.json` y documentar cada exclusión con responsable y
      fecha de caducidad.
- [ ] Confirmar que en Windows está disponible un backend no-polling y que el
      servicio se ejecuta con la cuenta mínima necesaria.
- [ ] Probar EICAR en un entorno aislado, incluida la restauración desde
      cuarentena, y comprobar que no se generan falsos positivos inaceptables.
- [ ] Seguir `docs/EV_OV_HANDOFF.md` para obtener el certificado EV/OV, firmar
      el release y coordinar la regla de AppLocker/WDAC; adjuntar la evidencia.
- [ ] Contratar la auditoría externa con `docs/EXTERNAL_AUDIT_SCOPE.md` y cerrar
      los hallazgos con prueba de regresión antes de aceptar el informe.
- [ ] Registrar como pendientes el filtro de kernel, la desofuscación
      arbitraria de macros y la rotación de claves de firmas.
