# Diseño de filtro de sistema de archivos a nivel kernel

**Estado: propuesta arquitectónica.** No hay código de driver en este
repositorio, no se ha compilado con WDK y no se ha instalado nada en el kernel.
El monitor actual (`realtime.py`) sigue siendo de modo usuario.

## 1. Qué resuelve y qué no

El monitor actual usa `ReadDirectoryChangesW` (o `watchdog`/sondeo), con un
buffer de 64 KiB. Un proceso con los mismos privilegios puede terminarlo,
desbordar la cola o ejecutar el archivo antes de que venza el *grace period*.

Un minifiltro permitiría:

- Observar `IRP_MJ_CREATE`, `IRP_MJ_WRITE` y renombrados antes de que el archivo
  se ejecute.
- Negar la ejecución de un binario mientras el usuario decide, en lugar de
  limitarse a moverlo a cuarentena después.
- Proteger el proceso, su home y su base de firmas frente a terminates y
  escrituras de otros procesos del mismo usuario.

**No** resuelve: un atacante con privilegios de administrador (puede descargar
o desactivar el filtro), malware que ya se ejecutaba antes de instalarlo, ni
detección por sí mismo. Sigue siendo necesaria la base de firmas y el análisis.

## 2. Arquitectura propuesta

```text
            IRP_MJ_CREATE / WRITE / SET_INFORMATION
 Archivos ───────────────────────────────────────────► [FltMgr]
                                                         │
                                                         ▼
                                              [sentinel-filter.sys]
                                     (minifiltro C/WDK, PASSIVE_LEVEL)
                                                         │ FltSendMessage
                                     puerto \SentinelFilterPort (ACL SYSTEM)
                                                         │ FilterGetMessage /
                                                         │ FilterReplyMessage
                                                         ▼
                                       [sentinel service / monitor]
                              kernel_bridge.py (ctypes → FltLib.dll)
                                                         │
                    ┌────────────────────────────────────┼────────────────┐
                    ▼                                    ▼                ▼
          core/allowlist.py                     engine/scanner.py   core/quarantine.py
          core/logging.py                       (hash + reglas)     (SHA-256 + HMAC)
```

Componentes:

1. **`sentinel-filter.sys`**: minifiltro registrado con `FltRegisterFilter`.
   Se instancia en volúmenes locales; por defecto no sigue redireccionamientos
   de red. Su única responsabilidad es observar, enviar mensajes y aplicar el
   veredicto que recibe.
2. **Puerto de comunicación**: creado con `FltCreateCommunicationPort` y un
   nombre global (`\SentinelFilterPort`). La ACL del objeto se construye con
   `FltBuildDefaultSecurityDescriptor` y se restringe a `SYSTEM` (y quizá
   `Administrators` solo en builds de prueba). `MaxConnections = 2` para
   permitir el servicio y una consola de diagnóstico.
3. **`kernel_bridge.py`**: nueva capa de Python sin dependencias obligatorias,
   usando `ctypes` sobre `FltLib.dll` (`FilterConnectCommunicationPort`,
   `FilterGetMessage`, `FilterReplyMessage`, `FilterSendMessage`). Reutiliza la
   lógica existente de `RealtimeMonitor.process_path()`.
4. **Worker de análisis**: recibe la ruta, aplica la allowlist, calcula el
   hash, ejecuta las reglas y devuelve `ALLOW`, `DETECT` o `QUARANTINE`.

## 3. Contrato de mensajes

Cabecera fija y campos de longitud explícita; versión y *magic* para rechazar
clientes incompatibles. Toda cadena se envía en UTF-16LE con longitud en
bytes. Ningún mensaje supera 64 KiB; las rutas largas se truncan con un flags.

| Tipo | Origen | Contenido | Respuesta |
| --- | --- | --- | --- |
| `HELLO` | usuario → kernel | versión, PID, nombre del proceso | `HELLO_ACK` con versión y *altitude* |
| `SCAN_REQUEST` | kernel → usuario | `request_id`, PID, ruta del proceso, volumen, ruta del archivo, `DesiredAccess`, flags | `SCAN_VERDICT` con el mismo `request_id` |
| `SCAN_VERDICT` | usuario → kernel | `request_id`, `ALLOW`/`BLOCK`/`QUARANTINE`, motivo | — |
| `CONFIG_UPDATE` | usuario → kernel | rutas excluidas, modo (audit/enforce), tamaño máximo | ACK |
| `HEARTBEAT` | ambos | contador, cola pendiente, pérdidas | ACK |
| `SHUTDOWN` | usuario → kernel | motivo | — |

Reglas del protocolo:

- `request_id` es un `UINT64` monótono; respuestas duplicadas o desconocidas se
  ignoran.
- Si el puente no responde en un plazo configurable (por ejemplo 5 s), el
  driver aplica la política *fail-open*/*fail-closed* descrita abajo y emite un
  evento de error.
- El driver **nunca** confía en una ruta relativa: la convierte a nombre NT
  completo (`\Device\HarddiskVolumeX\...`) antes de enviarla.

## 4. Decisiones de diseño

| Decisión | Elección | Razón |
| --- | --- | --- |
| Punto de intercepción | `IRP_MJ_CREATE` con `DesiredAccess` que incluya `EXECUTE` para bloquear; `IRP_MJ_WRITE`/`CLEANUP` para escanear después de cerrar | Evita analizar cada lectura y permite frenar ejecuciones |
| Modo de la llamada | `FltSendMessage` solo a `PASSIVE_LEVEL`, con timeout; nunca en una ruta de paging | Evita deadlocks y IRQL inválido |
| Cola llena | Fail-closed para `EXECUTE`, fail-open para lecturas/escrituras, siempre con evento `realtime.error` | Un antivirus no debe dejar de arrancar el sistema, pero sí debe impedir la ejecución dudosa |
| Falsos positivos | Modo `audit` por defecto; `enforce` solo después de ajustar la allowlist | El prototipo ya genera heurística falsa sobre datos aleatorios |
| *Altitude* | Rango anti-virus 320000–329999, asignado por Microsoft para producción | No se debe elegir un valor arbitrario en un despliegue real |
| Protección propia | Reglas de deny para escritura/terminación sobre la home, el exe y los Servicios del monitor | La clave de cuarentena y los logs están en la home |
| Renombrados | `IRP_MJ_SET_INFORMATION` con `FileRenameInformation` para mantener el contexto | Un rename puede eludir una regla de nombre |
| Exclusiones | La allowlist se envía al driver solo como filtro grueso por prefijo; la decisión final siempre está en usuario | Evita duplicar reglas y simplifica actualizaciones |

## 5. Integración con el código actual

- El userService existente (`service.py`) crea el puente y mantiene un hilo de
  lectura del puerto; no se sustituye `RealtimeMonitor`, sino que se añade un
  backend `native-kernel` seleccionable con `--backend`.
- `process_path()` sigue siendo el único punto que decide cuarentena y
  notificación; el driver solo ejecuta el veredicto. Así se conservan
  `audit.jsonl`, `history.db`, HMAC de cuarentena y los códigos de salida.
- La auto-exclusión de `AllowList.for_self()` se amplía con los archivos del
  propio driver (`sentinel-filter.sys`, `.inf`, catálogo) para no auto-detectarse.
- `sentinel audit` añadiría un check `realtime.driver` que compruebe que el
  servicio está conectado al puerto; en modo usuario seguiría pasando con
  `realtime.backend`.

## 6. Seguridad del canal

- El puerto solo acepta `SYSTEM`; el servicio de Windows se ejecuta con esa
  cuenta. La consola de diagnóstico requiere administrador.
- El `HELLO` incluye PID y ruta del proceso; el driver verifica que el PID
  coincide con el token del extremo conectado y rechaza clientes no autorizados.
- Los mensajes llevan *magic*, versión y longitud: un proceso que escriba bytes
  arbitrarios al puerto no puede fabricar un veredicto sin la ACL.
- El driver no realiza E/S de archivo ni cálculo de hash; solo pasa
  información. Eso reduce el código en kernel y su superficie de fallos.
- Si se implementa cifrado del canal, la clave debe derivarse del token del
  proceso conectado, no guardarse en un archivo.

## 7. Firma y distribución

Un driver de kernel **no** se puede firmar solo con el certificado EV/OV del
exe: desde Windows 10 1607, los drivers nuevos deben pasar por el portal de
Windows Hardware Dev Center. El EV es necesario para crear la cuenta del
programa; después:

1. Desarrollar con WDK y probar con *test signing* en una VM aislada ( nunca
   en producción).
2. Ejecutar el *Hardware Lab Kit* (HLK) para las versiones de Windows
   soportadas y reunir los logs.
3. Enviar el paquete al portal para **WHQL** (producción) o *attestation
   signing* (pruebas en cliente). El resultado es un `.sys` firmado por
   Microsoft o un catálogo aceptado por Code Integrity.
4. Instalar con un INF/catálogo firmado, nunca con `sc create` de un binario
   sin firmar. Verificar con `Get-AuthenticodeSignature` y los eventos de
   `Microsoft-Windows-CodeIntegrity/Operational`.

Esto es una barrera externa importante: añade WDK/C++, HLK, cuenta de hardware
y firma de Microsoft. No puede hacerse desde este repositorio Python.

## 8. Plan de pruebas y evidencia

- **VM aislada** con Versiones de Windows objetivo, Secure Boot activado y
  Driver Verifier (`/standard`).
- HLK completo y sin fallos; captura de logs y del paquete enviado al portal.
- EICAR y marcadores sintéticos: crear, ejecutar y renombrar; comprobar que el
  veredicto llega antes de la ejecución en modo `enforce`.
- Estrés: miles de archivos y procesos concurrentes; medir pérdidas de
  mensajes, latencia p99 y ausencia de deadlocks.
- Resiliencia: matar el proceso de usuario y reconectar; el driver debe degradar
  según la política y nunca dejar el sistema sin I/O.
- Auto-protección: intentar terminar el servicio y borrar la home desde otro
  proceso del mismo usuario; revisar `audit.jsonl`.
- Falsos positivos: ejecutar el benchmark y la suite de tests; revisar que las
  exclusiones evitan auto-detección.
- Recuperación: desinstalar el filtro y confirmar que el monitor de modo
  usuario sigue funcionando.

## 9. Riesgos abiertos

- Un bug en el driver puede causar BSOD; por eso el desarrollo exige VM,
  Driver Verifier y firma WHQL antes de cualquier despliegue.
- Bloquear en la ruta de `CREATE` puede provocar deadlocks si el análisis
  intenta abrir el mismo archivo; el diseño propuesto evita E/S en kernel, pero
  debe validarse con pruebas de estrés.
- La *altitude* y las reglas de auto-protección requieren coordinación con el
  administrador del equipo; una mala combinación con otros antivirus puede
  interferir.
- Incluso con filtro, un administrador puede desactivarlo: el modelo de
  amenazas de `THREAT_MODEL.md` sigue siendo válido.

## Referencias

- FltMgr: `FltRegisterFilter`, `FltCreateCommunicationPort`, `FltSendMessage`,
  `FltBuildDefaultSecurityDescriptor` (WDK / `fltkernel.h`).
- FltLib: `FilterConnectCommunicationPort`, `FilterGetMessage`,
  `FilterReplyMessage`, `FilterSendMessage` (`fltuser.h`, `FltLib.dll`).
- *Driver Signing Policy* y WHCP: documentación de Microsoft Hardware Dev
  Center.
- Alturas de filtros del sistema de archivos: documentación de Filter Manager
  (rango anti-virus 320000–329999).
