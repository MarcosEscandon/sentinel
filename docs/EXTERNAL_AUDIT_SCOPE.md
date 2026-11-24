# Alcance propuesto para una auditoría de seguridad externa

**Estado: propuesta.** No se ha contratado ni realizado ninguna auditoría
independiente. `sentinel audit` es una autoevaluación y no sustituye a esto.

## 1. Objetivo

Obtener una opinión independiente sobre si Sentinel cumple lo que afirma su
documentación y si un atacante con privilegios de usuario puede eludirlo,
manipular su estado persistente o convertirlo en un vector de ataque.

Preguntas que debe responder la auditoría:

1. ¿Las firmas, la allowlist y la cuarentena pueden ser manipuladas por un
   proceso con los privilegios del usuario que ejecuta el escáner?
2. ¿El análisis de contenedores, OLE y VBA es resistente a archivos hostiles
   (bombas, anidamiento, entropía, ReDoS y rutas).
3. ¿La cadena de actualizaciones Ed25519 y el anti-rollback son correctos, o
   existe una ruta para instalar una base anterior o no firmada?
4. ¿El servicio de Windows y el monitor en tiempo real amplían la superficie
   de ataque más allá de lo documentado?
5. ¿Las afirmaciones de `README.md`, `THREAT_MODEL.md` y
   `KERNEL_FILTER_DESIGN.md` son exactas, o hay controles que no existen?

## 2. Alcance inclusiones

| Componente | Qué se entrega | Énfasis |
| --- | --- | --- |
| `sentinel/engine/` | `signatures.py`, `scanner.py`, `heuristics.py`, `containers.py`, `ole.py`, `vba.py`, `yara.py` | Parsing hostil, límites anti-bomba, timeout de regex, evasión |
| `sentinel/core/` | `allowlist.py`, `quarantine.py`, `logging.py`, `database.py`, `models.py` | HMAC, ACL, inyección SQL, auto-exclusión |
| `sentinel/` raíz | `crypto.py`, `updates.py`, `integrity.py`, `audit.py`, `realtime.py`, `service.py`, `cli.py`, `gui.py`, `feeds.py`, `notify.py` | Cadena de confianza, rollback, manipulación y control del servicio |
| `packaging/` | `build.ps1`, `sentinel.spec` | Manifiesto, firma incluida, secretos en el bundle |
| `tests/` | suite completa y resultados | Cobertura de los controles de seguridad |
| Documentación | README, THREAT_MODEL, PERFORMANCE y los dos handoff | Correspondencia con el código |

## 3. Fuera de alcance

- Malware real: solo EICAR, marcadores sintéticos e IOCs públicos.
- Infraestructura de producción: no hay servidor de firmas, CA EV/OV, filtro
  de kernel ni despliegue masivo que auditar.
- Certificación formal (ISO 27001, SOC 2, Common Criteria).
- Pruebas de penetración a una red corporativa o a los sistemas del auditor.
- Revisión de dependencias de terceros: ya se entregó `pip-audit` y `bandit`,
  pero el auditor puede replicarlos.

## 4. Metodología esperada

1. **Revisión de documentación y código** (1–2 días): contraste de
   `THREAT_MODEL.md` con la implementación, buscando afirmaciones sin control.
2. **Pruebas estáticas** (0,5 días): reproducción de `ruff`, `bandit`,
   `pip-audit` y búsqueda de secretos en el historial de Git.
3. **Pruebas dinámicas en VM aislada** (2–3 días): corpus sintético de
   contenedores anidados, OLE/VBA, PE manipulado, rutas largas, archivos
   comprimidos con ratio extremo y expresiones regulares agresivas.
4. **Amenaza con privilegios de usuario** (1–2 días): intentar modificar
   `quarantine.key`, `index.json`, `audit.jsonl`, `signatures.json`, la
   allowlist o terminar el monitor; comprobar qué se detecta y qué no.
5. **Cadena de actualizaciones** (1 día): firma válida, firma corrupta,
   rollback, `file://`, URL sin host, límite de tamaño y sustitución atómica.
6. **Servicio y monitor** (1 día): instalación, home persistida, `StopEvent`,
   reconexión y comportamiento al matar el proceso de usuario.

## 5. Entregable de la auditoría

- Informe con hallazgos clasificados por severidad, CWE y prueba de concepto.
- Mapa claro de **afirmación documentada → control real → evidencia**.
- Lista de controles que el auditor considera ausentes o insuficientes.
- Recomendaciones priorizadas, distinguiendo correcciones de código de cambios
  de infraestructura (certificado, kernel, externalización).
- Carta de retest tras las correcciones.

## 6. Paquete de evidencia a entregar

- Repositorio limpio con los cuatro commits actuales y `.gitignore` efectivo.
- `python -m pytest -q` → 127 pruebas en verde.
- `python -m ruff check .` → sin avisos.
- `python -m bandit -r sentinel -x tests` → 0 avisos; `docs/bandit-results.json`.
- `pip-audit` sobre los extras → 0 vulnerabilidades;
  `docs/pip-audit-results.json`.
- `sentinel selftest` y `sentinel audit` → 100/100.
- E2E registrado: EICAR → hash y contenido → cuarentena → `verify` →
  `restore` con SHA-256 idéntico, y códigos de salida 0/1/2.
- `docs/EV_OV_HANDOFF.md` y `docs/KERNEL_FILTER_DESIGN.md` como pendientes
  explícitos, no como controles implementados.
- `git ls-files` sin claves privadas, `packaging/tools/`, `dist/` ni `build/`.

## 7. Restricciones y reglas de compromiso

- El auditor recibe el código y una VM; no necesita acceso a este equipo.
- No se facilita la clave privada Ed25519 de distribución; se genera un par
  desechable para las pruebas de actualización.
- Cualquier hallazgo que requiera malware real se sustituye por un marcador
  sintético equivalente.
- La auditoría debe declarar explícitamente qué no pudo verificar; un informe
  que solo repita `sentinel audit` no cumple el objetivo.

## 8. Cómo se usa el resultado

Los hallazgos confirmados se convierten en issues con prueba de concepto y
prueba de regresión antes de cerrarse. Los documentos `README.md` y
`THREAT_MODEL.md` se actualizan con el resultado, incluidos los límites que la
auditoría confirme. **Una auditoría externa tampoco convierte al prototipo en
un producto certificado**: siguen pendientes el certificado EV/OV, el filtro
de kernel y una base de firmas comercial.
