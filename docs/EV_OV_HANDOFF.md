# Handoff: certificado EV/OV y confianza en Windows

Este documento es un **procedimiento de entrega**, no una verificación
realizada: en este entorno no se compró ningún certificado ni se modificó la
política de Device Guard. Describe exactamente qué falta y cómo hacerlo.

## 1. Estado actual

| Elemento | Situación hoy |
| --- | --- |
| Firma Authenticode | `dist\sentinel.exe` está firmado con un certificado **autofirmado de prueba** (`CN=Sentinel Test (self-signed)`, thumbprint `C73298594AF271C492DB91FAF35123B755E86F74`). |
| Verificación local | Añadiendo ese certificado a `CurrentUser\Root` y `TrustedPublisher` se consiguió `signtool verify /pa` sin errores; se retiró justo después. |
| Device Guard / WDAC | En una sesión posterior, el exe fue bloqueado por Application Control (`cmd` devuelve `4551`). Confiar el certificado solo al usuario **no bastó**. |
| Manifiesto interno | `manifest.json` y sus datos se firman con Ed25519 mediante `SENTINEL_PRIVATE_KEY`; es independiente de Authenticode. |
| Código | `packaging/build.ps1 -Sign` ya selecciona el certificado por `SENTINEL_CERT_THUMBPRINT` (o `SENTINEL_CERT_SUBJECT`) y aplica `/fd SHA256 /tr <URL> /td SHA256`. |

Conclusión: el pipeline de firma está listo; falta un certificado de una CA
pública de confianza y que TI actualice la política de control de aplicaciones.

## 2. EV frente a OV

| | EV (Extended Validation) | OV (Organization Validation) |
| --- | --- | --- |
| Identidad | Valida persona jurídica con verificación estricta | Valida organización, con menos rigor |
| Clave privada | Obligatoria en token/HSM no exportable (o servicio de firma remota) | Puede entregarse en PFX; aún así conviene HSM |
| SmartScreen | Reputación inmediata al firmar | Hay que acumular reputación (descargas, reporte a Microsoft) |
| Coste / plazo | Más caro y lento | Más barato y rápido |
| Recomendación | **Preferido** para un antivirus que se descarga desde internet | Aceptable solo con plan de reputación y control de WDAC |

Emisores habituales: DigiCert, Sectigo, GlobalSign, Entrust (o revendedores
autorizados). Se requiere entidad legal, datos de contacto verificables y,
para EV, token físico e instalación de su middleware.

## 3. Emisión e instalación del certificado

1. Solicitar el certificado indicando que será para **code signing de un
   ejecutable Windows x64**. En EV, la clave se genera dentro del token; en
   OV, seguir las instrucciones de la CA para el CSR e importar el PFX.
2. **Nunca** copiar la clave privada al repositorio ni a `packaging/keys/`.
   Esa carpeta ya está excluida por `.gitignore` y solo debe contener la clave
   Ed25519 del manifiesto, distinta de la clave Authenticode.
3. Conectar el token (EV) e importar el certificado en el almacén del usuario:

   ```powershell
   Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
       Select-Object Subject, Thumbprint, NotAfter
   ```

4. Guardar el thumbprint sin espacios y la URL de timestamp RFC 3161 que
   publique la CA. El script usa `http://timestamp.digicert.com` por defecto;
   conviene sobrescribirlo con `SENTINEL_TIMESTAMP_URL`.

## 4. Firma del release

```powershell
$env:SENTINEL_CERT_THUMBPRINT = '<THUMBPRINT_SIN_ESPACIOS>'
$env:SENTINEL_TIMESTAMP_URL   = '<URL_RFC3161_DE_LA_CA>'
$env:SENTINEL_PRIVATE_KEY     = 'C:\seguro\signing-ed25519.pem'  # solo manifiesto

# Release: sin -Console (la consola se usó únicamente para validar aquí).
.\packaging\build.ps1 -Sign
```

Si hay que firmar un exe ya generado:

```powershell
signtool sign /fd SHA256 /tr $env:SENTINEL_TIMESTAMP_URL /td SHA256 `
  /sha1 $env:SENTINEL_CERT_THUMBPRINT dist\sentinel.exe
```

Verificación obligatoria:

```powershell
signtool verify /pa /v dist\sentinel.exe
Get-AuthenticodeSignature -LiteralPath dist\sentinel.exe |
    Format-List Status, StatusMessage, SignerCertificate
```

`Status` debe ser `Valid` y `StatusMessage` debe indicar que la cadena termina
en una raíz de confianza. Sin timestamp, la firma deja de ser válida cuando
caduca el certificado: el build siempre debe usar `/tr` **y** `/td SHA256`.

## 5. Confianza en AppLocker / Device Guard

Con un certificado EV/OV, la CAD raíz ya está en el almacén de Windows, así
que **no hay que añadir nada a `Root` ni a `TrustedPublisher`**. Lo que sí
puede hacer falta es una regla que permita el binario en la política de
control de aplicaciones.

### AppLocker

Ejecutar en una sesión con administrador y revisar el XML antes de aplicarlo:

```powershell
Get-AppLockerFileInformation -Path .\dist\sentinel.exe |
    New-AppLockerPolicy -RuleType Publisher -User Everyone -XML |
    Set-Content .\sentinel-publisher.xml -Encoding UTF8

Test-AppLockerPolicy -XmlPolicy .\sentinel-publisher.xml -Path .\dist\sentinel.exe
Set-AppLockerPolicy -XmlPolicy .\sentinel-publisher.xml -Merge
```

La regla `Publisher` sigue siendo válida en versiones futuras firmadas por el
mismo certificado; una regla de hash habría que regenerarla en cada release.

### WDAC / App Control for Business

Trabajar con el equipo de TI y empezar en modo auditoría:

```powershell
# Directorio que contenga solo el exe firmado.
New-CIPolicy -MultiplePolicyFormat -Level Publisher -UserPEs `
  -FilePath .\sentinel-supplemental.xml -ScanPath .\dist
ConvertFrom-CIPolicy .\sentinel-supplemental.xml .\sentinel-supplemental.bin
```

Desplegar el `.bin` con Intune, GPO o `CiTool`, dejarlo primero en auditoría y
revisar `Microsoft-Windows-CodeIntegrity/Operational` antes de imponerlo.
`-Level Publisher` es preferible a `Hash`: no exige reemitir la política en
cada build. Si se usa `FilePublisher`, conviene fijar una versión mínima.

**No** resolver el bloqueo actual añadiendo el certificado autofirmado a los
almacenes del usuario: eso solo funciona para `signtool verify`, no para una
política WDAC en modo imposición.

## 6. Evidencia a entregar con el release

- Subject, emisor, thumbprint, fecha de caducidad y huella de la CA.
- Salida completa de `signtool verify /pa /v` y de `Get-AuthenticodeSignature`.
- URL de timestamp y confirmación de que el sello es RFC 3161 con SHA-256.
- XML de la regla de AppLocker o la política suplementaria de WDAC.
- Resultado de `Test-AppLockerPolicy` / eventos de Code Integrity en modo
  auditoría.
- Prueba en una VM limpia, fuera del equipo de desarrollo: descarga del exe,
  ejecución de `--version`, `sentinel selftest`, escaneo de EICAR y cuarentena.
- Para OV: captura del diálogo de SmartScreen tras la descarga y plan de
  reputación (informe a Microsoft Defender for Endpoint / SmartScreen).
- Verificación del manifiesto Ed25519 incluido:

  Solo en un build onedir (`-OneFile:$false`):

  ```powershell
  sentinel integrity verify _internal\sentinel\data `
    --manifest _internal\sentinel\data\manifest.json `
    --public-key _internal\sentinel\data\signatures.json.pub
  ```

  En el build onefile por defecto no hay `_internal`; verifica la copia de
  `sentinel/data` del árbol de fuentes.

## 7. Límites que este handoff no resuelve

Un certificado EV/OV elimina el bloqueo por confianza y mejora SmartScreen,
pero **no** convierte al prototipo en un antivirus production-ready: siguen
pendientes el filtro de sistema de archivos a nivel kernel, la auditoría
externa independiente, una base de firmas comercial y la rotación de claves.
Estos límites están descritos en `README.md` y `docs/THREAT_MODEL.md`.
