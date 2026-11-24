# Handoff: EV/OV certificate and trust on Windows

This document is a **handoff procedure**, not a verification already performed:
no certificate was purchased and no Device Guard policy was modified in this
environment. It describes exactly what is missing and how to do it.

## 1. Current status

| Item | Situation today |
| --- | --- |
| Authenticode signature | `dist\sentinel.exe` is signed with a **self-signed test certificate** (`CN=Sentinel Test (self-signed)`, thumbprint `C73298594AF271C492DB91FAF35123B755E86F74`). |
| Local verification | Adding that certificate to `CurrentUser\Root` and `TrustedPublisher` achieved `signtool verify /pa` without errors; it was removed immediately afterwards. |
| Device Guard / WDAC | In a later session, the exe was blocked by Application Control (`cmd` returned `4551`). Trusting the certificate for the current user alone **was not enough**. |
| Internal manifest | `manifest.json` and its data are signed with Ed25519 via `SENTINEL_PRIVATE_KEY`; this is independent of Authenticode. |
| Code | `packaging/build.ps1 -Sign` already selects the certificate by `SENTINEL_CERT_THUMBPRINT` (or `SENTINEL_CERT_SUBJECT`) and applies `/fd SHA256 /tr <URL> /td SHA256`. |

Conclusion: the signing pipeline is ready; what is missing is a certificate from
a trusted public CA and an application control policy update by IT.

## 2. EV vs. OV

| | EV (Extended Validation) | OV (Organization Validation) |
| --- | --- | --- |
| Identity | Validates a legal entity with strict verification | Validates an organization, with less rigor |
| Private key | Mandatory on a non-exportable token/HSM (or remote signing service) | May be delivered as a PFX; an HSM is still advisable |
| SmartScreen | Immediate reputation upon signing | Reputation must be accumulated (downloads, report to Microsoft) |
| Cost / lead time | More expensive and slower | Cheaper and faster |
| Recommendation | **Preferred** for an antivirus downloaded from the internet | Acceptable only with a reputation plan and WDAC control |

Common issuers: DigiCert, Sectigo, GlobalSign, Entrust (or authorized
resellers). A legal entity, verifiable contact details and, for EV, a physical
token and its middleware installed are required.

## 3. Certificate issuance and installation

1. Request the certificate specifying that it will be used for **code signing of
   a Windows x64 executable**. For EV, the key is generated inside the token;
   for OV, follow the CA's instructions for the CSR and import the PFX.
2. **Never** copy the private key to the repository or to `packaging/keys/`.
   That folder is already excluded by `.gitignore` and should only contain the
   Ed25519 key for the manifest, which is different from the Authenticode key.
3. Connect the token (EV) and import the certificate into the user store:

   ```powershell
   Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
       Select-Object Subject, Thumbprint, NotAfter
   ```

4. Save the thumbprint without spaces and the RFC 3161 timestamp URL published
   by the CA. The script uses `http://timestamp.digicert.com` by default; it is
   advisable to override it with `SENTINEL_TIMESTAMP_URL`.

## 4. Release signing

```powershell
$env:SENTINEL_CERT_THUMBPRINT = '<THUMBPRINT_NO_SPACES>'
$env:SENTINEL_TIMESTAMP_URL   = '<CA_RFC3161_URL>'
$env:SENTINEL_PRIVATE_KEY     = 'C:\secure\signing-ed25519.pem'  # manifest only

# Release: without -Console (the console was used only for validation here).
.\packaging\build.ps1 -Sign
```

If an already built exe needs to be signed:

```powershell
signtool sign /fd SHA256 /tr $env:SENTINEL_TIMESTAMP_URL /td SHA256 `
  /sha1 $env:SENTINEL_CERT_THUMBPRINT dist\sentinel.exe
```

Mandatory verification:

```powershell
signtool verify /pa /v dist\sentinel.exe
Get-AuthenticodeSignature -LiteralPath dist\sentinel.exe |
    Format-List Status, StatusMessage, SignerCertificate
```

`Status` must be `Valid` and `StatusMessage` must indicate that the chain ends
in a trusted root. Without a timestamp, the signature stops being valid when the
certificate expires: the build must always use `/tr` **and** `/td SHA256`.

## 5. Trust in AppLocker / Device Guard

With an EV/OV certificate, the root CA is already in the Windows store, so
**nothing needs to be added to `Root` or `TrustedPublisher`**. What may be
needed is a rule allowing the binary in the application control policy.

### AppLocker

Run in an administrator session and review the XML before applying it:

```powershell
Get-AppLockerFileInformation -Path .\dist\sentinel.exe |
    New-AppLockerPolicy -RuleType Publisher -User Everyone -XML |
    Set-Content .\sentinel-publisher.xml -Encoding UTF8

Test-AppLockerPolicy -XmlPolicy .\sentinel-publisher.xml -Path .\dist\sentinel.exe
Set-AppLockerPolicy -XmlPolicy .\sentinel-publisher.xml -Merge
```

The `Publisher` rule remains valid for future versions signed with the same
certificate; a hash rule would have to be regenerated for every release.

### WDAC / App Control for Business

Work with the IT team and start in audit mode:

```powershell
# Directory containing only the signed exe.
New-CIPolicy -MultiplePolicyFormat -Level Publisher -UserPEs `
  -FilePath .\sentinel-supplemental.xml -ScanPath .\dist
ConvertFrom-CIPolicy .\sentinel-supplemental.xml .\sentinel-supplemental.bin
```

Deploy the `.bin` with Intune, GPO or `CiTool`, leave it in audit mode first and
review `Microsoft-Windows-CodeIntegrity/Operational` before enforcing it.
`-Level Publisher` is preferable to `Hash`: it does not require reissuing the
policy for every build. If `FilePublisher` is used, a minimum version should be
pinned.

**Do not** resolve the current block by adding the self-signed certificate to
the user stores: that only works for `signtool verify`, not for a WDAC policy in
enforcement mode.

## 6. Evidence to deliver with the release

- Subject, issuer, thumbprint, expiration date and CA fingerprint.
- Full output of `signtool verify /pa /v` and `Get-AuthenticodeSignature`.
- Timestamp URL and confirmation that the timestamp is RFC 3161 with SHA-256.
- AppLocker rule XML or the WDAC supplemental policy.
- Result of `Test-AppLockerPolicy` / Code Integrity events in audit mode.
- Test on a clean VM, outside the development machine: download the exe, run
  `--version`, `sentinel selftest`, an EICAR scan and quarantine.
- For OV: screenshot of the SmartScreen dialog after download and a reputation
  plan (report to Microsoft Defender for Endpoint / SmartScreen).
- Verification of the included Ed25519 manifest:

  Only in an onedir build (`-OneFile:$false`):

  ```powershell
  sentinel integrity verify _internal\sentinel\data `
    --manifest _internal\sentinel\data\manifest.json `
    --public-key _internal\sentinel\data\signatures.json.pub
  ```

  In the default onefile build there is no `_internal`; verify the
  `sentinel/data` copy from the source tree.

## 7. Limitations this handoff does not resolve

An EV/OV certificate removes the trust block and improves SmartScreen, but it
**does not** turn the prototype into a production-ready antivirus: the
kernel-level file system filter, the independent external audit, a commercial
signature database and key rotation remain outstanding. These limitations are
described in `README.md` and `docs/THREAT_MODEL.md`.
