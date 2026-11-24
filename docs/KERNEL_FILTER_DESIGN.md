# Kernel-level file system filter design

**Status: architectural proposal.** There is no driver code in this repository,
it has not been built with the WDK and nothing has been installed in the kernel.
The current monitor (`realtime.py`) is still user-mode.

## 1. What it solves and what it does not

The current monitor uses `ReadDirectoryChangesW` (or `watchdog`/polling), with a
64 KiB buffer. A process with the same privileges can terminate it, overflow the
queue or execute the file before the *grace period* expires.

A minifilter would allow:

- Observing `IRP_MJ_CREATE`, `IRP_MJ_WRITE` and renames before the file is
  executed.
- Denying execution of a binary while the user decides, instead of merely
  moving it to quarantine afterwards.
- Protecting the process, its home and its signature database from termination
  and writes by other processes of the same user.

**It does not** solve: an attacker with administrator privileges (who can unload
or disable the filter), malware that was already running before it was
installed, nor detection by itself. A signature database and analysis are still
required.

## 2. Proposed architecture

```text
            IRP_MJ_CREATE / WRITE / SET_INFORMATION
 Files ───────────────────────────────────────────► [FltMgr]
                                                      │
                                                      ▼
                                           [sentinel-filter.sys]
                                  (C/WDK minifilter, PASSIVE_LEVEL)
                                                      │ FltSendMessage
                                  port \SentinelFilterPort (ACL SYSTEM)
                                                      │ FilterGetMessage /
                                                      │ FilterReplyMessage
                                                      ▼
                                    [sentinel service / monitor]
                           kernel_bridge.py (ctypes → FltLib.dll)
                                                      │
                 ┌────────────────────────────────────┼────────────────┐
                 ▼                                    ▼                ▼
       core/allowlist.py                     engine/scanner.py   core/quarantine.py
       core/logging.py                       (hash + rules)     (SHA-256 + HMAC)
```

Components:

1. **`sentinel-filter.sys`**: minifilter registered with `FltRegisterFilter`.
   It instantiates on local volumes; by default it does not follow network
   redirections. Its only responsibility is to observe, send messages and apply
   the verdict it receives.
2. **Communication port**: created with `FltCreateCommunicationPort` and a
   global name (`\SentinelFilterPort`). The object's ACL is built with
   `FltBuildDefaultSecurityDescriptor` and restricted to `SYSTEM` (and perhaps
   `Administrators` only in test builds). `MaxConnections = 2` allows the
   service and a diagnostic console.
3. **`kernel_bridge.py`**: a new Python layer with no mandatory dependencies,
   using `ctypes` over `FltLib.dll` (`FilterConnectCommunicationPort`,
   `FilterGetMessage`, `FilterReplyMessage`, `FilterSendMessage`). It reuses the
   existing `RealtimeMonitor.process_path()` logic.
4. **Analysis worker**: receives the path, applies the allowlist, computes the
   hash, runs the rules and returns `ALLOW`, `DETECT` or `QUARANTINE`.

## 3. Message contract

Fixed header and fields with explicit lengths; version and *magic* to reject
incompatible clients. Every string is sent as UTF-16LE with its length in bytes.
No message exceeds 64 KiB; long paths are truncated with a flag.

| Type | Source | Content | Response |
| --- | --- | --- | --- |
| `HELLO` | user → kernel | version, PID, process name | `HELLO_ACK` with version and *altitude* |
| `SCAN_REQUEST` | kernel → user | `request_id`, PID, process path, volume, file path, `DesiredAccess`, flags | `SCAN_VERDICT` with the same `request_id` |
| `SCAN_VERDICT` | user → kernel | `request_id`, `ALLOW`/`BLOCK`/`QUARANTINE`, reason | — |
| `CONFIG_UPDATE` | user → kernel | excluded paths, mode (audit/enforce), maximum size | ACK |
| `HEARTBEAT` | both | counter, pending queue, losses | ACK |
| `SHUTDOWN` | user → kernel | reason | — |

Protocol rules:

- `request_id` is a monotonic `UINT64`; duplicate or unknown responses are
  ignored.
- If the bridge does not respond within a configurable period (for example 5 s),
  the driver applies the *fail-open*/*fail-closed* policy described below and
  emits an error event.
- The driver **never** trusts a relative path: it converts it to a full NT name
  (`\Device\HarddiskVolumeX\...`) before sending it.

## 4. Design decisions

| Decision | Choice | Reason |
| --- | --- | --- |
| Interception point | `IRP_MJ_CREATE` with `DesiredAccess` including `EXECUTE` to block; `IRP_MJ_WRITE`/`CLEANUP` to scan after closing | Avoids analyzing every read and allows stopping executions |
| Call mode | `FltSendMessage` only at `PASSIVE_LEVEL`, with a timeout; never on a paging path | Avoids deadlocks and invalid IRQL |
| Full queue | Fail-closed for `EXECUTE`, fail-open for reads/writes, always with a `realtime.error` event | An antivirus must not prevent the system from starting, but it must prevent doubtful executions |
| False positives | `audit` mode by default; `enforce` only after tuning the allowlist | The prototype already generates false heuristics on random data |
| *Altitude* | Anti-virus range 320000–329999, assigned by Microsoft for production | An arbitrary value must not be chosen in a real deployment |
| Self-protection | Deny rules for write/termination on the home, the exe and the monitor's services | The quarantine key and logs are in the home |
| Renames | `IRP_MJ_SET_INFORMATION` with `FileRenameInformation` to preserve context | A rename can evade a name rule |
| Exclusions | The allowlist is sent to the driver only as a coarse prefix filter; the final decision is always in user mode | Avoids duplicating rules and simplifies updates |

## 5. Integration with the current code

- The existing service (`service.py`) would create the bridge and maintain a
  port reader thread; `RealtimeMonitor` would not be replaced, rather a
  `native-kernel` backend selectable with `--backend` would be added. That
  backend, `kernel_bridge.py` and the driver itself **do not exist today**:
  they are part of this proposal.
- `process_path()` remains the only point that decides quarantine and
  notification; the driver only enforces the verdict. This preserves
  `audit.jsonl`, `history.db`, the quarantine HMAC and the exit codes.
- The self-exclusion of `AllowList.for_self()` would be extended with the
  driver's own files (`sentinel-filter.sys`, `.inf`, catalog) to avoid
  self-detection.
- `sentinel audit` would add a `realtime.driver` check that verifies the
  service is connected to the port; in user mode it would still pass with
  `realtime.backend`.

## 6. Channel security

- The port only accepts `SYSTEM`; the Windows service runs under that account.
  The diagnostic console requires administrator privileges.
- `HELLO` includes the PID and process path; the driver verifies that the PID
  matches the token of the connected endpoint and rejects unauthorized clients.
- Messages carry *magic*, version and length: a process writing arbitrary bytes
  to the port cannot fabricate a verdict without the ACL.
- The driver performs no file I/O or hashing; it only passes information. This
  reduces kernel code and its failure surface.
- If channel encryption is implemented, the key must be derived from the
  connected process's token, not stored in a file.

## 7. Signing and distribution

A kernel driver **cannot** be signed with only the exe's EV/OV certificate:
since Windows 10 1607, new drivers must go through the Windows Hardware Dev
Center portal. EV is required to create the program account; after that:

1. Develop with the WDK and test with *test signing* in an isolated VM (never in
   production).
2. Run the *Hardware Lab Kit* (HLK) for the supported Windows versions and
   collect the logs.
3. Submit the package to the portal for **WHQL** (production) or *attestation
   signing* (customer testing). The result is a `.sys` signed by Microsoft or a
   catalog accepted by Code Integrity.
4. Install with a signed INF/catalog, never with `sc create` on an unsigned
   binary. Verify with `Get-AuthenticodeSignature` and the events in
   `Microsoft-Windows-CodeIntegrity/Operational`.

This is a major external barrier: it adds WDK/C++, HLK, a hardware account and
Microsoft signing. It cannot be done from this Python repository.

## 8. Test plan and evidence

- **Isolated VM** with the target Windows versions, Secure Boot enabled and
  Driver Verifier (`/standard`).
- Full HLK run with no failures; capture the logs and the package submitted to
  the portal.
- EICAR and synthetic markers: create, execute and rename; verify that the
  verdict arrives before execution in `enforce` mode.
- Stress: thousands of concurrent files and processes; measure message losses,
  p99 latency and the absence of deadlocks.
- Resilience: kill the user process and reconnect; the driver must degrade
  according to policy and never leave the system without I/O.
- Self-protection: attempt to terminate the service and delete the home from
  another process of the same user; review `audit.jsonl`.
- False positives: run the benchmark and the test suite; check that exclusions
  prevent self-detection.
- Recovery: uninstall the filter and confirm that the user-mode monitor still
  works.

## 9. Open risks

- A bug in the driver can cause a BSOD; hence development requires a VM, Driver
  Verifier and WHQL signing before any deployment.
- Blocking in the `CREATE` path can cause deadlocks if analysis tries to open
  the same file; the proposed design avoids I/O in the kernel, but it must be
  validated with stress tests.
- The *altitude* and self-protection rules require coordination with the machine
  administrator; a bad combination with other antivirus products may interfere.
- Even with a filter, an administrator can disable it: the threat model in
  `THREAT_MODEL.md` remains valid.

## References

- FltMgr: `FltRegisterFilter`, `FltCreateCommunicationPort`, `FltSendMessage`,
  `FltBuildDefaultSecurityDescriptor` (WDK / `fltkernel.h`).
- FltLib: `FilterConnectCommunicationPort`, `FilterGetMessage`,
  `FilterReplyMessage`, `FilterSendMessage` (`fltuser.h`, `FltLib.dll`).
- *Driver Signing Policy* and WHCP: Microsoft Hardware Dev Center documentation.
- File system filter altitudes: Filter Manager documentation (anti-virus range
  320000–329999).
