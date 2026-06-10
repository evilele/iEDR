# iEDR
> *better maldev & more insights into MDE*

## How to run it
```powershell
# start the monitor, tracks MDE actions against yourmalware.exe
iEDR.exe -a C:\path\to\file\yourmalware.exe

# then copy/write/etc. your file to C:\path\to\file\yourmalware.exe
# and see what actions MDE takes against your file (static, emulation, memscan)
```

## Why iEDR
iEDR uses ETW to track the relevant actions of MsMpEng (MDE) against your malware. Usually you need kernel-based access to modify MsMpEng to track all systemcalls. However, the relevant events for **heuristics checks**, **emulation** and **memory scans** can be found in the ETW traces Microsoft-Antimalware-Engine and Microsoft-Windows-Kernel-Audit-API-Calls respectively.

## EDR background
* see [Defender Detection Engines](https://blog.levi.wiki/post/2025-12-04-defender-detection-engines)
<img width="1090" height="653" alt="image" src="https://github.com/user-attachments/assets/2ea582dd-9583-4e28-8752-ba23b6a7bee5" />

## Relevant Events to Track MDE
| Phase       | ETW Antimalware Engine | Kernel Audit API Calls | ETW TI        | Hooked EDR    |
|-------------|------------------------|------------------------|---------------|---------------|
| Static Scan | **Stream scan**        | Not visible            | Not visible   | NtReadFile    |
| Emulation   | **Scan**               | Not visible            | Alloc in EDR  | Not visible   |
| Memory Scan | Not visible            | **OpenProcess**        | RW->RX in EDR | NtOpenProcess |
| Tracking    | Other events           | Other events           | Other events  | Other events  |

## More Theory
* see [EDR-Introspection](https://github.com/evilele/EDR-Introspection)
* and [Defender Detection Mechanisms](https://blog.levi.wiki/post/2026-01-09-defender-detection-mechanisms)


