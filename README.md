# Intune-SecureBoot-CertUpdate

Intune Remediation scripts to deploy the Microsoft 2023 Secure Boot certificates via the `AvailableUpdates` registry key (`0x5944`).

## Supported Devices

| Manufacturer | Model | Min BIOS Version |
|---|---|---|
| Dell Inc. | Latitude 5340 | 1.24.1 |
| Dell Inc. | Latitude 5540 | 1.24.1 |
| Dell Inc. | Latitude 5550 | 1.16.2 |
| LENOVO | 11JQ* | M47KT3FA ≥ 1.63 |

## Scripts

### `Detect-SecureBootCertUpdate.ps1`
Detection script — checks (in order):
1. **Secure Boot enabled** — if disabled, exits compliant (no action)
2. **Manufacturer** — must be `Dell Inc.` or `LENOVO`
3. **Model** — must match a supported device
4. **BIOS version** — must meet the minimum for 2023 certificate support
5. **UEFI CA 2023 certificate** — if already present, exits compliant
6. **Registry key** — if `AvailableUpdates` is already `0x5944`, exits compliant

Exit codes: `0` = compliant (no remediation) | `1` = non-compliant (triggers remediation)

### `Remediate-SecureBootCertUpdate.ps1`
Remediation script — after safety checks (Secure Boot, manufacturer, model, BIOS), sets:
```
HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\AvailableUpdates = 0x5944 (DWORD)
```
A **reboot is required** to complete the certificate update.

Exit codes: `0` = success | `1` = failed or skipped

## Monitoring

After remediation, monitor progress via registry:
- `UEFICA2023Status`: `NotStarted` → `InProgress` → `Updated`
- `UEFICA2023Error`: `0` = success

## References
- [Dell KB000347876 — Microsoft 2011 Secure Boot Certificate Expiration](https://www.dell.com/support/kbdoc/en-us/000347876/microsoft-2011-secure-boot-certificate-expiration)
- [Microsoft — Registry key updates for Secure Boot](https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d)
