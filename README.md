# kensington-reset

One tiny Windows binary. It wipes every fingerprint off a Kensington VeriMark
DT reader (Synaptics sensor) and resets the reader. That's all it does.

```text
> kensington-reset.exe            (run as Administrator)
kensington-reset: erase fingerprints + reset reader
erase IOCTL: 0x00442028 (CTL_CODE(0x44, 2058))
fingerprint units:
  unit 1: Synaptics ... [USB\VID_06CB&PID_00DE...]
erasing unit 1 ...
  ControlUnitPrivileged -> hr=0x00000000 S_OK status=0x00000000 returned=0B
erase commands accepted
- reset service found, requesting restart via service events
- service confirmed device restart
done
```

## Usage

```text
kensington-reset [--unit ID]... [--component storage|sensor|engine]
                 [--send-bytes N] [--recv-bytes N]
                 [--skip-erase] [--no-restart]
```

- No flags: erase on **every** fingerprint unit, then restart the reader.
- `--unit 1`: only touch unit 1 (see the unit list printed at startup).
- `--skip-erase`: restart the reader without erasing (recovery poke).
- `--no-restart`: erase without restarting.
- `--send-bytes` / `--recv-bytes` / `--component`: escape hatches if a
  firmware revision validates buffer sizes differently (defaults match the
  stock app: 4-byte zeroed send buffer, storage component).
- Exit code 0 = done, 1 = something failed (read the lines above).

Run elevated — the privileged erase and the device restart both require it.
`E_ACCESSDENIED` in the output means you forgot.

## Build

On Windows with Rust installed:

```text
cargo build --release
```

That produces a single `kensington-reset.exe` (~900 KB, zero
dependencies). Copy it to the target machine and run elevated.

Cross-compiled from Linux with mingw (how the bundled exe was built):

```text
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

`winbio.dll` ships no mingw import lib, so one is generated from
`.cargo/libs/winbio.def` via `dlltool` (prebuilt as
`.cargo/libs/libwinbio.a`).

## What this replaces

The stock package (`Kensington-132 _v6_0_9_1132_x64_inf_WHQL_pass`) needs a
.NET GUI app plus a permanently installed system service to do this. This
binary performs the same two operations and exits:

1. **Erase** — the vendor `IOCTL_BIOMETRIC_SYNA_ERASE_DB` command, same as
   the Reset button.
2. **Reset** — a device restart, same as `WBFResetService132.exe`
   (via the service when it's running, direct `DIF_PROPERTYCHANGE`
   otherwise).

It deliberately does **not** call `WinBioRemoveAllCredentials`: that removes
Windows logon credentials, which is broader than clearing the reader. Remove
leftover sign-in entries in Settings → Accounts → Sign-in options if needed.

## How it was reverse engineered (REA)

Target files (from the vendor 7z):

| File | What it is |
|---|---|
| `KensingtonFingerprintApplication.exe` | .NET AnyCPU stub, real code embedded |
| `FMAUserControl.dll` (embedded resource) | .NET UI + `winbioclasses.Functions` |
| `WBFResetService132.exe` | x64 service, device restart only |
| `synaWudfBioUsb132.dll` | UMDF WBDI driver |
| `synaFpAdapter132.dll` | WinBio sensor/engine/storage adapter |
| `synaWudfBioUsb.inf` | install + device IDs |

Findings, each backed by tool evidence:

- **Reset button → `EraseDatabasePrivilege`.** The UI handler
  `FPManager.View.FingerSelectionView.reset_Click` calls
  `winbioclasses.Functions.EraseDatabasePrivilege`, which calls
  `WinBioOpenSession` → `WinBioLockUnit` →
  `WinBioControlUnitPrivileged` → `WinBioUnlockUnit` →
  `WinBioCloseSession`. Per-finger checkboxes call `DeleteTemplate`
  instead — Reset is a whole-database wipe, not per-finger deletes.
- **Session shape** (decoded from the method IL): 
...[truncated 1583 chars]