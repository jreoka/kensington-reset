//! kensington-reset — wipe every fingerprint off a Kensington / Synaptics
//! VeriMark reader and reset the device.
//!
//! What it does, in order:
//!   1. Enumerates fingerprint units via WinBio.
//!   2. Opens a WINBIO_FLAG_MAINTENANCE session on the system pool and sends
//!      the vendor erase-database command (`IOCTL_BIOMETRIC_SYNA_ERASE_DB`)
//!      with `WinBioControlUnitPrivileged` — the exact operation the stock
//!      `reset_Click` button performs (`EraseDatabasePrivilege`).
//!   3. Restarts the reader the same way `WBFResetService132.exe` does:
//!      through the vendor reset service if it is running, otherwise with a
//!      direct `DIF_PROPERTYCHANGE` restart of the matching USB device.
//!
//! Must run elevated on Windows (`cargo build --release --target
//! x86_64-pc-windows-msvc`, copy the single .exe over, run as Administrator).
//!
//! Reverse-engineering notes live in README.md.

#[cfg(windows)]
mod app {
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};

    // ---------------------------------------------------------------- constants

    const WINBIO_TYPE_FINGERPRINT: u32 = 8;
    const WINBIO_POOL_SYSTEM: u32 = 1;
    const WINBIO_FLAG_MAINTENANCE: u32 = 2; // BIO_UNIT_MAINTENANCE
    const WINBIO_COMPONENT_SENSOR: u32 = 1;
    const WINBIO_COMPONENT_ENGINE: u32 = 2;
    const WINBIO_COMPONENT_STORAGE: u32 = 3;

    const FILE_DEVICE_BIOMETRIC: u32 = 0x44;
    const METHOD_BUFFERED: u32 = 0;
    const FILE_ANY_ACCESS: u32 = 0;
    /// Vendor function number the stock app passes through BIO_CTL_CODE for erase.
    const ERASE_DB_FUNCTION: u32 = 2058;

    const fn ctl_code(device: u32, function: u32, method: u32, access: u32) -> u32 {
        (device << 16) | (access << 14) | (function << 2) | method
    }
    const IOCTL_ERASE_DB: u32 = ctl_code(
        FILE_DEVICE_BIOMETRIC,
        ERASE_DB_FUNCTION,
        METHOD_BUFFERED,
        FILE_ANY_ACCESS,
    ); // 0x442028

    /// SetupDi class GUID for biometric devices ({53D29EF7-...}, also in the INF).
    const BIOMETRIC_GUID: GUID = GUID {
        data1: 0x53D29EF7,
        data2: 0x377C,
        data3: 0x4D14,
        data4: [0x86, 0x4B, 0xEB, 0x3A, 0x85, 0x76, 0x93, 0x59],
    };
    /// USB hardware-ID fragments the stock reset service matches on.
    const HWID_NEEDLES: [&str; 2] = ["VID_06CB&PID_00DE", "VID_047D&PID_00F2"];

    const DIGCF_PRESENT: u32 = 0x2;
    const SPDRP_HARDWAREID: u32 = 1;
    const DIF_PROPERTYCHANGE: u32 = 0x12;
    const DICS_PROPCHANGE: u32 = 3;
    const DICS_FLAG_CONFIGSPECIFIC: u32 = 2;
    const DI_NEEDRESTART: u32 = 0x80;
    const DI_NEEDREBOOT: u32 = 0x100;

    const INVALID_HANDLE: isize = -1;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const WAIT_OBJECT_0: u32 = 0;

    const RESET_EVENT: &str = "Global\\SynaDevResetEvent-132";
    const CONFIRM_EVENT: &str = "Global\\SynaDevResetConfirmEvent-132";

    // ------------------------------------------------------------------ structs

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct GUID {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    #[repr(C)]
    struct WinbioVersion {
        _major: u32,
        _minor: u32,
    }

    /// Must stay in sync with winbio_types.h (5 u32 + 5 x 256 WCHAR + version).
    #[repr(C)]
    struct WinbioUnitSchema {
        unit_id: u32,
        _pool: u32,
        _factor: u32,
        _subtype: u32,
        _caps: u32,
        device_instance_id: [u16; 256],
        description: [u16; 256],
        manufacturer: [u16; 256],
        model: [u16; 256],
        _serial: [u16; 256],
        _fw: WinbioVersion,
    }

    #[repr(C)]
    struct SpDevinfoData {
        cb_size: u32,
        _class_guid: GUID,
        _dev_inst: u32,
        _reserved: usize,
    }

    #[repr(C)]
    struct SpPropchangeParams {
        cb_size: u32,
        install_function: u32,
        state_change: u32,
        scope: u32,
        hw_profile: u32,
    }

    #[repr(C)]
    struct SpDevinstallParams {
        cb_size: u32,
        flags: u32,
        _rest: [u8; 0x248 - 8],
    }

    // ---------------------------------------------------------------------- ffi

    #[link(name = "winbio")]
    extern "system" {
        fn WinBioOpenSession(
            factor: u32,
            pool: u32,
            flags: u32,
            unit_ids: *const u32,
            unit_count: usize,
            database: *const GUID,
            session: *mut u32,
        ) -> i32;
        fn WinBioCloseSession(session: u32) -> i32;
        fn WinBioEnumBiometricUnits(
            factor: u32,
            schema: *mut *mut WinbioUnitSchema,
            count: *mut usize,
        ) -> i32;
        fn WinBioFree(address: *mut c_void) -> i32;
        fn WinBioLockUnit(session: u32, unit: u32) -> i32;
        fn WinBioUnlockUnit(session: u32, unit: u32) -> i32;
        #[allow(clippy::too_many_arguments)]
        fn WinBioControlUnitPrivileged(
            session: u32,
            unit: u32,
            component: u32,
            control: u32,
            send: *const u8,
            send_size: usize,
            recv: *mut u8,
            recv_size: usize,
            recv_len: *mut usize,
            status: *mut u32,
        ) -> i32;
    }

    #[link(name = "setupapi")]
    extern "system" {
        fn SetupDiGetClassDevsW(
            guid: *const GUID,
            enumerator: *const u16,
            parent: *mut c_void,
            flags: u32,
        ) -> isize;
        fn SetupDiEnumDeviceInfo(set: isize, index: u32, data: *mut SpDevinfoData) -> i32;
        fn SetupDiGetDeviceRegistryPropertyW(
            set: isize,
            data: *mut SpDevinfoData,
            property: u32,
            reg_type: *mut u32,
            buffer: *mut u8,
            buffer_size: u32,
            required: *mut u32,
        ) -> i32;
        fn SetupDiSetClassInstallParamsW(
            set: isize,
            data: *mut SpDevinfoData,
            params: *const SpPropchangeParams,
            size: u32,
        ) -> i32;
        fn SetupDiCallClassInstaller(
            install_function: u32,
            set: isize,
            data: *mut SpDevinfoData,
        ) -> i32;
        fn SetupDiGetDeviceInstallParamsW(
            set: isize,
            data: *mut SpDevinfoData,
            params: *mut SpDevinstallParams,
        ) -> i32;
        fn SetupDiDestroyDeviceInfoList(set: isize) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetLastError() -> u32;
        fn OpenEventW(access: u32, inherit: i32, name: *const u16) -> isize;
        fn SetEvent(handle: isize) -> i32;
        fn WaitForSingleObject(handle: isize, millis: u32) -> u32;
        fn CloseHandle(handle: isize) -> i32;
    }

    // ------------------------------------------------------------------ helpers

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn from_wide(buf: &[u16]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }

    fn hr_name(hr: i32) -> &'static str {
        match hr as u32 {
            0 => "S_OK",
            0x80070005 => "E_ACCESSDENIED (run as Administrator?)",
            0x80070057 => "E_INVALIDARG",
            0x80070422 => "service disabled / no such device",
            0x8009802F => "WINBIO_E_LOCK_VIOLATION",
            0x80098032 => "WINBIO_E_INVALID_CONTROL_CODE",
            _ => "failed",
        }
    }

    struct Args {
        units: Vec<u32>,
        component: u32,
        send_bytes: usize,
        recv_bytes: usize,
        no_restart: bool,
        skip_erase: bool,
    }

    fn usage() -> ! {
        eprintln!(
            "usage: kensington-reset [--unit ID]... [--component storage|sensor|engine]\n\
                  [--send-bytes N] [--recv-bytes N] [--skip-erase] [--no-restart]\n\
                  \n\
                  Clears every fingerprint on the reader (vendor erase-database\n\
                  command 0x{erase:08X}) then restarts the reader device.\n\
                  Defaults target every fingerprint unit; --unit scopes to unit IDs.",
            erase = IOCTL_ERASE_DB
        );
        std::process::exit(2);
    }

    fn parse_args() -> Args {
        let mut a = Args {
            units: Vec::new(),
            component: WINBIO_COMPONENT_STORAGE,
            send_bytes: 4,
            recv_bytes: 64,
            no_restart: false,
            skip_erase: false,
        };
        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            match flag.as_str() {
                "--unit" => {
                    let v = it.next().unwrap_or_else(|| usage());
                    a.units.push(v.parse().unwrap_or_else(|_| usage()));
                }
                "--component" => {
                    let v = it.next().unwrap_or_else(|| usage());
                    a.component = match v.as_str() {
                        "storage" => WINBIO_COMPONENT_STORAGE,
                        "sensor" => WINBIO_COMPONENT_SENSOR,
                        "engine" => WINBIO_COMPONENT_ENGINE,
                        _ => usage(),
                    };
                }
                "--send-bytes" => {
                    a.send_bytes = it
                        .next()
                        .unwrap_or_else(|| usage())
                        .parse()
                        .unwrap_or_else(|_| usage());
                }
                "--recv-bytes" => {
                    a.recv_bytes = it
                        .next()
                        .unwrap_or_else(|| usage())
                        .parse()
                        .unwrap_or_else(|_| usage());
                }
                "--no-restart" => a.no_restart = true,
                "--skip-erase" => a.skip_erase = true,
                "-h" | "--help" => usage(),
                _ => usage(),
            }
        }
        a
    }

    struct Unit {
        id: u32,
        label: String,
    }

    fn enum_units() -> Result<Vec<Unit>, i32> {
        let mut schema: *mut WinbioUnitSchema = std::ptr::null_mut();
        let mut count: usize = 0;
        // SAFETY: WinBio-owned out params, freed with WinBioFree below.
        let hr =
            unsafe { WinBioEnumBiometricUnits(WINBIO_TYPE_FINGERPRINT, &mut schema, &mut count) };
        if hr != 0 {
            return Err(hr);
        }
        let mut out = Vec::new();
        for i in 0..count {
            // SAFETY: array of `count` schemas owned by WinBio until freed.
            let s = unsafe { &*schema.add(i) };
            let label = format!(
                "{} {} {} [{}]",
                from_wide(&s.manufacturer),
                from_wide(&s.model),
                from_wide(&s.description),
                from_wide(&s.device_instance_id)
            );
            out.push(Unit {
                id: s.unit_id,
                label,
            });
        }
        unsafe {
            WinBioFree(schema as *mut c_void);
        }
        Ok(out)
    }

    fn erase_unit(
        session: u32,
        unit: u32,
        component: u32,
        send_len: usize,
        recv_len: usize,
    ) -> (i32, u32, usize) {
        let send = vec![0u8; send_len.max(1)];
        let mut recv = vec![0u8; recv_len.max(1)];
        let mut got: usize = 0;
        let mut status: u32 = 0;
        // SAFETY: buffers are valid for the call; unit was locked by caller.
        let hr = unsafe {
            WinBioControlUnitPrivileged(
                session,
                unit,
                component,
                IOCTL_ERASE_DB,
                send.as_ptr(),
                send_len,
                recv.as_mut_ptr(),
                recv_len,
                &mut got,
                &mut status,
            )
        };
        let _ = recv;
        (hr, status, got)
    }

    /// Ask the vendor reset service to restart the reader (its native protocol).
    /// Returns true when the service handled the restart.
    fn restart_via_service() -> bool {
        const EVENT_MODIFY_STATE: u32 = 0x0002;
        const SYNCHRONIZE: u32 = 0x0010_0000;
        let reset_name = wide(RESET_EVENT);
        let confirm_name = wide(CONFIRM_EVENT);
        // SAFETY: OpenEventW with valid name pointers.
        let reset = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, reset_name.as_ptr()) };
        if reset == 0 || reset == INVALID_HANDLE {
            return false;
        }
        let confirm = unsafe { OpenEventW(SYNCHRONIZE, 0, confirm_name.as_ptr()) };
        if confirm == 0 || confirm == INVALID_HANDLE {
            unsafe {
                CloseHandle(reset);
            }
            return false;
        }
        println!("- reset service found, requesting restart via service events");
        let ok = unsafe { SetEvent(reset) } != 0
            && unsafe { WaitForSingleObject(confirm, 30_000) } == WAIT_OBJECT_0;
        unsafe {
            CloseHandle(reset);
            CloseHandle(confirm);
        }
        if ok {
            println!("- service confirmed device restart");
        } else {
            println!("- service did not confirm within 30s, falling back to direct restart");
        }
        ok
    }

    fn hardware_id_matches(set: isize, data: *mut SpDevinfoData) -> bool {
        let mut needed: u32 = 0;
        let mut reg_type: u32 = 0;
        // SAFETY: two-call sizing pattern for SPDRP_HARDWAREID.
        let ok = unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                set,
                data,
                SPDRP_HARDWAREID,
                &mut reg_type,
                std::ptr::null_mut(),
                0,
                &mut needed,
            )
        };
        if ok != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || needed == 0 {
            return false;
        }
        let mut buf = vec![0u8; needed as usize];
        let ok = unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                set,
                data,
                SPDRP_HARDWAREID,
                &mut reg_type,
                buf.as_mut_ptr(),
                needed,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return false;
        }
        // Multi-sz UTF-16 scan, case-insensitive.
        let words: Vec<u16> = buf
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let text = from_wide(&words).to_uppercase();
        HWID_NEEDLES.iter().any(|n| text.contains(n))
    }

    /// Direct DIF_PROPERTYCHANGE restart — mirrors WBFResetService!ResetDevice.
    fn restart_direct() -> bool {
        // SAFETY: all SetupDi handles/structs managed inline; list destroyed at end.
        unsafe {
            let set = SetupDiGetClassDevsW(
                &BIOMETRIC_GUID,
                std::ptr::null(),
                std::ptr::null_mut(),
                DIGCF_PRESENT,
            );
            if set == INVALID_HANDLE {
                println!("- SetupDiGetClassDevs failed, GLE={}", GetLastError());
                return false;
            }
            let mut restarted = false;
            let mut index = 0u32;
            loop {
                let mut data: SpDevinfoData = zeroed();
                data.cb_size = size_of::<SpDevinfoData>() as u32;
                if SetupDiEnumDeviceInfo(set, index, &mut data) == 0 {
                    break;
                }
                index += 1;
                if !hardware_id_matches(set, &mut data) {
                    continue;
                }
                println!(
                    "- restarting matching biometric device (index {})",
                    index - 1
                );
                let params = SpPropchangeParams {
                    cb_size: (size_of::<u32>() * 2) as u32,
                    install_function: DIF_PROPERTYCHANGE,
                    state_change: DICS_PROPCHANGE,
                    scope: DICS_FLAG_CONFIGSPECIFIC,
                    hw_profile: 0,
                };
                if SetupDiSetClassInstallParamsW(
                    set,
                    &mut data,
                    &params,
                    size_of::<SpPropchangeParams>() as u32,
                ) == 0
                {
                    println!(
                        "  SetupDiSetClassInstallParams failed, GLE={}",
                        GetLastError()
                    );
                    continue;
                }
                if SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, set, &mut data) == 0 {
                    println!("  SetupDiCallClassInstaller failed, GLE={}", GetLastError());
                    continue;
                }
                let mut dip: SpDevinstallParams = zeroed();
                dip.cb_size = size_of::<SpDevinstallParams>() as u32;
                if SetupDiGetDeviceInstallParamsW(set, &mut data, &mut dip) != 0
                    && (dip.flags & (DI_NEEDRESTART | DI_NEEDREBOOT)) != 0
                {
                    println!("  device reports a reboot is required to finish the restart");
                }
                restarted = true;
            }
            SetupDiDestroyDeviceInfoList(set);
            restarted
        }
    }

    pub fn run() -> i32 {
        let args = parse_args();
        println!("kensington-reset: erase fingerprints + reset reader");
        println!(
            "erase IOCTL: 0x{:08X} (CTL_CODE(0x44, 2058))",
            IOCTL_ERASE_DB
        );

        let units = match enum_units() {
            Ok(u) => u,
            Err(hr) => {
                eprintln!(
                    "WinBioEnumBiometricUnits failed: 0x{:08X} {}",
                    hr as u32,
                    hr_name(hr)
                );
                return 1;
            }
        };
        if units.is_empty() {
            eprintln!("no fingerprint units found");
            return 1;
        }
        println!("fingerprint units:");
        for u in &units {
            println!("  unit {}: {}", u.id, u.label);
        }
        let targets: Vec<&Unit> = units
            .iter()
            .filter(|u| args.units.is_empty() || args.units.contains(&u.id))
            .collect();
        if targets.is_empty() {
            eprintln!("--unit filter matched nothing");
            return 1;
        }

        if !args.skip_erase {
            let mut session: u32 = 0;
            // SAFETY: system-pool maintenance session, same shape as the stock app.
            let hr = unsafe {
                WinBioOpenSession(
                    WINBIO_TYPE_FINGERPRINT,
                    WINBIO_POOL_SYSTEM,
                    WINBIO_FLAG_MAINTENANCE,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    &mut session,
                )
            };
            if hr != 0 {
                eprintln!(
                    "WinBioOpenSession(maintenance) failed: 0x{:08X} {}",
                    hr as u32,
                    hr_name(hr)
                );
                return 1;
            }
            let mut failures = 0;
            for u in &targets {
                println!("erasing unit {} ...", u.id);
                let hr = unsafe { WinBioLockUnit(session, u.id) };
                if hr != 0 {
                    eprintln!(
                        "  WinBioLockUnit failed: 0x{:08X} {}",
                        hr as u32,
                        hr_name(hr)
                    );
                    failures += 1;
                    continue;
                }
                let (hr, status, got) = erase_unit(
                    session,
                    u.id,
                    args.component,
                    args.send_bytes,
                    args.recv_bytes,
                );
                println!(
                    "  ControlUnitPrivileged -> hr=0x{:08X} {} status=0x{:08X} returned={}B",
                    hr as u32,
                    hr_name(hr),
                    status,
                    got
                );
                if hr != 0 {
                    failures += 1;
                }
                let hr = unsafe { WinBioUnlockUnit(session, u.id) };
                if hr != 0 {
                    eprintln!("  WinBioUnlockUnit failed: 0x{:08X}", hr as u32);
                }
            }
            unsafe {
                WinBioCloseSession(session);
            }
            if failures > 0 {
                eprintln!("erase failed on {} unit(s)", failures);
                return 1;
            }
            println!("erase commands accepted");
        }

        if !args.no_restart {
            if !restart_via_service() && !restart_direct() {
                eprintln!("no matching reader device was restarted");
                return 1;
            }
            println!("reader restart done — unplug/replug if the OS does not re-enumerate it");
        }
        println!("done");
        0
    }
}

#[cfg(windows)]
fn main() {
    std::process::exit(app::run());
}

#[cfg(not(windows))]
fn main() {
    eprintln!("kensington-reset only runs on Windows (uses WinBio + SetupDi).");
    eprintln!("Build it for Windows: cargo build --release --target x86_64-pc-windows-msvc");
    std::process::exit(2);
}
