//! What differs between the platforms the manager runs on.

use std::path::Path;
use std::process::Command;

#[cfg(windows)]
pub mod windows;

/// Start `command` with no console window of its own. Nothing changes off Windows.
pub fn hide_console(command: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    command
}

/// Spawn flags for the patcher host.
///
/// Adds `CREATE_BREAKAWAY_FROM_JOB` on top of the console-hiding bits so the host
/// leaves the launcher's job object. Some launchers (notably Tauri-wrapped apps)
/// are run inside a job that forbids child processes from installing user-mode
/// hooks on windows owned by other jobs; the host's `SetWindowsHookEx` then fails
/// with `0x00000000` and no inject happens. Breaking away gives the host its own
/// process group with no inherited job restrictions.
///
/// If the launcher's job denies breakaway (`JOB_OBJECT_LIMIT_BREAKAWAY_OK` unset
/// AND no `SILENT_BREAKAWAY_OK`), `CreateProcess` fails with ERROR_ACCESS_DENIED;
/// callers that need the fallback should retry with [`hide_console`].
pub fn host_creation_flags(command: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        command.creation_flags(CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB);
    }

    command
}

/// Whether this machine accepts paths past the legacy 260-character limit.
///
/// Always true off Windows, where the limit does not exist.
#[must_use]
pub fn long_paths_enabled() -> bool {
    #[cfg(windows)]
    {
        let enabled = windows::reg_read_num(
            windows::HKLM,
            "SYSTEM\\CurrentControlSet\\Control\\FileSystem",
            "LongPathsEnabled",
        );
        enabled.unwrap_or(0) != 0
    }

    #[cfg(not(windows))]
    {
        true
    }
}

/// Returns the bytes free to the current user on the volume that contains `path`.
///
/// Returns `None` if the volume cannot be queried, and always off Windows.
#[must_use]
pub fn free_disk_bytes(path: &Path) -> Option<u64> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

        let wide = windows::path_to_wide(path);
        let mut free: u64 = 0;
        // SAFETY: `wide` is a null-terminated wide string that outlives the call, and `free`
        // is a stack `u64` that the call writes. The two optional outputs are null.
        let ok = unsafe {
            GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &raw mut free,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        (ok != 0).then_some(free)
    }

    #[cfg(not(windows))]
    {
        let _ = path;
        None
    }
}
