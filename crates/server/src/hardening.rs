//! Best-effort process hardening. Failures are logged, never fatal, except
//! where the operator explicitly requested a guarantee (`lock_memory`).

use crate::config::SecurityConfig;

#[derive(Debug, Default, Clone, Copy)]
pub struct HardeningReport {
    pub core_dumps_disabled: bool,
    pub non_dumpable: bool,
    pub memory_locked: bool,
}

/// Apply hardening according to configuration.
///
/// # Errors
/// Returns an error only if `lock_memory` was requested and `mlockall` failed.
pub fn apply(sec: &SecurityConfig) -> Result<HardeningReport, String> {
    #[allow(unused_mut)]
    let mut report = HardeningReport::default();
    #[cfg(unix)]
    {
        use rustix::process::{Resource, Rlimit, setrlimit};
        if sec.disable_core_dumps {
            report.core_dumps_disabled = setrlimit(
                Resource::Core,
                Rlimit {
                    current: Some(0),
                    maximum: Some(0),
                },
            )
            .is_ok();
            #[cfg(target_os = "linux")]
            {
                // Also blocks ptrace attach by unprivileged processes and
                // makes /proc/self/mem unreadable to other same-uid processes.
                report.non_dumpable = rustix::process::set_dumpable_behavior(
                    rustix::process::DumpableBehavior::NotDumpable,
                )
                .is_ok();
            }
        }
        if sec.lock_memory {
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            {
                use rustix::mm::{MlockAllFlags, mlockall};
                mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE)
                    .map_err(|e| format!("mlockall failed ({e}); grant CAP_IPC_LOCK or set security.lock_memory = false"))?;
                report.memory_locked = true;
            }
            #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
            return Err("security.lock_memory is only supported on Linux and FreeBSD".into());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = sec;
    }
    Ok(report)
}
