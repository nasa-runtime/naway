//! 进程资源只读采样，当前驻留与累计CPU使用各自真实系统口径。

use nametrics_core::{MetricSample, MetricValue};

/// 业务作用：采集当前进程资源，平台不支持或系统调用失败时省略该项而非伪造零。
///
/// 参数说明: 无。
///
/// 返回：最多两项结构化事实；CPU为累计纳秒，RSS为当前驻留字节。
pub(super) fn samples() -> Vec<MetricSample> {
    let mut samples = Vec::with_capacity(2);
    if let Some(total) = cpu_nanos() {
        samples.push(MetricSample {
            name: "gw_process_cpu_nanoseconds_total",
            labels: vec![],
            value: MetricValue::Counter(total),
        });
    }
    if let Some(current) = resident_bytes() {
        samples.push(MetricSample {
            name: "gw_process_resident_bytes",
            labels: vec![],
            value: MetricValue::Gauge(current as f64),
        });
    }
    samples
}

/// 业务作用：取得整个进程累计CPU时间，后续按采样间隔计算使用率。
///
/// 参数说明: 无。
///
/// 返回：成功取得非负CPU时钟时返回纳秒，不支持或调用失败时返回None。
fn cpu_nanos() -> Option<u64> {
    #[cfg(unix)]
    {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // 栈对象大小与系统ABI一致；只读取进程时钟，不将墙钟跳变当CPU消耗。
        if unsafe {
            libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut time)
        } != 0 {
            return None;
        }
        u64::try_from(time.tv_sec)
            .ok()?
            .checked_mul(1_000_000_000)?
            .checked_add(u64::try_from(time.tv_nsec).ok()?)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// 业务作用：读取当前驻留物理内存，避免把getrusage峰值误标为当前RSS。
///
/// 参数说明: 无。
///
/// 返回：当前驻留字节，平台不支持或读取失败为None。
fn resident_bytes() -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            /// 业务作用：按macOS libproc合同读取当前进程的固定大小任务信息。
            ///
            /// 参数说明：
            /// - `pid`：当前进程标识。
            /// - `flavor`：固定PROC_PIDTASKINFO查询类型。
            /// - `arg`：此查询固定为零。
            /// - `buffer`：接收系统任务结构的有效写入地址。
            /// - `buffersize`：结构的真实字节大小。
            ///
            /// 返回：实际写入长度，非完整长度不得读取结构。
            fn proc_pidinfo(
                pid: libc::c_int,
                flavor: libc::c_int,
                arg: u64,
                buffer: *mut libc::c_void,
                buffersize: libc::c_int,
            ) -> libc::c_int;
        }
        let mut info = std::mem::MaybeUninit::<libc::proc_taskinfo>::uninit();
        let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
        // 固定查询只能写入给定结构；只有完整成功才读取未初始化缓冲中的系统输出。
        let written = unsafe {
            proc_pidinfo(
                std::process::id() as libc::c_int,
                libc::PROC_PIDTASKINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if written != size {
            return None;
        }
        Some(unsafe {
            info.assume_init()
        }.pti_resident_size)
    }
    #[cfg(target_os = "linux")]
    {
        use std::io::Read;
        let mut bytes = String::new();
        std::fs::File::open("/proc/self/statm")
            .ok()?
            .take(4096)
            .read_to_string(&mut bytes)
            .ok()?;
        let pages = bytes.split_whitespace().nth(1)?.parse::<u64>().ok()?;
        // sysconf只读取本机页大小；负值不能转换成巨大的驻留字节数。
        let page_size = u64::try_from(unsafe {
            libc::sysconf(libc::_SC_PAGESIZE)
        }).ok()?;
        pages.checked_mul(page_size)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}
