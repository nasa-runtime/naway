//! 业务范围的日志写入不阻塞代理任务。候选范围共享进程的一条有界文件输出队列。

use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use nasa::log::FileLogConfig;
use parking_lot::Mutex;
use tracing::{Level, Metadata};
use tracing_subscriber::fmt::MakeWriter;

use super::scoped_files::Files;

const MAX_PENDING_LOG_RECORDS: usize = 256;
const MAX_LOG_RECORD_BYTES: usize = 64 * 1024;
const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) struct Writer {
    sender: SyncSender<Work>,
    pending_errors: Arc<AtomicU64>,
}

pub(super) struct Worker {
    writer: Arc<Writer>,
}

struct Dispatch {
    files: Arc<Mutex<Files>>,
    options: Arc<FileLogConfig>,
}

enum Work {
    Record {
        dispatch: Arc<Dispatch>,
        level: Level,
        text: Vec<u8>,
    },
    Prune(Arc<Dispatch>),
    Flush(mpsc::Sender<()>),
}

#[derive(Clone)]
pub(super) struct Destination {
    writer: Arc<Writer>,
    dispatch: Arc<Dispatch>,
}

pub(super) struct Record<'a> {
    output: &'a Destination,
    level: Level,
    text: Option<Vec<u8>>,
}

impl Worker {
    /// 业务作用：为此进程建立范围日志共用的有界文件任务，禁止单个监听配置占用独立的线程池。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：线程正常建立时提供 writer 所有者。线程创建失败拒绝开放私有日志。
    pub(super) fn start() -> Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(MAX_PENDING_LOG_RECORDS);
        let pending_errors = Arc::new(AtomicU64::new(0));
        let worker_errors = pending_errors.clone();
        std::thread::Builder::new()
            .name("naway-scoped-log".to_owned())
            .spawn(move || {
                while let Ok(job) = receiver.recv() {
                    let result = match job {
                        Work::Record {
                            dispatch,
                            level,
                            text,
                        } => dispatch
                            .files
                            .lock()
                            .append(&dispatch.options, level, &text),
                        Work::Prune(dispatch) => dispatch.files.lock().prune(&dispatch.options),
                        Work::Flush(done) => {
                            let _ = done.send(());
                            continue;
                        }
                    };
                    if result.is_err() {
                        worker_errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
            .context("start scoped log file worker")?;
        Ok(Self {
            writer: Arc::new(Writer {
                sender,
                pending_errors,
            }),
        })
    }

    /// 业务作用：关联已准备的本地文件和特定配置代的日志规则。
    ///
    /// 参数说明：
    /// - `files`：同一个物理日志目录拥有的当前输出句柄。
    /// - `options`：该代日志的滚动、错误文件和归档保留策略。
    ///
    /// 返回：可由 tracing 订阅持有的范围 writer，不发布到其它范围或全局日志。
    pub(super) fn destination(
        &self,
        files: Arc<Mutex<Files>>,
        options: Arc<FileLogConfig>,
    ) -> Destination {
        Destination {
            writer: self.writer.clone(),
            dispatch: Arc::new(Dispatch {
                files,
                options,
            }),
        }
    }

    /// 业务作用：待数据面停止产生新日志后确认此前入队的记录已完成文件处理。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：确认队列消费时为真，队列无法接收或文件任务超时返回假。
    pub(super) fn flush(&self) -> bool {
        let (done, complete) = mpsc::channel();
        self.writer.sender.try_send(Work::Flush(done)).is_ok()
            && complete.recv_timeout(FLUSH_TIMEOUT).is_ok()
    }

    /// 业务作用：以低基数指标汇报实例日志未落盘数，保留私有正文的隔离边界。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：此 writer 累计的队列、记录大小或 I/O 丢弃数，不包含业务内容。
    pub(super) fn failed_records(&self) -> u64 {
        self.writer.pending_errors.load(Ordering::Relaxed)
    }
}

impl Writer {
    /// 业务作用：以非阻塞方式提交完整私有日志，文件出错时避免回退至全局输出。
    ///
    /// 参数说明：
    /// - `work`：完整的记录或对应范围的后台保留维护。
    ///
    /// 返回：无；队列已满或关闭时计数并释放候选字节。
    fn enqueue(&self, work: Work) {
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
            self.sender.try_send(work)
        {
            self.pending_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Destination {
    /// 业务作用：在范围文件正式生效后执行启动期保留规则。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：配置要求清理时投递一次有界任务，禁用时无副作用。
    pub(super) fn activate(&self) {
        if self.dispatch.options.clean_history_on_start {
            self.writer.enqueue(Work::Prune(self.dispatch.clone()));
        }
    }
}

impl<'writer> MakeWriter<'writer> for Destination {
    type Writer = Record<'writer>;

    /// 业务作用：为无事件元数据的输出建立仅供当前业务范围使用的缓冲。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：默认以 INFO 级别标记的空记录。
    fn make_writer(&'writer self) -> Self::Writer {
        Record {
            output: self,
            level: Level::INFO,
            text: Some(Vec::new()),
        }
    }

    /// 业务作用：使用 tracing 的实际级别分流，保证只有 ERROR 记录进入私有错误文件。
    ///
    /// 参数说明：
    /// - `meta`：由当前记录的真实调用点提供的元数据。
    ///
    /// 返回：绑定本次级别与已选范围的空缓冲。
    fn make_writer_for(&'writer self, meta: &Metadata<'_>) -> Self::Writer {
        Record {
            output: self,
            level: *meta.level(),
            text: Some(Vec::new()),
        }
    }
}

impl Write for Record<'_> {
    /// 业务作用：只收集同一条记录的有界文本，长字段不能使后台积压失去内存上限。
    ///
    /// 参数说明：
    /// - `bytes`：格式化器提交的同一条记录的一段文本。
    ///
    /// 返回：按原协议确认已消费的字节数，超限时整条放弃并计数。
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(record) = &mut self.text {
            if record.len().saturating_add(bytes.len()) <= MAX_LOG_RECORD_BYTES {
                record.extend_from_slice(bytes);
            } else {
                self.text = None;
                self.output
                    .writer
                    .pending_errors
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(bytes.len())
    }

    /// 业务作用：保持一次格式化调用生成一条完整记录，刷新由进程日志所有者集中确认。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：记录仍在当前写缓冲中，关闭后进入文件队列。
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for Record<'_> {
    /// 业务作用：将已渲染的记录和当前范围关联，后续换代不会让队列重新选择目的地。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：完整且非空的记录提交后台，丢弃的记录不会被部分提交。
    fn drop(&mut self) {
        if let Some(text) = self.text.take().filter(|text| !text.is_empty()) {
            self.output.writer.enqueue(Work::Record {
                dispatch: self.output.dispatch.clone(),
                level: self.level,
                text,
            });
        }
    }
}
