//! 显式静态媒体路由的解析与并发预算；不加载外部编解码器。
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Mp4,
    Flv,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MediaCfg {
    /// 只解释显式选中的容器，不能从请求头切换解析器。
    pub format: Format,
    pub max_file_bytes: u64,
    pub max_metadata_bytes: usize,
    pub max_parse_bytes: usize,
    /// mdat 媒体区只校验边界而不聚合；其它 box 和 FLV tag 均受此限制。
    pub max_box_bytes: usize,
    pub max_boxes: usize,
    pub max_depth: usize,
    pub max_samples: usize,
    pub max_inflight: usize,
    pub timeout_ms: u64,
}
impl Default for MediaCfg {
    /// 业务作用：提供 MP4 有界索引默认值，路由仍需显式开启媒体能力。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：单文件 8GiB、元数据 4MiB、两路并发及一秒解析期限。
    fn default() -> Self {
        Self {
            format: Format::Mp4,
            max_file_bytes: 8 << 30,
            max_metadata_bytes: 4 << 20,
            max_parse_bytes: 8 << 20,
            max_box_bytes: 4 << 20,
            max_boxes: 10000,
            max_depth: 16,
            max_samples: 200000,
            max_inflight: 2,
            timeout_ms: 1000,
        }
    }
}
impl MediaCfg {
    /// 业务作用：在候选发布前拒绝无界解析预算与未编译的媒体执行能力。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：预算全部可计量时成功，否则保留当前路由快照。
    pub fn validate(&self) -> Result<()> {
        ensure!(
            cfg!(feature = "media-streaming"),
            "media requires media-streaming feature"
        );
        ensure!(
            (1..=1u64 << 40).contains(&self.max_file_bytes),
            "invalid media max_file_bytes"
        );
        ensure!(
            (1024..=16 << 20).contains(&self.max_metadata_bytes),
            "invalid media max_metadata_bytes"
        );
        ensure!(
            (self.max_metadata_bytes..=32 << 20).contains(&self.max_parse_bytes),
            "invalid media max_parse_bytes"
        );
        ensure!(
            (1024..=16 << 20).contains(&self.max_box_bytes),
            "invalid media max_box_bytes"
        );
        ensure!(
            (16..=100000).contains(&self.max_boxes) && (4..=32).contains(&self.max_depth),
            "invalid media box count/depth"
        );
        ensure!(
            (1..=500000).contains(&self.max_samples) && (1..=8).contains(&self.max_inflight),
            "invalid media samples/concurrency"
        );
        ensure!(
            (10..=10000).contains(&self.timeout_ms),
            "invalid media timeout_ms"
        );
        ensure!(
            self.memory_reservation() <= 192 << 20,
            "media metadata working set exceeds process admission budget"
        );
        Ok(())
    }
    /// 业务作用：在分配索引前为原始、解析、重写副本和样本表预留保守工作集。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：受配置上限约束的字节数，不能由媒体文件声明扩大。
    pub fn memory_reservation(&self) -> usize {
        self.max_metadata_bytes
            .saturating_mul(8)
            .saturating_add(self.max_samples.saturating_mul(96))
            .saturating_add(self.max_boxes.saturating_mul(128))
    }
}
