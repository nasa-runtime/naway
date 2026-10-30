//! 主动探测身份只在配置构建期计算，数据面按固定身份拒绝跨策略结果。

use super::ActiveHealthPolicy;
use crate::upstream::UpstreamProtocol;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct PolicyIdentity {
    definition: [u8; 32],
    protocol: UpstreamProtocol,
}

impl ActiveHealthPolicy {
    /// 业务作用：绑定规范化探测策略与实际传输协议，不允许旧协议结果摘除新候选。
    ///
    /// 参数说明：
    /// - `protocol`：当前逻辑服务编译出的上游传输协议。
    ///
    /// 返回：固定大小身份；不重新散列策略或分配字符串。
    pub fn identity(&self, protocol: UpstreamProtocol) -> PolicyIdentity {
        PolicyIdentity {
            definition: self.fingerprint,
            protocol,
        }
    }

    /// 业务作用：为完整规范化策略建立无歧义身份，热更等价策略保留阈值而语义变化隔离旧结果。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：全部实际探测字段的 SHA-256，不编码中间文档，不包含运行时计数。
    pub(super) fn fingerprint(&self) -> [u8; 32] {
        let Self {
            kind,
            path,
            interval,
            jitter,
            timeout,
            healthy_threshold,
            unhealthy_threshold,
            expected_status,
            grpc_service,
            udp_payload,
            udp_expected_response,
            fingerprint: _,
        } = self;
        let mut hash = Sha256::new();
        hash.update(b"naway-active-health-policy\0");
        hash.update([match kind {
            super::HealthKind::Tcp => 0,
            super::HealthKind::Http => 1,
            super::HealthKind::Grpc => 2,
            super::HealthKind::Udp => 3,
        }]);
        for value in [interval, jitter, timeout] {
            hash.update(value.as_nanos().to_be_bytes());
        }
        hash.update(healthy_threshold.to_be_bytes());
        hash.update(unhealthy_threshold.to_be_bytes());
        hash.update([u8::from(expected_status.is_some())]);
        hash.update(expected_status.unwrap_or(0).to_be_bytes());
        for value in [
            path.as_bytes(),
            grpc_service.as_bytes(),
            udp_payload.as_ref(),
        ] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        }
        hash.update([u8::from(udp_expected_response.is_some())]);
        if let Some(value) = udp_expected_response {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        }
        hash.finalize().into()
    }
}
