//! 安装观察按完整来源组和原影响位置引用事实，不以文件条件或叶证书相同代替实际加载代。

use crate::tls::{installed::CertificateProtocol, keypair::conditions};
use serde::Serialize;

pub(crate) const MAX_BYTES: usize = 32 * 1024;
pub(crate) const MAX_WIRE_BYTES: usize = 7 * 1024;
pub(crate) const MAX_TARGETS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum State {
    Current,
    DifferentMaterial,
    Unmanaged,
    Unproven,
    External,
    Pending,
    NotSelected,
    Capacity,
    Unavailable,
}

#[derive(Serialize)]
pub(crate) struct Observation {
    pub protocol: CertificateProtocol,
    pub state: State,
    pub bindings: u32,
    pub material_generation: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct Target {
    pub protocols: Vec<Observation>,
}

#[derive(Serialize)]
pub(crate) struct Group {
    pub targets: Vec<Target>,
}

#[derive(Serialize)]
pub(crate) struct Batch {
    pub groups: Vec<Group>,
}

impl Batch {
    /// 业务作用：对照完整文件来源组验证安装事实的分母、协议和有限状态，部分输出不能成为完整安装证明。
    ///
    /// 参数说明：
    /// - `conditions`：已经通过原目标完整性门的文件条件及全部共享影响。
    ///
    /// 返回：两份原生结构位置完全一致且预算成立时为真；未知协议、超量或虚构当前代均拒绝。
    pub(crate) fn valid(&self, conditions: &conditions::Batch) -> bool {
        if self.groups.len() != conditions.groups.len() {
            return false;
        }
        let mut targets = 0usize;
        // 原条件最多占 24 KiB，附加证据只占 7 KiB，余量留给已有 32 KiB 管理消息的身份与封装。
        let mut wire_bytes = 0usize;
        let mut bytes =
            std::mem::size_of::<Self>() + self.groups.capacity() * std::mem::size_of::<Group>();
        for (observed, source) in self.groups.iter().zip(&conditions.groups) {
            wire_bytes = wire_bytes.saturating_add(8);
            if observed.targets.len() != source.affected.len() {
                return false;
            }
            targets = targets.saturating_add(observed.targets.len());
            bytes =
                bytes.saturating_add(observed.targets.capacity() * std::mem::size_of::<Target>());
            for (target, affected) in observed.targets.iter().zip(&source.affected) {
                wire_bytes = wire_bytes.saturating_add(8);
                use crate::tls::targets::Kind;
                use CertificateProtocol::{Http3, Https, StreamTls};
                let correct = match affected.target.kind {
                    Kind::Proxy => {
                        matches!(target.protocols.as_slice(), [one] if one.protocol == Https)
                            || matches!(target.protocols.as_slice(), [one, two] if one.protocol == Https && two.protocol == Http3)
                    }
                    Kind::Stream => {
                        matches!(target.protocols.as_slice(), [one] if one.protocol == StreamTls)
                    }
                };
                if !correct {
                    return false;
                }
                bytes = bytes.saturating_add(
                    target.protocols.capacity() * std::mem::size_of::<Observation>(),
                );
                for observation in &target.protocols {
                    wire_bytes = wire_bytes.saturating_add(
                        32 + observation
                            .material_generation
                            .as_ref()
                            .map_or(0, String::len),
                    );
                    bytes = bytes.saturating_add(
                        observation
                            .material_generation
                            .as_ref()
                            .map_or(0, String::capacity),
                    );
                    if observation.bindings > 512 {
                        return false;
                    }
                    match observation.state {
                        State::Current | State::DifferentMaterial => {
                            let Some(generation) = &observation.material_generation else {
                                return false;
                            };
                            if observation.bindings == 0
                                || !crate::tls::keypair::valid_material_generation(generation)
                                || affected.source_id != source.source_id
                                || (observation.state == State::Current)
                                    != (source.material_generation.as_ref() == Some(generation))
                            {
                                return false;
                            }
                        }
                        State::Pending
                        | State::NotSelected
                        | State::Capacity
                        | State::Unavailable => {
                            if observation.bindings != 0
                                || observation.material_generation.is_some()
                            {
                                return false;
                            }
                        }
                        State::Unmanaged | State::Unproven | State::External => {
                            if observation.bindings == 0
                                || observation.material_generation.is_some()
                            {
                                return false;
                            }
                        }
                    }
                }
            }
        }
        targets <= MAX_TARGETS && bytes <= MAX_BYTES && wire_bytes <= MAX_WIRE_BYTES
    }

    /// 业务作用：判断一个完整来源的所有共享目标与实际协议是否都已加载当前受管代，任一未知保持失败。
    ///
    /// 参数说明：
    /// - `group`：文件条件中已经确认的唯一来源组位置。
    ///
    /// 返回：所有原影响均有明确当前安装时为真；缺失、未选中或旧材料均不能被折叠为成功。
    pub(crate) fn current(&self, group: usize) -> bool {
        self.groups.get(group).is_some_and(|group| {
            !group.targets.is_empty()
                && group.targets.iter().all(|target| {
                    !target.protocols.is_empty()
                        && target
                            .protocols
                            .iter()
                            .all(|observation| observation.state == State::Current)
                })
        })
    }
}
