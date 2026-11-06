//! 安装观察按完整来源组和原影响位置引用事实，不以文件条件或叶证书相同代替实际加载代。

use crate::tls::{installed::CertificateProtocol, keypair::conditions};
use serde::{Deserialize, Serialize};

pub(crate) const MAX_BYTES: usize = 32 * 1024;
pub(crate) const MAX_WIRE_BYTES: usize = 7 * 1024;
pub(crate) const MAX_TARGETS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
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

#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Observation {
    pub protocol: CertificateProtocol,
    pub state: State,
    pub bindings: u32,
    pub material_generation: Option<String>,
}

#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Target {
    pub protocols: Vec<Observation>,
}

#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Group {
    pub targets: Vec<Target>,
}

#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Batch {
    pub groups: Vec<Group>,
}

/// 完整安装观察的内存与线协议预算，准备分母和实际观察使用同一计费规则。
pub(crate) struct Budget {
    targets: usize,
    bytes: usize,
    wire_bytes: usize,
}

impl Budget {
    /// 业务作用：为完整来源数组登记固定内存，不能把额外预分配空间藏在逻辑长度之外。
    ///
    /// 参数说明：
    /// - `groups_capacity`：来源数组实际或准备时精确分配的容量。
    ///
    /// 返回：尚未加入目标和协议的预算，不分配观察对象。
    pub(crate) fn new(groups_capacity: usize) -> Self {
        Self {
            targets: 0,
            bytes: std::mem::size_of::<Batch>()
                .saturating_add(groups_capacity.saturating_mul(std::mem::size_of::<Group>())),
            wire_bytes: 0,
        }
    }

    /// 业务作用：把一个来源的全部共享目标容器纳入完整观察预算，不能只登记选中的别名。
    ///
    /// 参数说明：
    /// - `targets_capacity`：该来源目标数组实际或精确预分配容量。
    ///
    /// 返回：累加来源封装和目标数组内存，溢出按超限处理。
    pub(crate) fn group(&mut self, targets_capacity: usize) {
        self.wire_bytes = self.wire_bytes.saturating_add(8);
        self.bytes = self
            .bytes
            .saturating_add(targets_capacity.saturating_mul(std::mem::size_of::<Target>()));
    }

    /// 业务作用：登记原逻辑目标及其全部协议槽，HTTP3不能因当前未观察到而省略计费。
    ///
    /// 参数说明：
    /// - `protocols_capacity`：该目标协议数组实际或精确预分配容量。
    ///
    /// 返回：增加目标数、封装和协议槽内存，尚不包含材料代字符串。
    pub(crate) fn target(&mut self, protocols_capacity: usize) {
        self.targets = self.targets.saturating_add(1);
        self.wire_bytes = self.wire_bytes.saturating_add(8);
        self.bytes = self
            .bytes
            .saturating_add(protocols_capacity.saturating_mul(std::mem::size_of::<Observation>()));
    }

    /// 业务作用：计入每协议实际材料代的传输长度和内存，成功观察不能借缺席代的较小占用获得受理。
    ///
    /// 参数说明：
    /// - `length`：代字符串实际字节数，成功目标为64。
    /// - `capacity`：该字符串实际或精确预分配容量。
    ///
    /// 返回：计入协议封装和材料代，任何累计溢出保持超限。
    pub(crate) fn observation(&mut self, length: usize, capacity: usize) {
        self.wire_bytes = self.wire_bytes.saturating_add(32).saturating_add(length);
        self.bytes = self.bytes.saturating_add(capacity);
    }

    /// 业务作用：按共同目标数、内存和线协议上限决定完整观察能否表达，超限不截断分母。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：全部预算同时满足才为真，不证明各协议的实际安装状态。
    pub(crate) fn fits(&self) -> bool {
        self.targets <= MAX_TARGETS && self.bytes <= MAX_BYTES && self.wire_bytes <= MAX_WIRE_BYTES
    }
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
        // 原条件最多占 24 KiB，附加证据只占 7 KiB，余量留给已有 32 KiB 管理消息的身份与封装。
        let mut budget = Budget::new(self.groups.capacity());
        for (observed, source) in self.groups.iter().zip(&conditions.groups) {
            budget.group(observed.targets.capacity());
            if observed.targets.len() != source.affected.len() {
                return false;
            }
            for (target, affected) in observed.targets.iter().zip(&source.affected) {
                budget.target(target.protocols.capacity());
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
                for observation in &target.protocols {
                    budget.observation(
                        observation
                            .material_generation
                            .as_ref()
                            .map_or(0, String::len),
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
        budget.fits()
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
