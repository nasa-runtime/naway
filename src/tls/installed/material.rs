//! 当前监听材料归属只取自实际安装注册表，不读取私钥或用磁盘当前代填补缺席事实。

use super::{CertificateProtocol, InstalledCertificate, InstalledSnapshot};
use crate::{
    config::{GatewaySnapshot, TlsRuntimeCfg},
    control::material::installation::{Batch, Group, MAX_TARGETS, Observation, State, Target},
    tls::{
        keypair::conditions,
        material::{MaterialProvenance, ObservationState},
        targets::Kind,
    },
};
use std::collections::BTreeMap;

/// 业务作用：按完整来源影响逐一读取实际协议安装事实，原配置与 listener 计划不一致时保持未知。
///
/// 参数说明：
/// - `snapshot`：调用方持有配置发布权的完整当前计划。
/// - `installed`：同一节点实际 transport 安装后的原生事实快照。
/// - `conditions`：本轮完整来源组及全部共享目标，不接受客户端替代证明。
///
/// 返回：与完整影响位置一一对应的有界批次；结构或容量不足整批拒绝，不产生截断安装成功。
pub(crate) fn collect(
    snapshot: &GatewaySnapshot,
    installed: &InstalledSnapshot,
    conditions: &conditions::Batch,
) -> Option<Batch> {
    let targets = conditions.groups.iter().try_fold(0usize, |count, group| {
        count.checked_add(group.affected.len())
    })?;
    if targets > MAX_TARGETS {
        return None;
    }
    let registry: BTreeMap<_, _> = installed
        .entries
        .iter()
        .map(|entry| ((entry.protocol, entry.listener.as_ref()), entry))
        .collect();
    let mut groups = Vec::with_capacity(conditions.groups.len());
    for group in &conditions.groups {
        let mut targets = Vec::with_capacity(group.affected.len());
        for affected in &group.affected {
            let (plan, http3) = match affected.target.kind {
                Kind::Proxy => {
                    let proxy = snapshot
                        .proxies
                        .iter()
                        .find(|proxy| proxy.id == affected.target.listener)?;
                    (proxy.tls.as_ref()?, proxy.http3.enabled)
                }
                Kind::Stream => {
                    let stream = snapshot
                        .stream_listeners
                        .iter()
                        .find(|stream| stream.id == affected.target.listener)?;
                    (stream.tls.as_ref()?, false)
                }
            };
            let protocol = if affected.target.kind == Kind::Proxy {
                CertificateProtocol::Https
            } else {
                CertificateProtocol::StreamTls
            };
            let mut protocols = Vec::with_capacity(if http3 {
                2
            } else {
                1
            });
            for protocol in
                std::iter::once(protocol).chain(http3.then_some(CertificateProtocol::Http3))
            {
                protocols.push(observe(
                    protocol,
                    registry
                        .get(&(protocol, affected.target.listener.as_str()))
                        .copied(),
                    plan,
                    affected,
                    group,
                    installed.capacity,
                ));
            }
            targets.push(Target {
                protocols,
            });
        }
        groups.push(Group {
            targets,
        });
    }
    let batch = Batch {
        groups,
    };
    batch.valid(conditions).then_some(batch)
}

/// 业务作用：确认实际选中绑定的完整材料代，旧计划、未选中声明或混合归属都不能得到当前安装结论。
///
/// 参数说明：
/// - `protocol`：本项必须实际承载的服务协议。
/// - `installed`：该协议与入口的已安装记录；缺席不从配置或磁盘推断。
/// - `plan`：当前完整监听策略。
/// - `affected`：原影响中的确切默认或 SNI 声明及来源身份。
/// - `source`：本轮唯一来源的公开文件条件。
/// - `capacity`：安装注册表是否无法表达全部 listener。
///
/// 返回：单协议的完整低敏观察；只有全部选中绑定与同一受管来源一致才携带材料代。
fn observe(
    protocol: CertificateProtocol,
    installed: Option<&InstalledCertificate>,
    plan: &TlsRuntimeCfg,
    affected: &conditions::Affected,
    source: &conditions::Group,
    capacity: bool,
) -> Observation {
    let target = &affected.target;
    let source_id = &affected.source_id;
    let empty = |state| Observation {
        protocol,
        state,
        bindings: 0,
        material_generation: None,
    };
    if capacity {
        return empty(State::Capacity);
    }
    // 发布配置之后旧 listener 仍可能正在交接；同名入口不能替代完整计划的归属证明。
    let Some(installed) = installed.filter(|entry| entry.matches(plan)) else {
        return empty(State::Pending);
    };
    if installed.observation.state != ObservationState::Complete {
        return empty(
            if installed.observation.state == ObservationState::Capacity {
                State::Capacity
            } else {
                State::Unavailable
            },
        );
    }
    let declaration = if target.entry == "default" {
        None
    } else {
        let Some(index) = target
            .entry
            .strip_prefix("sni-")
            .and_then(|text| text.parse::<u16>().ok())
        else {
            return empty(State::Unavailable);
        };
        Some(index)
    };
    let mut bindings = installed.observation.bindings.iter().filter(|binding| {
        binding.declaration == declaration && selected(binding, &installed.observation.bindings)
    });
    let Some(first) = bindings.next() else {
        return empty(State::NotSelected);
    };
    let mut count = 1u32;
    let mut coherent = true;
    let now = chrono::Utc::now().timestamp();
    let authorized = |binding: &crate::tls::material::CertificateBinding| {
        !binding.ocsp_required
            || binding
                .ocsp_valid_until
                .is_some_and(|deadline| deadline > now)
    };
    let mut current_authority = authorized(first);
    for binding in bindings {
        count += 1;
        coherent &= binding.provenance == first.provenance;
        current_authority &= authorized(binding);
    }
    if count > 512 {
        return empty(State::Capacity);
    }
    // 必需 OCSP 到期后 resolver 会关闭该身份，已加载材料代不能冒充当前仍可服务的安装事实。
    if !current_authority {
        return empty(State::Unavailable);
    }
    let mut result = Observation {
        protocol,
        state: State::Unproven,
        bindings: count,
        material_generation: None,
    };
    // 混合身份或只读 seed 影响没有同一写入所有权，不能用其中一个成功绑定代表整个声明。
    if !coherent || &source.source_id != source_id {
        return result;
    }
    result.state = match &first.provenance {
        MaterialProvenance::External => State::External,
        MaterialProvenance::Unmanaged => State::Unmanaged,
        MaterialProvenance::Candidate | MaterialProvenance::Unproven => State::Unproven,
        MaterialProvenance::Managed(material) => {
            if !same_source(source_id, &material.source_id) {
                return result;
            }
            result.material_generation = Some(material.generation.clone());
            if source.material_generation.as_deref() == Some(material.generation.as_str()) {
                State::Current
            } else {
                State::DifferentMaterial
            }
        }
    };
    result
}

/// 业务作用：按实际后缀选择顺序排除永远无法命中的通配绑定，声明存在不能代替监听器实际选中。
///
/// 参数说明：
/// - `binding`：原配置位置对应的候选绑定。
/// - `bindings`：同一实际 resolver 的完整有序选择事实。
///
/// 返回：默认、精确或仍有可匹配名称的通配绑定为真；被更早宽后缀完全覆盖时为假。
fn selected(
    binding: &crate::tls::material::CertificateBinding,
    bindings: &[crate::tls::material::CertificateBinding],
) -> bool {
    // resolver 使用首个匹配后缀；较早的宽后缀会覆盖整个窄后缀域，不能用不可达身份确认材料代。
    binding.selection_order == 0
        || !bindings.iter().any(|earlier| {
            earlier.selection_order != 0
                && earlier.selection_order < binding.selection_order
                && earlier
                    .name
                    .strip_prefix('*')
                    .is_some_and(|suffix| binding.name.ends_with(suffix))
        })
}

/// 业务作用：直接对照原生来源摘要与规范文本，不创建临时十六进制字符串或接受等价别名。
///
/// 参数说明：
/// - `text`：完整条件中已经验证的来源身份。
/// - `digest`：加载时固定的原生来源摘要。
///
/// 返回：精确小写 SHA-256 文本一致时为真，其它输入拒绝归属。
fn same_source(text: &str, digest: &[u8; 32]) -> bool {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    text.len() == 64
        && text
            .as_bytes()
            .chunks_exact(2)
            .zip(digest)
            .all(|(pair, byte)| {
                pair[0] == HEX[(byte >> 4) as usize] && pair[1] == HEX[(byte & 15) as usize]
            })
}
