//! 材料条件来自同一安装锁下的实际来源，不能替代已安装监听事实或持续写入许可。

use super::{generation, keypair_install_lock, recover_legacy_keypair_transaction_locked, source};
use crate::{config::GatewaySnapshot, tls::targets::Target};
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct Conditions {
    pub source: Source,
    pub certificate_etag: String,
    pub material_generation: Option<String>,
    pub source_id: String,
    pub affected: Vec<Affected>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Source {
    File,
    Manifest,
    Acme,
}

#[derive(Serialize)]
pub(crate) struct Affected {
    pub target: Target,
    pub source_id: String,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Unavailable {
    TargetAbsent,
    ExternalSource,
    Capacity,
    Storage,
    ImpactUnproven,
}

/// 业务作用：在同一材料锁内读取公开条件及完整共享影响，GET 不创建材料代或取得安装权。
///
/// 参数说明：
/// - `snapshot`：调用方冻结且在交付前需要复验的完整配置。
/// - `target`：已按当前主体授权的默认或 SNI 逻辑目标，不接受文件路径。
///
/// 返回：公开证书条件及完整来源影响；缺失、外部所有权、超量或证据不足返回固定原因。
/// 普通读取不打开私钥，已有未完成 pair 事务仍须先按既定恢复规则结算。
pub(crate) fn read(snapshot: &GatewaySnapshot, target: &Target) -> Result<Conditions, Unavailable> {
    let selected = target.resolve(snapshot).ok_or(Unavailable::TargetAbsent)?;
    if !crate::tls::targets::writable(&selected) {
        return Err(Unavailable::ExternalSource);
    }
    let identities = snapshot
        .proxies
        .iter()
        .filter_map(|proxy| proxy.tls.as_ref())
        .chain(
            snapshot
                .stream_listeners
                .iter()
                .filter_map(|listener| listener.tls.as_ref()),
        )
        .try_fold(0usize, |count, plan| {
            count.checked_add(plan.certs.len().saturating_add(1))
        });
    if identities.is_none_or(|count| count > 4096) {
        return Err(Unavailable::Capacity);
    }
    let _guard = keypair_install_lock()
        .lock()
        .map_err(|_| Unavailable::Storage)?;
    // 旧 journal 代表尚未结算的文件决定；不能绕开恢复把半份 pair 声称为可提交的基线。
    recover_legacy_keypair_transaction_locked(&selected).map_err(|_| Unavailable::Storage)?;
    let impact =
        source::Impact::read(snapshot, &selected).map_err(|_| Unavailable::ImpactUnproven)?;
    // 完整影响必须能在控制消息预算内交付；超量整体拒绝，不能截断为看似独立的目标。
    if impact
        .listeners
        .iter()
        .map(|listener| listener.entries.len())
        .sum::<usize>()
        > 128
    {
        return Err(Unavailable::Capacity);
    }
    let (path, _) = crate::tls::active_keypair_paths_unrecovered(&selected)
        .map_err(|_| Unavailable::Storage)?;
    let certificate = zeroize::Zeroizing::new(
        crate::io::bounded_io::read_file(&path, 1024 * 1024, "TLS material conditions")
            .map_err(|_| Unavailable::Storage)?,
    );
    // 错放到证书位置的私钥或非法材料不能产生对外摘要；仅确认完整的公开 X.509 链后计算 ETag。
    public_chain(&certificate)?;
    let material_generation =
        generation::current(&selected, &certificate, None).map_err(|_| Unavailable::Storage)?;
    let source_id = generation::target(&selected)
        .map(|id| hex(&id))
        .map_err(|_| Unavailable::Storage)?;
    let mut affected = Vec::new();
    for listener in impact.listeners {
        for entry in listener.entries {
            let source;
            let source = if let Some(index) = entry {
                source =
                    crate::tls::targets::sni_source(listener.plan, &listener.plan.certs[index]);
                &source
            } else {
                listener.plan
            };
            let target = Target {
                kind: listener.kind,
                listener: listener.id.to_owned(),
                entry: entry.map_or_else(|| "default".into(), |index| format!("sni-{index}")),
            };
            if !target.valid() {
                return Err(Unavailable::Capacity);
            }
            // seed 的读取影响与 manifest 的写入所有权不同，分别记录来源证明，不能把它们合并成一个动作。
            let source_id = generation::target(source)
                .map(|id| hex(&id))
                .map_err(|_| Unavailable::Storage)?;
            affected.push(Affected {
                target,
                source_id,
            });
        }
    }
    affected.sort_unstable_by(|left, right| {
        (
            left.target.kind as u8,
            &left.target.listener,
            &left.target.entry,
        )
            .cmp(&(
                right.target.kind as u8,
                &right.target.listener,
                &right.target.entry,
            ))
    });
    Ok(Conditions {
        source: if selected.acme.is_some() {
            Source::Acme
        } else if selected.keypair_manifest_file.is_some() {
            Source::Manifest
        } else {
            Source::File
        },
        certificate_etag: super::certificate_etag(&certificate),
        material_generation,
        source_id,
        affected,
    })
}

/// 业务作用：只允许公开证书链参与条件摘要，拒绝错位私钥、混合身份和不可解释的链材料。
///
/// 参数说明：
/// - `pem`：从证书槽位读取且受一 MiB 限制的原始材料。
///
/// 返回：一至三十二张完整 X.509 证书且没有其它 PEM 身份时成功；任何解析失败都不产生条件。
fn public_chain(pem: &[u8]) -> Result<(), Unavailable> {
    let mut in_certificate = false;
    for line in pem.split(|byte| *byte == b'\n') {
        let line = line.trim_ascii();
        if line.is_empty() {
            continue;
        }
        if !in_certificate {
            if line != b"-----BEGIN CERTIFICATE-----" {
                return Err(Unavailable::Storage);
            }
            in_certificate = true;
        } else if line == b"-----END CERTIFICATE-----" {
            in_certificate = false;
        } else if !line
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(byte))
        {
            return Err(Unavailable::Storage);
        }
    }
    if in_certificate {
        return Err(Unavailable::Storage);
    }
    let mut reader = std::io::Cursor::new(pem);
    let mut count = 0;
    for item in rustls_pemfile::read_all(&mut reader) {
        let rustls_pemfile::Item::X509Certificate(der) = item.map_err(|_| Unavailable::Storage)?
        else {
            return Err(Unavailable::Storage);
        };
        count += 1;
        if count > 32
            || !x509_parser::parse_x509_certificate(&der).is_ok_and(|(rest, _)| rest.is_empty())
        {
            return Err(Unavailable::Storage);
        }
    }
    if count == 0 {
        return Err(Unavailable::Storage);
    }
    Ok(())
}

/// 业务作用：对外给出可比较的来源证明，文件路径只参与摘要，不进入响应。
///
/// 参数说明：
/// - `digest`：具有固定来源域和长度帧的路径摘要。
///
/// 返回：规范的小写 SHA-256 文本，不包含私钥摘要。
fn hex(digest: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(64);
    for byte in digest {
        write!(&mut text, "{byte:02x}").expect("write source identity");
    }
    text
}
