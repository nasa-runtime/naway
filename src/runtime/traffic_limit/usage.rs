//! 可信成本只来自冻结的上游入口；响应插件、客户端头与重试中落选的响应不能生成退款事实。

use anyhow::{ensure, Result};
use http::{HeaderMap, HeaderName};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

const UNKNOWN: u64 = 0;
const KNOWN: u64 = 1 << 33;
const INVALID: u64 = 1 << 34;
const AMOUNT: u64 = KNOWN - 1;

pub(crate) enum Source {
    ProviderTokens,
    ResponseHeader(HeaderName),
}

pub(crate) struct Plan {
    pub(crate) source: Source,
    maximum: u64,
}

/// 只在真实上游响应入口生成；不能从最终响应头或缓存序列化值恢复。
#[derive(Clone)]
pub(crate) struct Captured {
    plan: Arc<Plan>,
    value: Observation,
}

#[derive(Clone, Copy)]
pub(crate) enum Observation {
    Missing,
    Known(u64),
    Invalid,
}

/// 用于已选择响应的最终事实；状态与最大已知金额原子发布，坏证据不能抹掉先前确认的消耗。
#[derive(Clone)]
pub(crate) struct Facts(Arc<State>);

struct State {
    plan: Arc<Plan>,
    value: AtomicU64,
}

/// 只携带只读规则进入每次上游尝试，避免并发 hedge 直接覆盖同一份计费事实。
#[derive(Clone)]
pub(crate) struct Capture(pub(crate) Arc<Plan>);

impl Plan {
    /// 业务作用：编译可信用量来源和有限整数边界，不根据请求字段推断计费协议。
    ///
    /// 参数说明：
    /// - `source`：provider_tokens 或 response_header。
    /// - `header`：响应头来源唯一允许读取的字段，provider 模式必须为空。
    /// - `reserve`：准入预留额度。
    /// - `maximum`：事实成本上限。
    ///
    /// 返回：冻结来源；不明确、敏感或协议控制头及越界金额拒绝候选。
    pub(crate) fn build(
        source: &str,
        header: &str,
        reserve: u64,
        maximum: u64,
    ) -> Result<Arc<Self>> {
        ensure!(
            maximum > 0 && maximum <= 1 << 32 && reserve <= maximum,
            "trusted usage requires reserve <= max_actual within 1..2^32"
        );
        let source = match source {
            "provider_tokens" => {
                ensure!(
                    header.is_empty(),
                    "provider_tokens cannot declare a response header"
                );
                Source::ProviderTokens
            }
            "response_header" => {
                ensure!(
                    !header.is_empty() && header.len() <= 128,
                    "trusted usage requires one bounded response header name"
                );
                let name = HeaderName::from_bytes(header.as_bytes())?;
                let raw = name.as_str();
                ensure!(
                    !matches!(
                        raw,
                        "host"
                            | "connection"
                            | "keep-alive"
                            | "upgrade"
                            | "transfer-encoding"
                            | "content-length"
                            | "content-type"
                            | "content-encoding"
                            | "trailer"
                            | "te"
                            | "authorization"
                            | "proxy-authorization"
                            | "cookie"
                            | "set-cookie"
                            | "www-authenticate"
                            | "proxy-authenticate"
                    ) && !raw.contains("token")
                        && !raw.contains("secret")
                        && !raw.contains("api-key")
                        && !raw.contains("credential"),
                    "trusted usage cannot read a credential or protocol control header"
                );
                Source::ResponseHeader(name)
            }
            _ => anyhow::bail!("trusted usage source must be provider_tokens|response_header"),
        };
        Ok(Arc::new(Self {
            source,
            maximum,
        }))
    }
}

impl Capture {
    /// 业务作用：在请求头最后变换后撤下客户端同名用量声明，避免上游意外回显成为计费证据。
    ///
    /// 参数说明：
    /// - `headers`：即将发送真实上游的请求头。
    ///
    /// 返回：只移除声明的用量字段，provider 来源没有头部副作用。
    pub(crate) fn strip_request(&self, headers: &mut HeaderMap) {
        if let Source::ResponseHeader(header) = &self.0.source {
            headers.remove(header);
        }
    }

    /// 业务作用：在响应插件之前捕获一次真实上游头，等待重试或 hedge 最终选择再提交事实。
    ///
    /// 参数说明：
    /// - `headers`：真实上游返回的原始响应头。
    ///
    /// 返回：有界整数、缺失或坏证据；重复字段、小数、符号及超界金额均不允许退款。
    pub(crate) fn headers(&self, headers: &HeaderMap) -> Captured {
        let value = match &self.0.source {
            Source::ProviderTokens => Observation::Missing,
            Source::ResponseHeader(header) => {
                let mut fields = headers.get_all(header).iter();
                match fields.next() {
                    None => Observation::Missing,
                    Some(value) if fields.next().is_none() => {
                        let bytes = value.as_bytes();
                        if bytes.is_empty()
                            || bytes.len() > 10
                            || !bytes.iter().all(u8::is_ascii_digit)
                        {
                            Observation::Invalid
                        } else {
                            let amount = bytes
                                .iter()
                                .fold(0u64, |value, byte| value * 10 + u64::from(byte - b'0'));
                            if amount <= self.0.maximum {
                                Observation::Known(amount)
                            } else {
                                Observation::Invalid
                            }
                        }
                    }
                    Some(_) => Observation::Invalid,
                }
            }
        };
        Captured {
            plan: self.0.clone(),
            value,
        }
    }
}

impl Facts {
    /// 业务作用：保存 provider 已报告但尚未终结的累计消耗，取消时不能把这部分误作未使用预留。
    ///
    /// 参数说明：
    /// - `input`：已确认输入 token 数。
    /// - `output`：已确认累计输出 token 数。
    ///
    /// 返回：只提高保守成本下界，不授予退款权威；倒退、溢出或超限使事实永久失效。
    pub(crate) fn provider_progress(&self, input: u64, output: u64) {
        if !matches!(self.0.plan.source, Source::ProviderTokens) {
            return;
        }
        let Some(amount) = input
            .checked_add(output)
            .filter(|value| *value <= self.0.plan.maximum)
        else {
            self.record(Observation::Invalid);
            return;
        };
        let _ = self
            .0
            .value
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |previous| {
                let prior = previous & AMOUNT;
                let invalid = amount < prior || (previous & KNOWN != 0 && amount != prior);
                Some(
                    (previous & (KNOWN | INVALID))
                        | if invalid {
                            INVALID
                        } else {
                            0
                        }
                        | prior.max(amount),
                )
            });
    }

    /// 业务作用：在协议解析失败时撤销退款权威，保留此前已经确认的消耗下界。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：坏事实不可恢复；依赖降级不能重新开放响应流。
    pub(crate) fn reject(&self) {
        self.record(Observation::Invalid);
    }

    /// 业务作用：在明确命中缓存或本地拒绝、没有调用计费上游时记录零消耗。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：发布零成本；不能用此入口覆盖已经确认的上游消耗。
    pub(crate) fn no_upstream(&self) {
        self.record(Observation::Known(0));
    }

    /// 业务作用：仅为明确声明可信计费的请求创建有限事实槽，普通请求不分配此状态。
    ///
    /// 参数说明：
    /// - `plan`：同一快照的用量来源与金额上限。
    ///
    /// 返回：未知事实，未知不等价于零消耗。
    pub(crate) fn new(plan: Arc<Plan>) -> Self {
        Self(Arc::new(State {
            plan,
            value: AtomicU64::new(UNKNOWN),
        }))
    }

    /// 业务作用：只允许最终被选中的同策略上游响应移交计费头，落选尝试不覆盖本次成本。
    ///
    /// 参数说明：
    /// - `captured`：实际选择响应携带的内部捕获结果。
    ///
    /// 返回：发布同源事实，来源不一致时关闭事实权限并保留已确认消耗。
    pub(crate) fn accept_header(&self, captured: &Captured) {
        // 同一字段名不等于同一计费权威，内部重定向也不能混入另一候选的金额定义。
        if !Arc::ptr_eq(&self.0.plan, &captured.plan) {
            self.record(Observation::Invalid);
            return;
        }
        self.record(captured.value);
    }

    /// 业务作用：复用 provider 已解析的最终 token 事实，不再次聚合或解析模型正文。
    ///
    /// 参数说明：
    /// - `input`：provider 验证的输入 token 数。
    /// - `output`：provider 验证的输出 token 数。
    ///
    /// 返回：发布有限总成本，溢出或矛盾事实失败关闭；其它来源不接受 provider 事实。
    pub(crate) fn provider(&self, input: u64, output: u64) {
        if !matches!(self.0.plan.source, Source::ProviderTokens) {
            return;
        }
        self.record(match input.checked_add(output) {
            Some(total) if total <= self.0.plan.maximum => Observation::Known(total),
            _ => Observation::Invalid,
        });
    }

    /// 业务作用：按单向事实状态发布金额，缺失不能抹去已知金额，坏证据不可恢复成可退款状态。
    ///
    /// 参数说明：
    /// - `observation`：同源解析器提供的有限事实。
    ///
    /// 返回：更新金额与可信状态；重复相同事实幂等，矛盾事实保留较大已知金额。
    fn record(&self, observation: Observation) {
        match observation {
            Observation::Missing => {}
            Observation::Invalid => {
                self.0.value.fetch_or(INVALID, Ordering::AcqRel);
            }
            Observation::Known(amount) => {
                if amount > self.0.plan.maximum {
                    self.record(Observation::Invalid);
                    return;
                }
                // 状态和金额在同一个原子字中发布；并发重复通知不能看到半个金额或误判相同证据。
                let _ =
                    self.0
                        .value
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |previous| {
                            Some(
                                if (previous & (KNOWN | INVALID) == 0
                                    && amount >= (previous & AMOUNT))
                                    || previous == (KNOWN | amount)
                                {
                                    KNOWN | amount
                                } else {
                                    INVALID | (previous & AMOUNT).max(amount)
                                },
                            )
                        });
            }
        }
    }

    /// 业务作用：确定当前事实是否要求关闭流，依赖 fail-open 不能接受非法或矛盾金额。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：存在坏证据时为真。
    pub(crate) fn invalid(&self) -> bool {
        self.0.value.load(Ordering::Acquire) & INVALID != 0
    }

    /// 业务作用：判定是否已有完整成本，可在发布响应头前完成明确的补扣或退款。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：仅完整且未发生矛盾的事实为真；未知或坏证据不能提前返还额度。
    pub(crate) fn known(&self) -> bool {
        self.0.value.load(Ordering::Acquire) & (KNOWN | INVALID) == KNOWN
    }

    /// 业务作用：为取消与正常结束提供保守成本，provider 已发生的消耗不依赖下游是否读到正文。
    ///
    /// 参数说明：
    /// - `reserve`：没有完整可信证据时必须保留的预留。
    ///
    /// 返回：已知事实成本；缺失或坏证据至少保留预留和此前确认的较大金额。
    pub(crate) fn cost(&self, reserve: u64) -> u64 {
        let value = self.0.value.load(Ordering::Acquire);
        let known = value & AMOUNT;
        if value & (KNOWN | INVALID) == KNOWN {
            known
        } else {
            reserve.max(known)
        }
    }
}
