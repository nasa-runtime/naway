//! 客体只得到显式输入，输出先验证权限、类型和总量，再交付主管线。
use super::{vm::Vm, Failure};
use crate::config::scripts::ScriptCfg;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue};
use mlua::{Lua, Table, Value};

#[derive(Clone, Default)]
pub(crate) struct Context {
    pub scope: String,
    pub state_budget: Option<crate::control::ownership::state::Budget>,
    pub method: String,
    pub path: String,
    pub scheme: String,
    pub status: u16,
    pub eof: bool,
}
pub(super) struct Input {
    pub context: Context,
    pub headers: HeaderMap,
    pub body: Option<Bytes>,
}
#[derive(Default)]
pub(super) struct Output {
    pub set: HeaderMap,
    pub remove: Vec<HeaderName>,
    pub body: Option<Bytes>,
    pub reject: Option<u16>,
}
/// 业务作用：禁止脚本获取或改写认证、路由来源、协议边界与宿主安全策略。
///
/// 参数说明：
/// - `name`：规范化 HTTP 名称。
///
/// 返回：具有固定安全意义的头部为 true；动态身份字段另由路由构建门拒绝。
pub(super) fn forbidden(name: &HeaderName) -> bool {
    let name = name.as_str();
    name.starts_with("x-naway-")
        || name.starts_with("x-forwarded-")
        || name.starts_with("access-control-")
        || matches!(
            name,
            "authorization"
                | "proxy-authorization"
                | "proxy-authenticate"
                | "www-authenticate"
                | "cookie"
                | "set-cookie"
                | "x-api-key"
                | "host"
                | "connection"
                | "keep-alive"
                | "transfer-encoding"
                | "upgrade"
                | "trailer"
                | "te"
                | "content-length"
                | "forwarded"
                | "content-encoding"
                | "content-range"
                | "range"
                | "if-range"
                | "etag"
                | "last-modified"
                | "content-security-policy"
                | "strict-transport-security"
        )
}
impl Input {
    /// 业务作用：复制显式允许的最小上下文，不把全部请求头或超限实体带入阻塞队列。
    ///
    /// 参数说明：
    /// - `cfg`：输入相位与总量上限。
    /// - `names`：已编译输入字段白名单。
    /// - `headers`：当前相位头部。
    /// - `context`：冻结的请求及响应元数据。
    /// - `body`：当前相位可见的完整实体或单帧。
    ///
    /// 返回：有界输入；超限或相位能力不一致时拒绝。
    pub fn capture(
        cfg: &ScriptCfg,
        names: &[HeaderName],
        headers: &HeaderMap,
        context: &Context,
        body: Option<Bytes>,
    ) -> Result<Self, Failure> {
        if context.path.len() > 8192
            || context.method.len() > 32
            || context.scheme.len() > 8
            || body.as_ref().is_some_and(|body| {
                !cfg.phase.body() || body.len() > cfg.max_body_bytes.unwrap_or(0)
            })
        {
            return Err(Failure::Input);
        }
        let mut selected = HeaderMap::new();
        let mut bytes = 0usize;
        let mut count = 0;
        for name in names {
            for value in headers.get_all(name) {
                bytes = bytes
                    .saturating_add(name.as_str().len())
                    .saturating_add(value.len());
                count += 1;
                if bytes > cfg.max_header_bytes || count > 128 {
                    return Err(Failure::Input);
                }
                selected.append(name.clone(), value.clone());
            }
        }
        Ok(Self {
            context: context.clone(),
            headers: selected,
            body,
        })
    }
    /// 业务作用：将已经限界的输入编码成纯 Lua 表，重复头值保持有序数组。
    ///
    /// 参数说明：
    /// - `lua`：受预算限制的本次解释器。
    ///
    /// 返回：仅本次调用可见的上下文表；客体内存不足时失败。
    pub fn table(&self, lua: &Lua) -> mlua::Result<Table> {
        let table = lua.create_table()?;
        table.raw_set("method", self.context.method.as_str())?;
        table.raw_set("path", self.context.path.as_str())?;
        table.raw_set("scheme", self.context.scheme.as_str())?;
        table.raw_set("status", self.context.status)?;
        table.raw_set("eof", self.context.eof)?;
        let headers = lua.create_table()?;
        for name in self.headers.keys() {
            let values = lua.create_table()?;
            for (index, value) in self.headers.get_all(name).iter().enumerate() {
                values.raw_set(index + 1, lua.create_string(value.as_bytes())?)?;
            }
            headers.raw_set(name.as_str(), values)?;
        }
        table.raw_set("headers", headers)?;
        if let Some(body) = &self.body {
            table.raw_set("body", lua.create_string(body.as_ref())?)?;
        }
        Ok(table)
    }
}
impl Output {
    /// 业务作用：将客体输出视为不可信提案，完整校验后才允许变更头部或实体。
    ///
    /// 参数说明：
    /// - `vm`：当前解释器及最终期限门。
    /// - `value`：函数返回值，仅 nil 或固定字段表有效。
    /// - `cfg`：当前相位权限与总量预算。
    /// - `allowed`：构建期允许修改的字段名。
    ///
    /// 返回：原子变更提案；未知键、非法类型、越权或超限一律拒绝。
    pub fn parse(
        vm: &Vm,
        value: Value,
        cfg: &ScriptCfg,
        allowed: &[HeaderName],
    ) -> Result<Self, Failure> {
        vm.guard.check()?;
        let table = match value {
            Value::Nil => return Ok(Self::default()),
            Value::Table(table) => table,
            _ => return Err(Failure::Output),
        };
        for pair in table.clone().pairs::<Value, Value>().take(5) {
            let (key, _) = pair.map_err(|_| Failure::Output)?;
            if !matches!(key, Value::String(ref key) if matches!(key.as_bytes().as_ref(), b"set_headers"|b"remove_headers"|b"body"|b"reject"))
            {
                return Err(Failure::Output);
            }
        }
        let mut output = Self::default();
        let mut size = 0usize;
        let mut count = 0usize;
        if let Value::Table(set) = optional_table(&table, "set_headers")? {
            if cfg.phase.body() {
                return Err(Failure::Output);
            }
            for pair in set.pairs::<Value, Value>() {
                let (key, value) = pair.map_err(|_| Failure::Output)?;
                count += 1;
                if count > cfg.max_mutations {
                    return Err(Failure::Output);
                }
                let name = header_name(key, allowed)?;
                let Value::String(value) = value else {
                    return Err(Failure::Output);
                };
                size = size
                    .saturating_add(name.as_str().len())
                    .saturating_add(value.as_bytes().len());
                if size > cfg.max_header_bytes {
                    return Err(Failure::Output);
                }
                let value =
                    HeaderValue::from_bytes(&value.as_bytes()).map_err(|_| Failure::Output)?;
                if output.set.insert(name, value).is_some() {
                    return Err(Failure::Output);
                }
            }
        }
        if let Value::Table(remove) = optional_table(&table, "remove_headers")? {
            if cfg.phase.body() {
                return Err(Failure::Output);
            }
            let len = remove.raw_len();
            if len > cfg.max_mutations {
                return Err(Failure::Output);
            }
            let mut actual = 0;
            for pair in remove.pairs::<Value, Value>() {
                let (index, value) = pair.map_err(|_| Failure::Output)?;
                if !matches!(index, Value::Integer(i) if i > 0 && i as usize <= len) {
                    return Err(Failure::Output);
                }
                actual += 1;
                count += 1;
                if count > cfg.max_mutations {
                    return Err(Failure::Output);
                }
                let name = header_name(value, allowed)?;
                size = size.saturating_add(name.as_str().len());
                if size > cfg.max_header_bytes
                    || output.set.contains_key(&name)
                    || output.remove.contains(&name)
                {
                    return Err(Failure::Output);
                }
                output.remove.push(name);
            }
            if actual != len {
                return Err(Failure::Output);
            }
        }
        match table
            .raw_get::<Value>("body")
            .map_err(|_| Failure::Output)?
        {
            Value::Nil => (),
            Value::String(body)
                if cfg.phase.body() && body.as_bytes().len() <= cfg.max_body_bytes.unwrap_or(0) =>
            {
                output.body = Some(Bytes::copy_from_slice(&body.as_bytes()))
            }
            _ => return Err(Failure::Output),
        }
        match table
            .raw_get::<Value>("reject")
            .map_err(|_| Failure::Output)?
        {
            Value::Nil => (),
            Value::Integer(status) if (400..=599).contains(&status) => {
                output.reject = Some(status as u16)
            }
            _ => return Err(Failure::Output),
        }
        vm.guard.check()?;
        Ok(output)
    }
    /// 业务作用：在发布变更前复核最终头部总量，多脚本串联不能累计出无界 head。
    ///
    /// 参数说明：
    /// - `headers`：尚未修改的头部。
    ///
    /// 返回：最终头部最多 128 个值、64KiB 时成功；超限不提交任何改写。
    pub fn validate_head(&self, headers: &HeaderMap) -> Result<(), Failure> {
        if self.set.is_empty() && self.remove.is_empty() {
            return Ok(());
        }
        let mut count = 0;
        let mut size = 0usize;
        for (name, value) in headers
            .iter()
            .filter(|(name, _)| !self.set.contains_key(*name) && !self.remove.contains(name))
            .chain(self.set.iter())
        {
            count += 1;
            size = size
                .saturating_add(name.as_str().len())
                .saturating_add(value.len());
            if count > 128 || size > 65536 {
                return Err(Failure::Output);
            }
        }
        Ok(())
    }
}
/// 业务作用：严格识别可选变更表，不把错误类型静默忽略。
///
/// 参数说明：
/// - `table`：客体提案。
/// - `name`：固定协议字段名。
///
/// 返回：nil 或表；其它类型失败关闭。
fn optional_table(table: &Table, name: &str) -> Result<Value, Failure> {
    match table.raw_get::<Value>(name).map_err(|_| Failure::Output)? {
        value @ (Value::Nil | Value::Table(_)) => Ok(value),
        _ => Err(Failure::Output),
    }
}
/// 业务作用：输出名称必须属于冻结的修改白名单，大小写别名不能扩大权限。
///
/// 参数说明：
/// - `value`：未验证客体键。
/// - `allowed`：规范化白名单。
///
/// 返回：已授权名称；非法类型或越权拒绝。
fn header_name(value: Value, allowed: &[HeaderName]) -> Result<HeaderName, Failure> {
    let Value::String(value) = value else {
        return Err(Failure::Output);
    };
    if value.as_bytes().len() > 128 {
        return Err(Failure::Output);
    }
    let name = HeaderName::from_bytes(&value.as_bytes()).map_err(|_| Failure::Output)?;
    if !allowed.contains(&name) {
        return Err(Failure::Output);
    }
    Ok(name)
}
