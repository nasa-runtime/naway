//! 进程内有界锁权威；相同目录的快照与请求共享状态，令牌不授予额外身份权限。

use dav_server::{
    davpath::DavPath,
    ls::{DavLock, DavLockSystem, LsFuture},
};
use parking_lot::Mutex;
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use xmltree::Element;

#[derive(Debug)]
struct Entry {
    value: DavLock,
    deadline: Instant,
}

#[derive(Clone, Debug, Default)]
pub(super) struct Table(Arc<Mutex<Vec<Entry>>>);

#[derive(Clone)]
pub(super) struct Locks {
    table: Table,
    principal: Arc<str>,
    max_locks: usize,
    max_seconds: u64,
    authority: super::filesystem::Authority,
}

impl std::fmt::Debug for Locks {
    /// 业务作用：为协议适配器提供不含主体和锁 token 的调试描述。
    ///
    /// 参数说明：
    /// - `formatter`：格式化输出目标。
    ///
    /// 返回：仅写出类型名，不暴露锁状态或认证信息。
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WebDavLocks")
    }
}

impl Table {
    /// 业务作用：在根目录退休前确认是否仍有未过期的锁权威需要保留。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：存在活动锁时为 true；顺便回收已过期条目。
    pub fn active(&self) -> bool {
        let mut entries = self.0.lock();
        entries.retain(|entry| entry.deadline > Instant::now());
        !entries.is_empty()
    }

    /// 业务作用：为当前已认证请求绑定同一目录锁表及本代更严格的资源预算。
    ///
    /// 参数说明：
    /// - `principal`：冻结认证身份的稳定摘要，不来自 XML owner 或请求头。
    /// - `max_locks`：本代允许的活动锁数量上限。
    /// - `max_seconds`：本代允许的锁存活秒数。
    /// - `authority`：本次请求的配置、来源期限和取消权威。
    ///
    /// 返回：轻量请求视图，不清空既有锁，也不授予任何锁。
    pub fn bind(
        &self,
        principal: Arc<str>,
        max_locks: usize,
        max_seconds: u64,
        authority: super::filesystem::Authority,
    ) -> Locks {
        Locks {
            table: self.clone(),
            principal,
            max_locks,
            max_seconds,
            authority,
        }
    }
}

impl Locks {
    /// 业务作用：每次操作前按单调时钟回收过期锁，避免系统时钟回拨延长写阻塞。
    ///
    /// 参数说明: 无。
    ///
    /// 返回：已经回收过期条目的唯一可变视图，不为活动锁腾位。
    fn entries(&self) -> parking_lot::MutexGuard<'_, Vec<Entry>> {
        let mut entries = self.table.0.lock();
        let now = Instant::now();
        entries.retain(|entry| entry.deadline > now);
        entries
    }

    /// 业务作用：将客户端锁期限裁剪到路由硬上限，禁止永久锁。
    ///
    /// 参数说明：
    /// - `requested`：标准 Timeout 协商出的相对期限。
    ///
    /// 返回：至少一秒、不超过配置上限的有限时长。
    fn duration(&self, requested: Option<Duration>) -> Duration {
        requested
            .unwrap_or(Duration::from_secs(self.max_seconds))
            .min(Duration::from_secs(self.max_seconds))
            .max(Duration::from_secs(1))
    }
}

/// 业务作用：比较资源路径段的从属关系，不把同名前缀当作后代。
///
/// 参数说明：
/// - `parent`：潜在祖先的已规范化 DAV 路径。
/// - `path`：待判断的 DAV 路径。
///
/// 返回：同一节点或实际后代为 true。
fn within(parent: &DavPath, path: &DavPath) -> bool {
    let parent = parent
        .as_bytes()
        .strip_suffix(b"/")
        .unwrap_or(parent.as_bytes());
    let path = path
        .as_bytes()
        .strip_suffix(b"/")
        .unwrap_or(path.as_bytes());
    path == parent
        || path
            .strip_prefix(parent)
            .is_some_and(|rest| rest.starts_with(b"/"))
}

/// 业务作用：确定一个锁是否约束目标节点及其要求检查的子树。
///
/// 参数说明：
/// - `lock`：未过期锁。
/// - `path`：目标节点。
/// - `deep`：本次操作是否同时改变后代。
///
/// 返回：当前锁与操作范围相交时为 true。
fn overlaps(lock: &DavLock, path: &DavPath, deep: bool) -> bool {
    let same = within(&lock.path, path) && within(path, &lock.path);
    same || (lock.deep && within(&lock.path, path)) || (deep && within(path, &lock.path))
}

impl DavLockSystem for Locks {
    /// 业务作用：在同一临界区裁决共享/独占冲突并分配不可预测的有限期锁。
    ///
    /// 参数说明：
    /// - `path`：已经限定在目录能力中的资源。
    /// - `principal`：协议引擎携带的冻结身份，必须与当前请求一致。
    /// - `owner`：仅用于展示的有界 XML，不参与授权。
    /// - `timeout`：客户端期望期限，受本代硬上限裁剪。
    /// - `shared`：是否请求共享写锁。
    /// - `deep`：是否覆盖后代资源。
    ///
    /// 返回：合法无冲突时返回新锁；身份、容量、随机源或冲突不满足时不改变锁表。
    fn lock(
        &self,
        path: &DavPath,
        principal: Option<&str>,
        owner: Option<&Element>,
        timeout: Option<Duration>,
        shared: bool,
        deep: bool,
    ) -> LsFuture<'_, Result<DavLock, DavLock>> {
        let duration = self.duration(timeout);
        let mut value = DavLock {
            token: String::new(),
            path: Box::new(path.clone()),
            principal: Some(self.principal.to_string()),
            owner: owner.map(|owner| Box::new(owner.clone())),
            timeout_at: SystemTime::now().checked_add(duration),
            timeout: Some(duration),
            shared,
            deep,
        };
        let mut entries = self.entries();
        // XML owner 不能代替已认证主体；满额不逐出仍有效的写保护。
        if !(self.authority)()
            || principal != Some(self.principal.as_ref())
            || entries.len() >= self.max_locks
        {
            return Box::pin(std::future::ready(Err(value)));
        }
        if let Some(conflict) = entries
            .iter()
            .find(|entry| overlaps(&entry.value, path, deep) && !(shared && entry.value.shared))
        {
            return Box::pin(std::future::ready(Err(conflict.value.clone())));
        }
        let mut random = [0u8; 32];
        if getrandom::getrandom(&mut random).is_err() {
            return Box::pin(std::future::ready(Err(value)));
        }
        value.token = format!(
            "opaquelocktoken:{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        entries.push(Entry {
            value: value.clone(),
            deadline: Instant::now() + duration,
        });
        Box::pin(std::future::ready(Ok(value)))
    }

    /// 业务作用：仅允许创建锁的已认证主体用精确根路径和 token 撤销锁。
    ///
    /// 参数说明：
    /// - `path`：锁的根资源。
    /// - `token`：客户端提交的秘密锁凭证。
    ///
    /// 返回：匹配锁被移除；过期、错路径或错主体返回拒绝。
    fn unlock(&self, path: &DavPath, token: &str) -> LsFuture<'_, Result<(), ()>> {
        let mut entries = self.entries();
        // 失权后的请求不能解除其它在途操作依赖的写保护。
        if !(self.authority)() {
            return Box::pin(std::future::ready(Err(())));
        }
        let index = entries.iter().position(|entry| {
            entry.value.token == token
                && entry.value.principal.as_deref() == Some(self.principal.as_ref())
                && within(&entry.value.path, path)
                && within(path, &entry.value.path)
        });
        let result = index
            .map(|index| {
                entries.swap_remove(index);
            })
            .ok_or(());
        Box::pin(std::future::ready(result))
    }

    /// 业务作用：对同一主体持有的活动锁续期，过期 token 不能复活。
    ///
    /// 参数说明：
    /// - `path`：原锁根资源。
    /// - `token`：已提交的锁凭证。
    /// - `timeout`：期望新期限，仍受当前路由上限约束。
    ///
    /// 返回：同一锁的新期限；身份或路径不一致时不改变状态。
    fn refresh(
        &self,
        path: &DavPath,
        token: &str,
        timeout: Option<Duration>,
    ) -> LsFuture<'_, Result<DavLock, ()>> {
        let mut entries = self.entries();
        // 续期也是控制权变更，不能把过期配置的许可延伸到下一代。
        if !(self.authority)() {
            return Box::pin(std::future::ready(Err(())));
        }
        let result = entries
            .iter_mut()
            .find(|entry| {
                entry.value.token == token
                    && entry.value.principal.as_deref() == Some(self.principal.as_ref())
                    && within(&entry.value.path, path)
                    && within(path, &entry.value.path)
            })
            .map(|entry| {
                let duration = self.duration(timeout);
                entry.deadline = Instant::now() + duration;
                entry.value.timeout = Some(duration);
                entry.value.timeout_at = SystemTime::now().checked_add(duration);
                entry.value.clone()
            })
            .ok_or(());
        Box::pin(std::future::ready(result))
    }

    /// 业务作用：在实际写入前验证全部独占锁与每个共享锁域，不因持有其它域的 token 放行。
    ///
    /// 参数说明：
    /// - `path`：操作目标。
    /// - `principal`：实际请求的已认证身份。
    /// - `ignore_principal`：仅用于标准 If 条件的 token 存在性判断，不代替写权限检查。
    /// - `deep`：是否检查整棵子树。
    /// - `submitted_tokens`：有界 If 条件解析出的 token。
    ///
    /// 返回：所有相交锁域均获授权时成功，否则返回一个冲突锁。
    fn check(
        &self,
        path: &DavPath,
        principal: Option<&str>,
        ignore_principal: bool,
        deep: bool,
        submitted_tokens: &[String],
    ) -> LsFuture<'_, Result<(), DavLock>> {
        let entries = self.entries();
        let authorized = |lock: &DavLock| {
            submitted_tokens.iter().any(|token| token == &lock.token)
                && (ignore_principal
                    || (principal == Some(self.principal.as_ref())
                        && principal == lock.principal.as_deref()))
        };
        let conflict = entries
            .iter()
            .filter(|entry| overlaps(&entry.value, path, deep))
            .find(|entry| {
                if !entry.value.shared {
                    return !authorized(&entry.value);
                }
                !entries.iter().any(|other| {
                    other.value.shared
                        && within(&other.value.path, &entry.value.path)
                        && within(&entry.value.path, &other.value.path)
                        && authorized(&other.value)
                })
            });
        Box::pin(std::future::ready(
            conflict.map_or(Ok(()), |entry| Err(entry.value.clone())),
        ))
    }

    /// 业务作用：生成当前资源的有界 lockdiscovery，仅列出实际约束该资源的活动锁。
    ///
    /// 参数说明：
    /// - `path`：查询资源。
    ///
    /// 返回：最多路由锁容量的当前描述；不暴露其它目录域。
    fn discover(&self, path: &DavPath) -> LsFuture<'_, Vec<DavLock>> {
        let entries = self.entries();
        Box::pin(std::future::ready(
            entries
                .iter()
                .filter(|entry| overlaps(&entry.value, path, false))
                .map(|entry| entry.value.clone())
                .collect(),
        ))
    }

    /// 业务作用：在协议引擎完成已授权的 DELETE/MOVE 后撤下原资源子树锁。
    ///
    /// 参数说明：
    /// - `path`：已删除或移动的原根资源。
    ///
    /// 返回：撤销该子树锁，不影响祖先或其它子树。
    fn delete(&self, path: &DavPath) -> LsFuture<'_, Result<(), ()>> {
        // 文件动作已完成也不授权迟到请求扩大锁表变化；保留的锁会按有限 TTL 自然退出。
        if !(self.authority)() {
            return Box::pin(std::future::ready(Err(())));
        }
        self.entries()
            .retain(|entry| !within(path, &entry.value.path));
        Box::pin(std::future::ready(Ok(())))
    }
}
