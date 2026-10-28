//! ZooKeeper 精确持久 znode 的短会话读取；仅认证、sync、getData、watch 和关闭，不持有写权限。

mod wire;

use super::model::Declaration;
use anyhow::{ensure, Context, Result};
use parking_lot::Mutex;
use std::{sync::Arc, time::Duration};
use tokio_rustls::{
    rustls::{self, pki_types::ServerName},
    TlsConnector,
};
use wire::{buffer, integer, long, put_buffer, Wire};

pub(super) struct Reader {
    host: String,
    port: u16,
    path: String,
    auth: String,
    tls: Option<Arc<rustls::ClientConfig>>,
    wait: Duration,
    session_ms: i32,
    cursor: Mutex<Option<Stamp>>,
}

#[derive(Clone, Copy)]
struct Stamp {
    created: i64,
    modified: i64,
    version: i32,
}

impl Reader {
    /// 业务作用：冻结单键、认证及 TLS 信任；不允许远端声明指定任意 znode 或降级网络传输。
    ///
    /// 参数说明：
    /// - `endpoint`：为本地目标
    /// - `path`：为本地目标
    /// - `wait`：为毫秒预算
    /// - `deadline`：为毫秒预算
    /// - `plaintext`：仅允许 IP loopback
    /// - `credentials`：依次为 digest、CA、证书、私钥。
    ///
    /// 返回：无网络副作用的读取计划；非法路径、预算或不完整信任拒绝。
    pub fn build(
        endpoint: &str,
        path: &str,
        wait: u64,
        deadline: u64,
        plaintext: bool,
        credentials: [String; 4],
    ) -> Result<Self> {
        ensure!(
            endpoint.len() <= 2048
                && !endpoint
                    .chars()
                    .any(|ch| ch.is_control() || matches!(ch, '$' | '\\' | '%' | '@')),
            "invalid ZooKeeper endpoint"
        );
        let endpoint = reqwest::Url::parse(endpoint).context("invalid ZooKeeper endpoint")?;
        let host = endpoint
            .host_str()
            .context("ZooKeeper host required")?
            .trim_matches(['[', ']'])
            .to_string();
        let port = endpoint
            .port()
            .filter(|port| *port != 0)
            .context("ZooKeeper explicit port required")?;
        ensure!(
            endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.query().is_none()
                && endpoint.fragment().is_none()
                && matches!(endpoint.path(), "" | "/"),
            "ZooKeeper endpoint requires an origin"
        );
        let loopback = host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
        ensure!(
            endpoint.scheme() == "zks" || (endpoint.scheme() == "zk" && plaintext && loopback),
            "ZooKeeper requires TLS"
        );
        ensure!(
            path.len() <= 512
                && path.starts_with('/')
                && path.len() > 1
                && path[1..].split('/').all(|part| !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_-.:".contains(&byte))),
            "invalid ZooKeeper exact path"
        );
        ensure!(
            (100..=5000).contains(&wait) && wait + 500 <= deadline,
            "ZooKeeper watch requires read deadline headroom"
        );
        let [auth, ca, certificate, key] = credentials;
        ensure!(
            auth.len() <= 4096
                && !auth.chars().any(char::is_control)
                && auth
                    .split_once(':')
                    .is_some_and(|(user, password)| !user.is_empty() && !password.is_empty()),
            "ZooKeeper requires digest credentials"
        );
        let tls = if endpoint.scheme() == "zks" {
            let mut roots = rustls::RootCertStore::empty();
            ensure!(!ca.is_empty(), "ZooKeeper requires explicit CA trust");
            for certificate in rustls_pemfile::certs(&mut ca.as_bytes()) {
                roots.add(certificate?)?;
            }
            ensure!(!roots.is_empty(), "ZooKeeper CA trust empty");
            ensure!(
                certificate.is_empty() == key.is_empty(),
                "ZooKeeper client identity must be paired"
            );
            let config = rustls::ClientConfig::builder().with_root_certificates(roots);
            let config = if certificate.is_empty() {
                config.with_no_client_auth()
            } else {
                let certificates = rustls_pemfile::certs(&mut certificate.as_bytes())
                    .collect::<std::io::Result<Vec<_>>>()?;
                let key = rustls_pemfile::private_key(&mut key.as_bytes())?
                    .context("ZooKeeper private key absent")?;
                config.with_client_auth_cert(certificates, key)?
            };
            Some(Arc::new(config))
        } else {
            ensure!(
                ca.is_empty() && certificate.is_empty() && key.is_empty(),
                "plaintext ZooKeeper cannot use TLS identity"
            );
            None
        };
        Ok(Self {
            host,
            port,
            path: path.into(),
            auth,
            tls,
            wait: Duration::from_millis(wait),
            session_ms: (deadline * 2).max(4000) as i32,
            cursor: Mutex::new(None),
        })
    }

    /// 业务作用：在有界短会话中完整重读持久声明；会话关闭、ACL 拒绝与旧事务均不能续期路由。
    ///
    /// 参数说明：
    /// - `maximum`：为声明上限；调用者覆盖连接、等待与解析的绝对 deadline。
    ///
    /// 返回：验证过正文与事务水位的声明；失败丢弃整条连接，无重连或请求后台队列。
    pub async fn read(&self, maximum: usize) -> Result<Declaration> {
        let socket = tokio::net::TcpStream::connect((self.host.as_str(), self.port)).await?;
        socket.set_nodelay(true)?;
        let io: Box<dyn wire::Io> = if let Some(tls) = &self.tls {
            let name =
                ServerName::try_from(self.host.clone()).context("invalid ZooKeeper TLS name")?;
            Box::new(
                TlsConnector::from(tls.clone())
                    .connect(name, socket)
                    .await?,
            )
        } else {
            Box::new(socket)
        };
        let mut session = Wire::new(io, maximum);
        self.connect(&mut session).await?;
        let (mut data, mut stamp) = self.get(&mut session, maximum, true, 1).await?;
        let previous = *self.cursor.lock();
        if previous
            .is_some_and(|old| old.modified == stamp.modified && old.created == stamp.created)
        {
            // 单次 watch 存在间隙且不携带完整状态；无论提示或超时，都 sync 后重新取正文。
            if let Ok(result) = tokio::time::timeout(self.wait, session.watch(&self.path)).await {
                result?;
            }
            (data, stamp) = self.get(&mut session, maximum, false, 3).await?;
        }
        if let Some(previous) = previous {
            // znode 重建只能提升创建事务；旧数据或重置 version 不得借新会话绕过声明水位。
            ensure!(
                stamp.created >= previous.created
                    && stamp.modified >= previous.modified
                    && (stamp.created > previous.created || stamp.version >= previous.version),
                "ZooKeeper transaction rollback rejected"
            );
        }
        let document = crate::config::document::decode(&data, maximum)
            .map_err(|_| anyhow::anyhow!("ZooKeeper declaration rejected"))?;
        let mut close = 5i32.to_be_bytes().to_vec();
        close.extend_from_slice(&(-11i32).to_be_bytes());
        // 只关闭本次读取会话，不写回配置事实；发送失败也不抹去已经取得的完整读取证据。
        let _ = session.send(&close).await;
        *self.cursor.lock() = Some(stamp);
        Ok(document)
    }

    /// 业务作用：新建不可只读降级的会话并完成 digest 认证，不复用旧会话的权限或密码。
    ///
    /// 参数说明：
    /// - `session`：为本轮唯一连接。
    ///
    /// 返回：认证成功后允许只读操作，过期、只读或畸形握手拒绝。
    async fn connect(&self, session: &mut Wire) -> Result<()> {
        let mut request = 0i32.to_be_bytes().to_vec();
        request.extend_from_slice(&0i64.to_be_bytes());
        request.extend_from_slice(&self.session_ms.to_be_bytes());
        request.extend_from_slice(&0i64.to_be_bytes());
        put_buffer(&[0; 16], &mut request);
        request.push(0);
        session.send(&request).await?;
        let response = session.frame(64).await?;
        let mut response = response.as_slice();
        ensure!(
            integer(&mut response)? == 0
                && integer(&mut response)? >= self.wait.as_millis() as i32 + 500
                && long(&mut response)? != 0,
            "ZooKeeper session rejected"
        );
        ensure!(
            buffer(&mut response, 16)?.len() == 16 && response == [0],
            "ZooKeeper read-only session rejected"
        );
        let mut auth = 0i32.to_be_bytes().to_vec();
        put_buffer(b"digest", &mut auth);
        put_buffer(self.auth.as_bytes(), &mut auth);
        ensure!(
            session
                .request(-4, 100, &auth, 16, &self.path)
                .await?
                .is_empty(),
            "ZooKeeper authentication rejected"
        );
        Ok(())
    }

    /// 业务作用：sync 后读取唯一键并验证持久节点元数据，不将同步操作宣传为跨客户端线性一致性。
    ///
    /// 参数说明：
    /// - `session`：为已认证连接
    /// - `maximum`：为正文预算
    /// - `watch`：是否登记单次提示
    /// - `xid`：为本轮固定请求编号。
    ///
    /// 返回：完整正文与事务戳，缺键、临时节点、版本或长度不符拒绝。
    async fn get(
        &self,
        session: &mut Wire,
        maximum: usize,
        watch: bool,
        xid: i32,
    ) -> Result<(Vec<u8>, Stamp)> {
        let mut path = Vec::new();
        put_buffer(self.path.as_bytes(), &mut path);
        let synchronized = session.request(xid, 9, &path, 544, &self.path).await?;
        let mut synchronized = synchronized.as_slice();
        ensure!(
            buffer(&mut synchronized, 512)? == self.path.as_bytes() && synchronized.is_empty(),
            "ZooKeeper sync target mismatch"
        );
        path.push(u8::from(watch));
        let response = session
            .request(xid + 1, 4, &path, maximum + 88, &self.path)
            .await?;
        let mut response = response.as_slice();
        let data = buffer(&mut response, maximum)?;
        let created = long(&mut response)?;
        let modified = long(&mut response)?;
        let _created_time = long(&mut response)?;
        let _modified_time = long(&mut response)?;
        let version = integer(&mut response)?;
        let child_version = integer(&mut response)?;
        let acl_version = integer(&mut response)?;
        let owner = long(&mut response)?;
        let length = integer(&mut response)?;
        let children = integer(&mut response)?;
        let _children_zxid = long(&mut response)?;
        ensure!(
            created > 0
                && modified >= created
                && version >= 0
                && child_version >= 0
                && acl_version >= 0
                && owner == 0
                && length >= 0
                && length as usize == data.len()
                && children >= 0
                && response.is_empty(),
            "ZooKeeper persistent node metadata rejected"
        );
        Ok((
            data.to_vec(),
            Stamp {
                created,
                modified,
                version,
            },
        ))
    }
}
