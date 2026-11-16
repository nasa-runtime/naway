//! 黑名单变更通知的有界业务身份与接收端验证合同。

mod event;
#[cfg(feature = "acl-kafka")]
mod kafka;
mod plan;
mod receiver;
#[cfg(feature = "acl-rocketmq")]
mod rocketmq;
mod runtime;
mod transport;

pub use event::{Action, Event, EventFactory, Source, MAX_EVENT_BYTES};
pub use plan::{dependencies, Plan};
pub use receiver::{sign_webhook, verify_webhook, Admission, VerifiedEvent};
pub use runtime::Runtime;
pub use transport::AclNotifier;
