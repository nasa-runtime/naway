//! apache.rocketmq.v2普通消息所需的选择性字段；不声明消费、事务或长期遥测会话。

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Resource {
    #[prost(string, tag = "1")]
    pub namespace: String,
    #[prost(string, tag = "2")]
    pub name: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Address {
    #[prost(string, tag = "1")]
    pub host: String,
    #[prost(int32, tag = "2")]
    pub port: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Endpoints {
    #[prost(int32, tag = "1")]
    pub scheme: i32,
    #[prost(message, repeated, tag = "2")]
    pub addresses: Vec<Address>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct QueryRouteRequest {
    #[prost(message, optional, tag = "1")]
    pub topic: Option<Resource>,
    #[prost(message, optional, tag = "2")]
    pub endpoints: Option<Endpoints>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Status {
    #[prost(int32, tag = "1")]
    pub code: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Broker {
    #[prost(int32, tag = "2")]
    pub id: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct MessageQueue {
    #[prost(message, optional, tag = "1")]
    pub topic: Option<Resource>,
    #[prost(int32, tag = "2")]
    pub id: i32,
    #[prost(int32, tag = "3")]
    pub permission: i32,
    #[prost(message, optional, tag = "4")]
    pub broker: Option<Broker>,
    #[prost(int32, repeated, tag = "5")]
    pub accepted_types: Vec<i32>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct QueryRouteResponse {
    #[prost(message, optional, tag = "1")]
    pub status: Option<Status>,
    #[prost(message, repeated, tag = "2")]
    pub queues: Vec<MessageQueue>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct SystemProperties {
    #[prost(string, repeated, tag = "2")]
    pub keys: Vec<String>,
    #[prost(string, tag = "3")]
    pub message_id: String,
    #[prost(int32, tag = "5")]
    pub body_encoding: i32,
    #[prost(int32, tag = "6")]
    pub message_type: i32,
    #[prost(message, optional, tag = "7")]
    pub born_timestamp: Option<prost_types::Timestamp>,
    #[prost(string, tag = "8")]
    pub born_host: String,
    #[prost(int32, tag = "13")]
    pub queue_id: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Message {
    #[prost(message, optional, tag = "1")]
    pub topic: Option<Resource>,
    #[prost(btree_map = "string, string", tag = "2")]
    pub properties: std::collections::BTreeMap<String, String>,
    #[prost(message, optional, tag = "3")]
    pub system: Option<SystemProperties>,
    #[prost(bytes = "vec", tag = "4")]
    pub body: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct SendMessageRequest {
    #[prost(message, repeated, tag = "1")]
    pub messages: Vec<Message>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct SendResult {
    #[prost(message, optional, tag = "1")]
    pub status: Option<Status>,
    #[prost(string, tag = "2")]
    pub message_id: String,
    #[prost(int64, tag = "4")]
    pub offset: i64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct SendMessageResponse {
    #[prost(message, optional, tag = "1")]
    pub status: Option<Status>,
    #[prost(message, repeated, tag = "2")]
    pub results: Vec<SendResult>,
}
