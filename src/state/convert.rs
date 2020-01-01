use std::convert::{TryFrom, TryInto};

use failure::{Backtrace, Fail};
use sss::lattice::{Reconciliator, SessionKeyPart};

use super::{
    protocol, BridgeAsk, BridgeId, BridgeMessage, BridgeNegotiationMessage, BridgeType,
    ClientMessage, ClientMessageVariant, GrpcBridge, KeyExchangeMessage, Message, Params,
    PayloadFeedback, Pomerium, StreamRequest,
};
use crate::{
    protocol::{RawShard, RawShardId},
    Redact,
};

impl<G> From<Message<G>> for protocol::Message {
    fn from(message: Message<G>) -> Self {
        Self {
            message: Some(<_>::from(message)),
        }
    }
}

impl<G> From<Message<G>> for protocol::message::Message {
    fn from(message: Message<G>) -> Self {
        use protocol::message::Message as M;
        match message {
            Message::KeyExchange(kex) => M::KeyExchange(protocol::KeyExchange::from(kex)),
            Message::Params(Redact(params)) => M::Params(params.data),
            Message::Client(msg) => M::Client(protocol::ClientMessage::from(msg)),
        }
    }
}

impl From<KeyExchangeMessage> for protocol::KeyExchange {
    fn from(kex: KeyExchangeMessage) -> Self {
        Self {
            variant: Some(<_>::from(kex)),
        }
    }
}

impl From<KeyExchangeMessage> for protocol::key_exchange::Variant {
    fn from(kex: KeyExchangeMessage) -> Self {
        use protocol::key_exchange::Variant as V;
        match kex {
            KeyExchangeMessage::Offer(ident, init_ident) => V::Offer(protocol::Offer {
                identity: ident.to_string(),
                init_identity: init_ident.to_string(),
            }),
            KeyExchangeMessage::Accept(ident, init_ident) => V::Accept(protocol::Accept {
                identity: ident.to_string(),
                init_identity: init_ident.to_string(),
            }),
            KeyExchangeMessage::Reject(ident, init_ident) => V::Reject(protocol::Reject {
                identity: ident.to_string(),
                init_identity: init_ident.to_string(),
            }),
            KeyExchangeMessage::AnkePart(Redact(part)) => V::AnkePart(protocol::AnkePart {
                part: part.into_coeff_bytes(),
            }),
            KeyExchangeMessage::BorisPart(Redact(part), Redact(recon)) => {
                V::BorisPart(protocol::BorisPart {
                    part: part.into_coeff_bytes(),
                    reconciliator: recon.into_bytes(),
                })
            }
        }
    }
}

impl<G> From<ClientMessage<G>> for protocol::ClientMessage {
    fn from(msg: ClientMessage<G>) -> Self {
        Self {
            serial: msg.serial,
            session: msg.session.to_string(),
            variant: msg.variant.0.data,
        }
    }
}

impl From<BridgeMessage> for protocol::BridgeMessage {
    fn from(msg: BridgeMessage) -> Self {
        Self {
            variant: Some(<_>::from(msg)),
        }
    }
}

impl From<BridgeMessage> for protocol::bridge_message::Variant {
    fn from(msg: BridgeMessage) -> Self {
        use protocol::bridge_message::Variant as V;
        match msg {
            BridgeMessage::Payload {
                raw_shard,
                raw_shard_id,
            } => V::Payload(protocol::Payload {
                raw_shard: Some(<_>::from(raw_shard)),
                raw_shard_id: Some(<_>::from(raw_shard_id)),
            }),
            BridgeMessage::PayloadFeedback { stream, feedback } => {
                V::PayloadFeedback(protocol::PayloadFeedback {
                    stream: stream as u32,
                    inner: Some(protocol::PayloadFeedbackInner {
                        variant: Some(<_>::from(feedback)),
                    }),
                })
            }
        }
    }
}

impl From<RawShard> for protocol::RawShard {
    fn from(raw_shard: RawShard) -> Self {
        Self {
            raw_data: raw_shard.raw_data,
        }
    }
}

impl From<RawShardId> for protocol::RawShardId {
    fn from(raw_shard_id: RawShardId) -> Self {
        Self {
            id_and_stream: raw_shard_id.id as u32 | ((raw_shard_id.stream as u32) << 8),
            serial: raw_shard_id.serial,
        }
    }
}

impl From<PayloadFeedback> for protocol::payload_feedback_inner::Variant {
    fn from(feedback: PayloadFeedback) -> Self {
        use protocol::payload_feedback_inner::Variant as V;
        match feedback {
            PayloadFeedback::Ok { serial, id, quorum } => V::Ok(protocol::FeedbackOk {
                id_and_quorum: id as u32 | ((quorum as u32) << 8),
                serial,
            }),
            PayloadFeedback::Duplicate { serial, id, quorum } => {
                V::Duplicate(protocol::FeedbackDuplicate {
                    id_and_quorum: id as u32 | ((quorum as u32) << 8),
                    serial,
                })
            }
            PayloadFeedback::Full { serial, queue_len } => V::Full(protocol::FeedbackFull {
                serial,
                queue: queue_len as u32,
            }),
            PayloadFeedback::OutOfBound {
                serial,
                start,
                queue_len,
            } => V::OutOfBound(protocol::FeedbackOutOfBound {
                serial,
                start,
                queue: queue_len as u32,
            }),
            PayloadFeedback::Malformed { serial } => {
                V::Malformed(protocol::FeedbackMalformed { serial })
            }
            PayloadFeedback::Complete { serial } => {
                V::Complete(protocol::FeedbackComplete { serial })
            }
        }
    }
}

#[derive(Fail, Debug, From)]
pub enum WireError {
    #[fail(display = "missing field {}", _0)]
    Missing(String, Backtrace),
    #[fail(display = "malformed messae")]
    Malformed(Backtrace),
    #[fail(display = "invalid integer: {}", _0)]
    Int(#[cause] std::num::TryFromIntError),
    #[fail(display = "invalid socket address: {}", _0)]
    SocketAddr(#[cause] std::net::AddrParseError),
}

impl<G> TryFrom<protocol::Message> for Message<G> {
    type Error = WireError;
    fn try_from(msg: protocol::Message) -> Result<Self, Self::Error> {
        Self::try_from(
            msg.message
                .ok_or_else(|| WireError::Missing("message".into(), <_>::default()))?,
        )
    }
}

impl<G> TryFrom<protocol::message::Message> for Message<G> {
    type Error = WireError;
    fn try_from(msg: protocol::message::Message) -> Result<Self, Self::Error> {
        use protocol::message::Message as M;
        Ok(match msg {
            M::KeyExchange(protocol::KeyExchange { variant: Some(kex) }) => {
                Self::KeyExchange(<_>::try_from(kex)?)
            }
            M::Params(params) => Self::Params(Redact(Pomerium::from_raw(params))),
            M::Client(msg) => Self::Client(ClientMessage::try_from(msg)?),
            _ => return Err(WireError::Malformed(<_>::default())),
        })
    }
}

impl TryFrom<protocol::key_exchange::Variant> for KeyExchangeMessage {
    type Error = WireError;
    fn try_from(kex: protocol::key_exchange::Variant) -> Result<Self, Self::Error> {
        use protocol::key_exchange::Variant as V;
        Ok(match kex {
            V::Offer(protocol::Offer {
                identity,
                init_identity,
            }) => KeyExchangeMessage::Offer(identity.into(), init_identity.into()),
            V::Accept(protocol::Accept {
                identity,
                init_identity,
            }) => KeyExchangeMessage::Accept(identity.into(), init_identity.into()),
            V::Reject(protocol::Reject {
                identity,
                init_identity,
            }) => KeyExchangeMessage::Reject(identity.into(), init_identity.into()),
            V::AnkePart(protocol::AnkePart { part }) => KeyExchangeMessage::AnkePart(Redact(
                SessionKeyPart::from_coeff_bytes(part)
                    .ok_or_else(|| WireError::Malformed(<_>::default()))?,
            )),
            V::BorisPart(protocol::BorisPart {
                part,
                reconciliator,
            }) => KeyExchangeMessage::BorisPart(
                Redact(
                    SessionKeyPart::from_coeff_bytes(part)
                        .ok_or_else(|| WireError::Malformed(<_>::default()))?,
                ),
                Redact(Reconciliator::from_bytes(reconciliator)),
            ),
        })
    }
}

impl<G> TryFrom<protocol::ClientMessage> for ClientMessage<G> {
    type Error = WireError;
    fn try_from(msg: protocol::ClientMessage) -> Result<Self, Self::Error> {
        Ok(ClientMessage {
            serial: msg.serial,
            session: msg.session.into(),
            variant: Redact(Pomerium::from_raw(msg.variant)),
        })
    }
}

// Types behind the Pomerium
impl From<Params> for protocol::Params {
    fn from(params: Params) -> Self {
        Self {
            correction_and_entropy: params.correction as u32 | ((params.entropy as u32) << 8),
            window: params.window as u32,
        }
    }
}

impl From<ClientMessageVariant> for protocol::ClientMessageVariant {
    fn from(msg: ClientMessageVariant) -> Self {
        use protocol::client_message_variant::Variant as V;
        Self {
            variant: Some(match msg {
                ClientMessageVariant::BridgeNegotiate(msg) => V::BridgeNegotiate(msg.into()),
                ClientMessageVariant::Stream(msg) => V::Stream(msg.into()),
                ClientMessageVariant::Ok => V::Ok(true),
                ClientMessageVariant::Err => V::Err(true),
            }),
        }
    }
}

impl From<StreamRequest> for protocol::StreamRequest {
    fn from(msg: StreamRequest) -> Self {
        use protocol::stream_request::Variant as V;
        Self {
            variant: Some(match msg {
                StreamRequest::Reset { stream, window } => V::Reset(protocol::StreamReset {
                    stream: stream as u32,
                    window: window as u32,
                }),
            }),
        }
    }
}

impl From<BridgeNegotiationMessage> for protocol::BridgeNegotiate {
    fn from(msg: BridgeNegotiationMessage) -> Self {
        use protocol::bridge_negotiate::Variant as V;
        Self {
            variant: Some(match msg {
                BridgeNegotiationMessage::Ask(asks) => V::Ask(protocol::BridgeAsk {
                    asks: asks.into_iter().map(<_>::from).collect(),
                }),
                BridgeNegotiationMessage::Retract(retracts) => {
                    V::Retract(protocol::BridgeRetract {
                        retracts: retracts.into_iter().map(|r| r.0.to_string()).collect(),
                    })
                }
                BridgeNegotiationMessage::AskProposal(asks) => {
                    V::AskProposal(protocol::BridgeAsk {
                        asks: asks.into_iter().map(<_>::from).collect(),
                    })
                }
                BridgeNegotiationMessage::ProposeAsk => V::ProposeAsk(true),
                BridgeNegotiationMessage::QueryHealth => V::QueryHealth(true),
                BridgeNegotiationMessage::Health(health) => V::Health(protocol::Health {
                    report: health
                        .into_iter()
                        .map(|(id, count)| (id.to_string(), count))
                        .collect(),
                }),
            }),
        }
    }
}

impl From<BridgeAsk> for protocol::BridgeSpec {
    fn from(msg: BridgeAsk) -> Self {
        Self {
            bridge_type: Some(msg.r#type.into()),
            id: msg.id.to_string(),
        }
    }
}

impl From<BridgeType> for protocol::BridgeType {
    fn from(typ: BridgeType) -> Self {
        use protocol::bridge_type::Variant as V;
        Self {
            variant: Some(match typ {
                BridgeType::Grpc(typ) => V::Grpc(typ.into()),
            }),
        }
    }
}

impl From<GrpcBridge> for protocol::BridgeGrpc {
    fn from(grpc: GrpcBridge) -> Self {
        Self {
            endpoint: grpc.0.to_string(),
        }
    }
}

impl TryFrom<protocol::Params> for Params {
    type Error = WireError;
    fn try_from(params: protocol::Params) -> Result<Self, Self::Error> {
        let correction_and_entropy = u16::try_from(params.correction_and_entropy)?;
        let correction = (correction_and_entropy & 0xff) as u8;
        let entropy = (correction_and_entropy >> 8) as u8;
        Ok(Self {
            correction,
            entropy,
            window: usize::try_from(params.window)?,
        })
    }
}

impl TryFrom<protocol::ClientMessageVariant> for ClientMessageVariant {
    type Error = WireError;
    fn try_from(msg: protocol::ClientMessageVariant) -> Result<Self, Self::Error> {
        use protocol::client_message_variant::Variant as V;
        let protocol::ClientMessageVariant { variant } = msg;
        if let Some(variant) = variant {
            Ok(match variant {
                V::BridgeNegotiate(msg) => ClientMessageVariant::BridgeNegotiate(msg.try_into()?),
                V::Stream(msg) => ClientMessageVariant::Stream(msg.try_into()?),
                V::Ok(_) => ClientMessageVariant::Ok,
                V::Err(_) => ClientMessageVariant::Err,
            })
        } else {
            Err(WireError::Malformed(<_>::default()))
        }
    }
}

impl TryFrom<protocol::BridgeNegotiate> for BridgeNegotiationMessage {
    type Error = WireError;
    fn try_from(msg: protocol::BridgeNegotiate) -> Result<Self, Self::Error> {
        use protocol::bridge_negotiate::Variant as V;
        let protocol::BridgeNegotiate { variant } = msg;
        if let Some(variant) = variant {
            Ok(match variant {
                V::Ask(protocol::BridgeAsk { asks }) => {
                    let asks = asks
                        .into_iter()
                        .map(BridgeAsk::try_from)
                        .collect::<Result<Vec<_>, _>>()?;
                    BridgeNegotiationMessage::Ask(asks)
                }
                V::Retract(protocol::BridgeRetract { retracts }) => {
                    let retracts = retracts
                        .into_iter()
                        .map(BridgeId::from)
                        .map(<_>::from)
                        .collect();
                    BridgeNegotiationMessage::Retract(retracts)
                }
                V::AskProposal(protocol::BridgeAsk { asks }) => {
                    let asks = asks
                        .into_iter()
                        .map(BridgeAsk::try_from)
                        .collect::<Result<Vec<_>, _>>()?;
                    BridgeNegotiationMessage::AskProposal(asks)
                }
                V::ProposeAsk(_) => BridgeNegotiationMessage::ProposeAsk,
                V::QueryHealth(_) => BridgeNegotiationMessage::QueryHealth,
                V::Health(protocol::Health { report }) => BridgeNegotiationMessage::Health(
                    report
                        .into_iter()
                        .map(|(id, count)| (id.into(), count))
                        .collect(),
                ),
            })
        } else {
            Err(WireError::Malformed(<_>::default()))
        }
    }
}

impl TryFrom<protocol::BridgeSpec> for BridgeAsk {
    type Error = WireError;
    fn try_from(msg: protocol::BridgeSpec) -> Result<Self, Self::Error> {
        match msg {
            protocol::BridgeSpec {
                id,
                bridge_type: Some(bridge_type),
            } => Ok(Self {
                id: id.into(),
                r#type: bridge_type.try_into()?,
            }),
            _ => Err(WireError::Malformed(<_>::default())),
        }
    }
}

impl TryFrom<protocol::BridgeType> for BridgeType {
    type Error = WireError;
    fn try_from(msg: protocol::BridgeType) -> Result<Self, Self::Error> {
        use protocol::bridge_type::Variant as V;
        if let protocol::BridgeType {
            variant: Some(variant),
        } = msg
        {
            Ok(match variant {
                V::Grpc(protocol::BridgeGrpc { endpoint }) => {
                    BridgeType::Grpc(GrpcBridge(endpoint.parse()?))
                }
            })
        } else {
            Err(WireError::Malformed(<_>::default()))
        }
    }
}

impl TryFrom<protocol::StreamRequest> for StreamRequest {
    type Error = WireError;
    fn try_from(msg: protocol::StreamRequest) -> Result<Self, Self::Error> {
        use protocol::stream_request::Variant as V;
        if let protocol::StreamRequest {
            variant: Some(variant),
        } = msg
        {
            Ok(match variant {
                V::Reset(protocol::StreamReset { stream, window }) => StreamRequest::Reset {
                    stream: u8::try_from(stream)?,
                    window: usize::try_from(window)?,
                },
            })
        } else {
            Err(WireError::Malformed(<_>::default()))
        }
    }
}
