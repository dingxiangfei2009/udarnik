use std::{
    convert::{TryFrom, TryInto},
    ffi::{OsStr, OsString},
    path::PathBuf,
};

use backtrace::Backtrace as Bt;
use cfg_if::cfg_if;
use sss::lattice::{Reconciliator, SessionKeyPart};
use thiserror::Error;

use super::{
    wire, BridgeAsk, BridgeId, BridgeMessage, BridgeNegotiationMessage, BridgeRetract, BridgeType,
    ClientMessage, ClientMessageVariant, GrpcBridge, KeyExchangeMessage, McElieceKeyExchange,
    Message, Params, PayloadFeedback, Pomerium, RLWEKeyExchange, SessionLogOn, StreamRequest,
    UnixBridge,
};
use crate::protocol::{RawShard, RawShardId};

impl From<wire::BridgeId> for BridgeId {
    fn from(id: wire::BridgeId) -> Self {
        Self {
            up: id.up,
            down: id.down,
        }
    }
}

impl From<BridgeId> for wire::BridgeId {
    fn from(id: BridgeId) -> Self {
        Self {
            up: id.up,
            down: id.down,
        }
    }
}

impl<G> From<Message<G>> for wire::Message {
    fn from(message: Message<G>) -> Self {
        Self {
            message: Some(<_>::from(message)),
        }
    }
}

impl<G> From<Message<G>> for wire::message::Message {
    fn from(message: Message<G>) -> Self {
        use wire::message::Message as M;
        match message {
            Message::KeyExchange(kex) => M::KeyExchange(wire::KeyExchange::from(kex)),
            Message::Params(params) => M::Params(params.data),
            Message::Client(msg) => M::Client(wire::ClientMessage::from(msg)),
            Message::Session(session) => M::Session(session.to_string()),
            Message::SessionLogOn(logon) => M::SessionLogOn(wire::SessionLogOn::from(logon)),
            Message::SessionLogOnChallenge(challenge) => M::SessionLogOnChallenge(challenge),
        }
    }
}

impl From<SessionLogOn> for wire::SessionLogOn {
    fn from(logon: SessionLogOn) -> Self {
        Self {
            session: logon.session.to_string(),
            challenge: logon.challenge,
        }
    }
}

impl From<KeyExchangeMessage> for wire::KeyExchange {
    fn from(kex: KeyExchangeMessage) -> Self {
        Self {
            variant: Some(<_>::from(kex)),
        }
    }
}

impl From<KeyExchangeMessage> for wire::key_exchange::Variant {
    fn from(kex: KeyExchangeMessage) -> Self {
        use wire::key_exchange::Variant as V;
        match kex {
            KeyExchangeMessage::RLWE(RLWEKeyExchange::AnkePart {
                part,
                anke_identity,
                boris_identity,
                init_identity,
            }) => V::Rlwe(wire::Rlwe {
                variant: Some(wire::rlwe::Variant::AnkePart(wire::AnkePart {
                    part: part.into_coeff_bytes(),
                    anke_identity: anke_identity.to_string(),
                    boris_identity: boris_identity.to_string(),
                    init_identity: init_identity.to_string(),
                })),
            }),
            KeyExchangeMessage::RLWE(RLWEKeyExchange::BorisPart {
                part,
                reconciliator,
            }) => V::Rlwe(wire::Rlwe {
                variant: Some(wire::rlwe::Variant::BorisPart(wire::BorisPart {
                    part: part.into_coeff_bytes(),
                    reconciliator: reconciliator.into_bytes(),
                })),
            }),
            KeyExchangeMessage::McEliece(McElieceKeyExchange::Anke {
                anke_identity,
                boris_identity,
                c0,
                c1,
            }) => V::Mc(wire::McEliece {
                variant: Some(wire::mc_eliece::Variant::AnkeKey(wire::McAnkeKey {
                    anke_identity: anke_identity.to_string(),
                    boris_identity: boris_identity.to_string(),
                    c0,
                    c1,
                })),
            }),
            KeyExchangeMessage::McEliece(McElieceKeyExchange::Boris { c0, c1 }) => {
                V::Mc(wire::McEliece {
                    variant: Some(wire::mc_eliece::Variant::BorisKey(wire::McBorisKey {
                        c0,
                        c1,
                    })),
                })
            }
        }
    }
}

impl<G> From<ClientMessage<G>> for wire::ClientMessage {
    fn from(msg: ClientMessage<G>) -> Self {
        Self {
            serial: msg.serial,
            session: msg.session.to_string(),
            variant: msg.variant.data,
        }
    }
}

impl From<BridgeMessage> for wire::BridgeMessage {
    fn from(msg: BridgeMessage) -> Self {
        Self {
            variant: Some(<_>::from(msg)),
        }
    }
}

impl From<BridgeMessage> for wire::bridge_message::Variant {
    fn from(msg: BridgeMessage) -> Self {
        use wire::bridge_message::Variant as V;
        match msg {
            BridgeMessage::Payload {
                raw_shard,
                raw_shard_id,
            } => V::Payload(wire::Payload {
                raw_shard: Some(<_>::from(raw_shard)),
                raw_shard_id: Some(<_>::from(raw_shard_id)),
            }),
            BridgeMessage::PayloadFeedback { stream, feedback } => {
                V::PayloadFeedback(wire::PayloadFeedback {
                    stream: stream as u32,
                    inner: Some(wire::PayloadFeedbackInner {
                        variant: Some(<_>::from(feedback)),
                    }),
                })
            }
        }
    }
}

impl From<RawShard> for wire::RawShard {
    fn from(raw_shard: RawShard) -> Self {
        Self {
            raw_data: raw_shard.raw_data,
        }
    }
}

impl From<RawShardId> for wire::RawShardId {
    fn from(raw_shard_id: RawShardId) -> Self {
        Self {
            id_and_stream: raw_shard_id.id as u32 | ((raw_shard_id.stream as u32) << 8),
            serial: raw_shard_id.serial,
        }
    }
}

impl From<PayloadFeedback> for wire::payload_feedback_inner::Variant {
    fn from(feedback: PayloadFeedback) -> Self {
        use wire::payload_feedback_inner::Variant as V;
        match feedback {
            PayloadFeedback::Ok { serial, id, quorum } => V::Ok(wire::FeedbackOk {
                id_and_quorum: id as u32 | ((quorum as u32) << 8),
                serial,
            }),
            PayloadFeedback::Duplicate { serial, id, quorum } => {
                V::Duplicate(wire::FeedbackDuplicate {
                    id_and_quorum: id as u32 | ((quorum as u32) << 8),
                    serial,
                })
            }
            PayloadFeedback::Full { serial, queue_len } => V::Full(wire::FeedbackFull {
                serial,
                queue: queue_len as u32,
            }),
            PayloadFeedback::OutOfBound {
                serial,
                start,
                queue_len,
            } => V::OutOfBound(wire::FeedbackOutOfBound {
                serial,
                start,
                queue: queue_len as u32,
            }),
            PayloadFeedback::Malformed { serial } => {
                V::Malformed(wire::FeedbackMalformed { serial })
            }
            PayloadFeedback::Complete { serial } => V::Complete(wire::FeedbackComplete { serial }),
        }
    }
}

#[derive(Error, Debug)]
pub enum WireError {
    #[error("missing field {0}, backtrace: {1:?}")]
    Missing(String, Bt),
    #[error("malformed messae, {0:?}")]
    Malformed(Bt),
    #[error("invalid integer: {0}")]
    Int(#[from] std::num::TryFromIntError),
    #[error("invalid socket address: {0}")]
    SocketAddr(#[from] std::net::AddrParseError),
}

// impl From<WireError> for GenericError {
//     fn from(e: WireError) -> GenericError {
//         Box::new(e.compat())
//     }
// }

impl<G> TryFrom<wire::Message> for Message<G> {
    type Error = WireError;
    fn try_from(msg: wire::Message) -> Result<Self, Self::Error> {
        Self::try_from(
            msg.message
                .ok_or_else(|| WireError::Missing("message".into(), <_>::default()))?,
        )
    }
}

impl<G> TryFrom<wire::message::Message> for Message<G> {
    type Error = WireError;
    fn try_from(msg: wire::message::Message) -> Result<Self, Self::Error> {
        use wire::message::Message as M;
        Ok(match msg {
            M::KeyExchange(wire::KeyExchange { variant: Some(kex) }) => {
                Self::KeyExchange(<_>::try_from(kex)?)
            }
            M::Params(params) => Self::Params(Pomerium::from_raw(params)),
            M::Client(msg) => Self::Client(ClientMessage::try_from(msg)?),
            M::Session(session) => Self::Session(session.into()),
            M::SessionLogOn(logon) => Self::SessionLogOn(logon.try_into()?),
            M::SessionLogOnChallenge(challenge) => Self::SessionLogOnChallenge(challenge),
            _ => return Err(WireError::Malformed(<_>::default())),
        })
    }
}

impl TryFrom<wire::SessionLogOn> for SessionLogOn {
    type Error = WireError;
    fn try_from(logon: wire::SessionLogOn) -> Result<Self, Self::Error> {
        match logon {
            wire::SessionLogOn { session, challenge } => Ok(Self {
                session: session.into(),
                challenge,
            }),
        }
    }
}

impl TryFrom<wire::key_exchange::Variant> for KeyExchangeMessage {
    type Error = WireError;
    fn try_from(kex: wire::key_exchange::Variant) -> Result<Self, Self::Error> {
        use wire::key_exchange::Variant as V;
        Ok(match kex {
            V::Rlwe(wire::Rlwe {
                variant:
                    Some(wire::rlwe::Variant::AnkePart(wire::AnkePart {
                        part,
                        anke_identity,
                        boris_identity,
                        init_identity,
                    })),
            }) => KeyExchangeMessage::RLWE(RLWEKeyExchange::AnkePart {
                part: SessionKeyPart::from_coeff_bytes(part)
                    .ok_or_else(|| WireError::Malformed(<_>::default()))?,
                anke_identity,
                boris_identity,
                init_identity,
            }),
            V::Rlwe(wire::Rlwe {
                variant:
                    Some(wire::rlwe::Variant::BorisPart(wire::BorisPart {
                        part,
                        reconciliator,
                    })),
            }) => KeyExchangeMessage::RLWE(RLWEKeyExchange::BorisPart {
                part: SessionKeyPart::from_coeff_bytes(part)
                    .ok_or_else(|| WireError::Malformed(<_>::default()))?,
                reconciliator: Reconciliator::from_bytes(reconciliator),
            }),
            V::Mc(wire::McEliece {
                variant:
                    Some(wire::mc_eliece::Variant::AnkeKey(wire::McAnkeKey {
                        anke_identity,
                        boris_identity,
                        c0,
                        c1,
                    })),
            }) => KeyExchangeMessage::McEliece(McElieceKeyExchange::Anke {
                anke_identity: anke_identity.into(),
                boris_identity: boris_identity.into(),
                c0,
                c1,
            }),
            V::Mc(wire::McEliece {
                variant: Some(wire::mc_eliece::Variant::BorisKey(wire::McBorisKey { c0, c1 })),
            }) => KeyExchangeMessage::McEliece(McElieceKeyExchange::Boris { c0, c1 }),
            _ => return Err(WireError::Malformed(<_>::default())),
        })
    }
}

impl<G> TryFrom<wire::ClientMessage> for ClientMessage<G> {
    type Error = WireError;
    fn try_from(msg: wire::ClientMessage) -> Result<Self, Self::Error> {
        Ok(ClientMessage {
            serial: msg.serial,
            session: msg.session.into(),
            variant: Pomerium::from_raw(msg.variant),
        })
    }
}

// Types behind the Pomerium
impl From<Params> for wire::Params {
    fn from(params: Params) -> Self {
        Self {
            correction_and_entropy: params.correction as u32 | ((params.entropy as u32) << 8),
            window: params.window as u32,
        }
    }
}

impl From<ClientMessageVariant> for wire::ClientMessageVariant {
    fn from(msg: ClientMessageVariant) -> Self {
        use wire::client_message_variant::Variant as V;
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

impl From<StreamRequest> for wire::StreamRequest {
    fn from(msg: StreamRequest) -> Self {
        use wire::stream_request::Variant as V;
        Self {
            variant: Some(match msg {
                StreamRequest::Reset { stream, window } => V::Reset(wire::StreamReset {
                    stream: stream as u32,
                    window: window as u32,
                }),
            }),
        }
    }
}

impl From<BridgeNegotiationMessage> for wire::BridgeNegotiate {
    fn from(msg: BridgeNegotiationMessage) -> Self {
        use wire::bridge_negotiate::Variant as V;
        Self {
            variant: Some(match msg {
                BridgeNegotiationMessage::Ask(asks) => V::Ask(wire::BridgeAsk {
                    asks: asks.into_iter().map(<_>::from).collect(),
                }),
                BridgeNegotiationMessage::Retract(retracts) => V::Retract(wire::BridgeRetract {
                    retracts: retracts
                        .into_iter()
                        .map(|BridgeRetract(id)| <_>::from(id))
                        .collect(),
                }),
                BridgeNegotiationMessage::AskProposal(asks) => V::AskProposal(wire::BridgeAsk {
                    asks: asks.into_iter().map(<_>::from).collect(),
                }),
                BridgeNegotiationMessage::ProposeAsk => V::ProposeAsk(true),
                BridgeNegotiationMessage::QueryHealth => V::QueryHealth(true),
                BridgeNegotiationMessage::Health(health) => V::Health(wire::Health {
                    report: health
                        .into_iter()
                        .map(|(id, count)| wire::HealthReport {
                            id: Some(<_>::from(id)),
                            count,
                        })
                        .collect(),
                }),
            }),
        }
    }
}

impl From<BridgeAsk> for wire::BridgeSpec {
    fn from(BridgeAsk { r#type, id }: BridgeAsk) -> Self {
        Self {
            bridge_type: Some(r#type.into()),
            id: Some(<_>::from(id)),
        }
    }
}

impl From<BridgeType> for wire::BridgeType {
    fn from(typ: BridgeType) -> Self {
        use wire::bridge_type::Variant as V;
        Self {
            variant: Some(match typ {
                BridgeType::Grpc(typ) => V::Grpc(typ.into()),
                BridgeType::Unix(UnixBridge { addr, id, up, down }) => {
                    let path;
                    cfg_if! {
                        if #[cfg(target_family = "unix")] {
                            use std::os::unix::ffi::OsStrExt;
                            path = addr.as_os_str().as_bytes().to_vec();
                        } else {
                            todo!("don't know handle this");
                            path = vec![];
                        }
                    };
                    V::Unix(wire::BridgeUnix {
                        addr: path,
                        id: Some(<_>::from(id)),
                        up: up.to_vec(),
                        down: down.to_vec(),
                    })
                }
            }),
        }
    }
}

impl From<GrpcBridge> for wire::BridgeGrpc {
    fn from(GrpcBridge { id, addr, up, down }: GrpcBridge) -> Self {
        Self {
            endpoint: addr.iter().map(ToString::to_string).collect(),
            id: Some(<_>::from(id)),
            up: up.to_vec(),
            down: down.to_vec(),
        }
    }
}

impl TryFrom<wire::Params> for Params {
    type Error = WireError;
    fn try_from(params: wire::Params) -> Result<Self, Self::Error> {
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

impl TryFrom<wire::ClientMessageVariant> for ClientMessageVariant {
    type Error = WireError;
    fn try_from(msg: wire::ClientMessageVariant) -> Result<Self, Self::Error> {
        use wire::client_message_variant::Variant as V;
        let wire::ClientMessageVariant { variant } = msg;
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

impl TryFrom<wire::BridgeNegotiate> for BridgeNegotiationMessage {
    type Error = WireError;
    fn try_from(msg: wire::BridgeNegotiate) -> Result<Self, Self::Error> {
        use wire::bridge_negotiate::Variant as V;
        let wire::BridgeNegotiate { variant } = msg;
        if let Some(variant) = variant {
            Ok(match variant {
                V::Ask(wire::BridgeAsk { asks }) => {
                    let asks = asks
                        .into_iter()
                        .map(BridgeAsk::try_from)
                        .collect::<Result<Vec<_>, _>>()?;
                    BridgeNegotiationMessage::Ask(asks)
                }
                V::Retract(wire::BridgeRetract { retracts }) => {
                    let retracts = retracts
                        .into_iter()
                        .map(BridgeId::from)
                        .map(<_>::from)
                        .collect();
                    BridgeNegotiationMessage::Retract(retracts)
                }
                V::AskProposal(wire::BridgeAsk { asks }) => {
                    let asks = asks
                        .into_iter()
                        .map(BridgeAsk::try_from)
                        .collect::<Result<Vec<_>, _>>()?;
                    BridgeNegotiationMessage::AskProposal(asks)
                }
                V::ProposeAsk(_) => BridgeNegotiationMessage::ProposeAsk,
                V::QueryHealth(_) => BridgeNegotiationMessage::QueryHealth,
                V::Health(wire::Health { report }) => BridgeNegotiationMessage::Health(
                    report
                        .into_iter()
                        .map(|wire::HealthReport { id, count }| {
                            if let Some(id) = id {
                                Ok((<_>::from(id), count))
                            } else {
                                Err(WireError::Malformed(<_>::default()))
                            }
                        })
                        .collect::<Result<_, WireError>>()?,
                ),
            })
        } else {
            Err(WireError::Malformed(<_>::default()))
        }
    }
}

impl TryFrom<wire::BridgeSpec> for BridgeAsk {
    type Error = WireError;
    fn try_from(msg: wire::BridgeSpec) -> Result<Self, Self::Error> {
        match msg {
            wire::BridgeSpec {
                id: Some(id),
                bridge_type: Some(bridge_type),
            } => Ok(Self {
                id: id.into(),
                r#type: bridge_type.try_into()?,
            }),
            _ => Err(WireError::Malformed(<_>::default())),
        }
    }
}

impl TryFrom<wire::BridgeType> for BridgeType {
    type Error = WireError;
    fn try_from(msg: wire::BridgeType) -> Result<Self, Self::Error> {
        use wire::bridge_type::Variant as V;
        if let wire::BridgeType {
            variant: Some(variant),
        } = msg
        {
            Ok(match variant {
                V::Grpc(wire::BridgeGrpc {
                    id: Some(id),
                    up,
                    down,
                    endpoint,
                }) => {
                    if up.len() != 32 || down.len() != 32 {
                        return Err(WireError::Malformed(<_>::default()));
                    }
                    let mut up_key = [0; 32];
                    let mut down_key = [0; 32];
                    up_key.copy_from_slice(&up);
                    down_key.copy_from_slice(&down);
                    BridgeType::Grpc(GrpcBridge {
                        addr: endpoint
                            .iter()
                            .map(|addr| addr.parse())
                            .collect::<Result<Vec<_>, _>>()?,
                        id: id.into(),
                        up: up_key,
                        down: down_key,
                    })
                }
                V::Unix(wire::BridgeUnix {
                    addr,
                    id: Some(id),
                    up,
                    down,
                }) => {
                    if up.len() != 32 || down.len() != 32 {
                        return Err(WireError::Malformed(<_>::default()));
                    }
                    let mut up_key = [0; 32];
                    let mut down_key = [0; 32];
                    up_key.copy_from_slice(&up);
                    down_key.copy_from_slice(&down);
                    let path;
                    cfg_if::cfg_if! {
                        if #[cfg(target_family = "unix")] {
                            path = <OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(&addr);
                        } else {
                            path = <OsStr as std::os::windows::ffi::OsStrExt>::from_bytes(&addr);
                        }
                    };
                    let path = OsString::from(path);
                    BridgeType::Unix(UnixBridge {
                        addr: PathBuf::from(path),
                        id: id.into(),
                        up: up_key,
                        down: down_key,
                    })
                }
                _ => return Err(WireError::Malformed(<_>::default())),
            })
        } else {
            Err(WireError::Malformed(<_>::default()))
        }
    }
}

impl TryFrom<wire::StreamRequest> for StreamRequest {
    type Error = WireError;
    fn try_from(msg: wire::StreamRequest) -> Result<Self, Self::Error> {
        use wire::stream_request::Variant as V;
        if let wire::StreamRequest {
            variant: Some(variant),
        } = msg
        {
            Ok(match variant {
                V::Reset(wire::StreamReset { stream, window }) => StreamRequest::Reset {
                    stream: u8::try_from(stream)?,
                    window: usize::try_from(window)?,
                },
            })
        } else {
            Err(WireError::Malformed(<_>::default()))
        }
    }
}

impl TryFrom<wire::BridgeMessage> for BridgeMessage {
    type Error = WireError;
    fn try_from(msg: wire::BridgeMessage) -> Result<Self, Self::Error> {
        use wire::bridge_message::Variant as V;
        if let wire::BridgeMessage {
            variant: Some(variant),
        } = msg
        {
            Ok(match variant {
                V::Payload(wire::Payload {
                    raw_shard: Some(wire::RawShard { raw_data }),
                    raw_shard_id:
                        Some(wire::RawShardId {
                            id_and_stream,
                            serial,
                        }),
                }) => {
                    let id = (id_and_stream & 0xff) as u8;
                    let stream = (id_and_stream >> 8) as u8;
                    BridgeMessage::Payload {
                        raw_shard: RawShard { raw_data },
                        raw_shard_id: RawShardId { id, stream, serial },
                    }
                }
                V::PayloadFeedback(wire::PayloadFeedback {
                    stream,
                    inner:
                        Some(wire::PayloadFeedbackInner {
                            variant: Some(variant),
                        }),
                }) => {
                    use wire::payload_feedback_inner::Variant as V;
                    BridgeMessage::PayloadFeedback {
                        stream: stream.try_into()?,
                        feedback: match variant {
                            V::Ok(wire::FeedbackOk {
                                id_and_quorum,
                                serial,
                            }) => {
                                let id = (id_and_quorum & 0xff) as u8;
                                let quorum = (id_and_quorum >> 8) as u8;
                                PayloadFeedback::Ok { serial, id, quorum }
                            }
                            V::Duplicate(wire::FeedbackDuplicate {
                                id_and_quorum,
                                serial,
                            }) => {
                                let id = (id_and_quorum & 0xff) as u8;
                                let quorum = (id_and_quorum >> 8) as u8;
                                PayloadFeedback::Ok { serial, id, quorum }
                            }
                            V::Full(wire::FeedbackFull { serial, queue }) => {
                                PayloadFeedback::Full {
                                    serial,
                                    queue_len: queue.try_into()?,
                                }
                            }
                            V::OutOfBound(wire::FeedbackOutOfBound {
                                serial,
                                start,
                                queue,
                            }) => PayloadFeedback::OutOfBound {
                                serial,
                                start,
                                queue_len: queue.try_into()?,
                            },
                            V::Malformed(wire::FeedbackMalformed { serial }) => {
                                PayloadFeedback::Malformed { serial }
                            }
                            V::Complete(wire::FeedbackComplete { serial }) => {
                                PayloadFeedback::Complete { serial }
                            }
                        },
                    }
                }
                _ => return Err(WireError::Malformed(<_>::default())),
            })
        } else {
            Err(WireError::Malformed(<_>::default()))
        }
    }
}
