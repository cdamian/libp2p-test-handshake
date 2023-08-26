use std::pin::Pin;

use asynchronous_codec::{Decoder, Encoder, Framed, FramedParts};
use futures::prelude::*;
use libp2p::{InboundUpgrade, OutboundUpgrade, PeerId};
use libp2p::bytes::BytesMut;
use libp2p::core::UpgradeInfo;
use libp2p::identity::{Keypair, PublicKey};
use unsigned_varint::codec::UviBytes;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct TestHandshake {
    identity: Keypair,
}

#[derive(Serialize, Deserialize)]
struct HandshakeInfo {
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

impl TestHandshake {
    pub fn new(identity: Keypair) -> Self {
        TestHandshake { identity }
    }

    async fn send_handshake_info<T, U>(&self, framed_socket: &mut Framed<T, U>) -> Result<(), TestHandshakeError>
        where
            T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
            U: Encoder<Item=BytesMut>,
    {
        let encoded_key = self.identity.public().encode_protobuf();

        let local_peer_id = PeerId::from(self.identity.public());

        let sig = self.identity.sign(local_peer_id.to_bytes().as_slice())
            .map_err(|_| TestHandshakeError::SigningError)?;

        let handshake_info = HandshakeInfo { public_key: encoded_key, signature: sig };

        let msg = serde_json::to_vec(&handshake_info).map_err(|_| TestHandshakeError::JSONEncodeError)?;

        framed_socket.send(BytesMut::from(msg.as_slice()))
            .await
            .map_err(|_| TestHandshakeError::SendError)?;

        Ok(())
    }

    async fn receive_handshake_info<T, U>(&self, framed_socket: &mut Framed<T, U>) -> Result<(PublicKey, PeerId, Vec<u8>), TestHandshakeError>
        where
            T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
            U: Decoder<Item=BytesMut>,
    {
        let rec = framed_socket.next()
            .await
            .ok_or(TestHandshakeError::AwaitError)?
            .map_err(|_| TestHandshakeError::ReceiveError)?;

        let handshake_info: HandshakeInfo = serde_json::from_slice(&rec).map_err(|_| TestHandshakeError::JSONDecodeError)?;

        let remote_public_key = PublicKey::try_decode_protobuf(&handshake_info.public_key)
            .map_err(|_| TestHandshakeError::KeyDecodeError)?;

        let remote_peer_id = PeerId::from(&remote_public_key);

        Ok((remote_public_key, remote_peer_id, handshake_info.signature))
    }
}

const PROTOCOL_NAME: &str = "/test-handshake";

impl UpgradeInfo for TestHandshake {
    type Info = &'static str;
    type InfoIter = std::iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once(PROTOCOL_NAME)
    }
}

impl<T> InboundUpgrade<T> for TestHandshake
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = (PeerId, T);
    type Error = TestHandshakeError;
    type Future = Pin<Box<dyn Future<Output=Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_inbound(self, socket: T, _: Self::Info) -> Self::Future {
        async move {
            let mut framed_socket = Framed::new(socket, UviBytes::default());

            self.send_handshake_info(&mut framed_socket).await?;

            let (remote_public_key, remote_peer_id, sig) = self.receive_handshake_info(&mut framed_socket).await?;

            if !remote_public_key.verify(remote_peer_id.to_bytes().as_slice(), &sig) {
                return Err(TestHandshakeError::SignatureError);
            }

            let FramedParts { io, .. } = framed_socket.into_parts();

            Ok((remote_peer_id, io))
        }.boxed()
    }
}

impl<T> OutboundUpgrade<T> for TestHandshake
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = (PeerId, T);
    type Error = TestHandshakeError;
    type Future = Pin<Box<dyn Future<Output=Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_outbound(self, socket: T, _: Self::Info) -> Self::Future {
        async move {
            let mut framed_socket = Framed::new(socket, UviBytes::default());

            let (remote_public_key, remote_peer_id, sig) = self.receive_handshake_info(&mut framed_socket).await?;

            if !remote_public_key.verify(remote_peer_id.to_bytes().as_slice(), &sig) {
                return Err(TestHandshakeError::SignatureError);
            }

            self.send_handshake_info(&mut framed_socket).await?;

            let FramedParts { io, .. } = framed_socket.into_parts();

            Ok((remote_peer_id, io))
        }.boxed()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TestHandshakeError {
    #[error("Send error")]
    SendError,
    #[error("Receive error")]
    ReceiveError,
    #[error("Await error")]
    AwaitError,
    #[error("Signing error")]
    SigningError,
    #[error("Signature error")]
    SignatureError,
    #[error("Key decode error")]
    KeyDecodeError,
    #[error("JSON encode error")]
    JSONEncodeError,
    #[error("JSON decode error")]
    JSONDecodeError,
}
