use messages;
use futures::future;
use futures::sync::oneshot;
use tokio_service::Service;
use keystore::KeyStore;
use failure;
use bytes::BytesMut;
use serde_cbor;
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
use service::DaemonService;
use void::{ResultVoidExt, Void};

use std::cell::Cell;
use std::io;

pub struct DaemonServiceImpl {
    shutdown_channel: Cell<Option<oneshot::Sender<()>>>,
    keystore: KeyStore,
}

impl DaemonServiceImpl {
    pub fn new(shutdown_channel: oneshot::Sender<()>) -> Result<DaemonServiceImpl, failure::Error> {
        Ok(DaemonServiceImpl {
            shutdown_channel: Cell::new(Some(shutdown_channel)),
            keystore: KeyStore::new()?,
        })
    }
}

impl DaemonServiceImpl {
    fn dispatch(&self, request: &[u8]) -> Result<Vec<u8>, serde_cbor::error::Error> {
        use messages::Request;

        match serde_cbor::from_slice(request)? {
            Request::List => serde_cbor::to_vec(&self.list().void_unwrap()),
            Request::AddKey {
                public_key,
                secret_key,
            } => serde_cbor::to_vec(&self.add_key(public_key, secret_key).void_unwrap()),
            Request::RemoveKey { public_key } => {
                serde_cbor::to_vec(&self.remove_key(public_key).void_unwrap())
            }
            Request::Precompute {
                public_key,
                ephemeral_public_key,
            } => serde_cbor::to_vec(&self.precompute(public_key, ephemeral_public_key)
                .void_unwrap()),
            Request::Shutdown => serde_cbor::to_vec(&self.shutdown().void_unwrap()),
        }
    }
}

impl<'a> DaemonService for &'a DaemonServiceImpl {
    type Error = Void;
    fn list(self) -> Result<messages::ListResponse, Void> {
        Ok(messages::ListResponse(self.keystore.list_keys()))
    }

    fn add_key(
        self,
        public_key: PublicKey,
        secret_key: SecretKey,
    ) -> Result<messages::AddKeyResponse, Void> {
        Ok(self.keystore.add_key(public_key, secret_key).into())
    }

    fn remove_key(self, public_key: PublicKey) -> Result<messages::RemoveKeyResponse, Void> {
        Ok(self.keystore.remove_key(&public_key).into())
    }

    fn precompute(
        self,
        public_key: PublicKey,
        ephemeral_public_key: PublicKey,
    ) -> Result<messages::PrecomputeResponse, Void> {
        Ok(self.keystore
            .precompute(&public_key, &ephemeral_public_key)
            .into())
    }

    fn shutdown(self) -> Result<messages::ShutdownResponse, Void> {
        self.shutdown_channel.replace(None).map(|c| {
            c.send(())
                .map_err(|_| ())
                .expect("Could not send shutdown signal")
        });
        Ok(messages::ShutdownResponse::Ok)
    }
}

impl Service for DaemonServiceImpl {
    type Request = BytesMut;
    type Response = Vec<u8>;

    // For non-streaming protocols, service errors are always io::Error
    type Error = io::Error;

    // The future for computing the response; box it for simplicity.
    type Future = future::FutureResult<Self::Response, Self::Error>;

    // Produce a future for computing a response from a request.
    fn call(&self, request: BytesMut) -> Self::Future {
        future::result(
            self.dispatch(&request)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, Box::new(err))),
        )
    }
}
