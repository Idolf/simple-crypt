use tokio_core::reactor::Core;
use tokio_proto::{pipeline, BindClient};
use failure::{Error, ResultExt};
use tokio_uds::UnixStream;
use tokio_service::Service;
use serde::de::DeserializeOwned;
use serde_cbor;
use futures::Future;
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};

use proto;
use messages;
use service::DaemonService;

pub struct Client {
    core: Core,
    client: pipeline::ClientService<UnixStream, proto::Proto>,
}

impl Client {
    pub fn new() -> Result<Client, Error> {
        let core = Core::new().unwrap();
        let handle = core.handle();
        let proto = proto::Proto::new();
        let stream = proto.connect(&handle)?;
        let client = proto.bind_client(&handle, stream);

        Ok(Client { core, client })
    }

    fn request<T: DeserializeOwned>(&mut self, msg: &messages::Request) -> Result<T, Error> {
        let future = self.client
            .call(serde_cbor::to_vec(&msg).context("could not serialize request")?)
            .map_err(Error::from)
            .and_then(|reply| {
                serde_cbor::from_slice(&reply)
                    .context("could not deserialize reply")
                    .map_err(Error::from)
            });
        self.core.run(future)
    }
}

impl<'a> DaemonService for &'a mut Client {
    type Error = Error;
    fn list(self) -> Result<messages::ListResponse, Error> {
        self.request(&messages::Request::List)
    }

    fn add_key(
        self,
        public_key: PublicKey,
        secret_key: SecretKey,
    ) -> Result<messages::AddKeyResponse, Error> {
        self.request(&messages::Request::AddKey {
            public_key,
            secret_key,
        })
    }

    fn remove_key(self, public_key: PublicKey) -> Result<messages::RemoveKeyResponse, Error> {
        self.request(&messages::Request::RemoveKey { public_key })
    }

    fn precompute(
        self,
        public_key: PublicKey,
        ephemeral_public_key: PublicKey,
    ) -> Result<messages::PrecomputeResponse, Error> {
        self.request(&messages::Request::Precompute {
            public_key,
            ephemeral_public_key,
        })
    }

    fn shutdown(self) -> Result<messages::ShutdownResponse, Error> {
        self.request(&messages::Request::Shutdown)
    }
}
