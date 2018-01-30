use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
use messages;

pub trait DaemonService {
    type Error;
    fn list(self) -> Result<messages::ListResponse, Self::Error>;
    fn add_key(
        self,
        public_key: PublicKey,
        secret_key: SecretKey,
    ) -> Result<messages::AddKeyResponse, Self::Error>;
    fn remove_key(self, public_key: PublicKey) -> Result<messages::RemoveKeyResponse, Self::Error>;
    fn precompute(
        self,
        public_key: PublicKey,
        ephemeral_public_key: PublicKey,
    ) -> Result<messages::PrecomputeResponse, Self::Error>;
    fn shutdown(self) -> Result<messages::ShutdownResponse, Self::Error>;
}
