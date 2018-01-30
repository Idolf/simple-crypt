use sodiumoxide::crypto::box_;

use simple_crypt_util::serde_arrays;
use keystore;

pub const CURRENT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientHandshake {
    pub version: u32,
}

impl ClientHandshake {
    pub fn is_current(&self) -> bool {
        self.version == CURRENT_VERSION
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub struct ServerHandshake {
    pub server_version: u32,
    pub status: ServerStatus,
}

impl ServerHandshake {
    pub fn new(status: ServerStatus) -> ServerHandshake {
        ServerHandshake {
            server_version: CURRENT_VERSION,
            status,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum ServerStatus {
    Ok,
    BadVersion,
    PermissionDenied,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum Request {
    List,
    AddKey {
        #[serde(with = "serde_arrays::bytes")] public_key: box_::PublicKey,
        #[serde(with = "serde_arrays::bytes")] secret_key: box_::SecretKey,
    },
    RemoveKey {
        #[serde(with = "serde_arrays::bytes")] public_key: box_::PublicKey,
    },
    Precompute {
        #[serde(with = "serde_arrays::bytes")] public_key: box_::PublicKey,
        #[serde(with = "serde_arrays::bytes")] ephemeral_public_key: box_::PublicKey,
    },
    Shutdown,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub struct ListResponse(pub Vec<box_::PublicKey>);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum AddKeyResponse {
    Ok,
    OutOfCapacity,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum RemoveKeyResponse {
    Ok,
    KeyNotFound,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum PrecomputeResponse {
    PrecomputeDone(#[serde(with = "serde_arrays::bytes")] box_::PrecomputedKey),
    KeyNotFound,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum ShutdownResponse {
    Ok,
}

impl From<Result<(), keystore::OutOfCapacity>> for AddKeyResponse {
    fn from(result: Result<(), keystore::OutOfCapacity>) -> AddKeyResponse {
        match result {
            Ok(()) => AddKeyResponse::Ok,
            Err(keystore::OutOfCapacity) => AddKeyResponse::OutOfCapacity,
        }
    }
}

impl From<Result<(), keystore::KeyNotFound>> for RemoveKeyResponse {
    fn from(result: Result<(), keystore::KeyNotFound>) -> RemoveKeyResponse {
        match result {
            Ok(()) => RemoveKeyResponse::Ok,
            Err(keystore::KeyNotFound) => RemoveKeyResponse::KeyNotFound,
        }
    }
}

impl From<Result<box_::PrecomputedKey, keystore::KeyNotFound>> for PrecomputeResponse {
    fn from(result: Result<box_::PrecomputedKey, keystore::KeyNotFound>) -> PrecomputeResponse {
        match result {
            Ok(key) => PrecomputeResponse::PrecomputeDone(key),
            Err(keystore::KeyNotFound) => PrecomputeResponse::KeyNotFound,
        }
    }
}
