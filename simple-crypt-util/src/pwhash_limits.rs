use sodiumoxide::crypto::pwhash;

#[derive(Copy, Clone)]
pub struct OpsLimit(pub u64);
#[derive(Copy, Clone)]
pub struct MemLimit(pub u64);

pub const OPSLIMIT_SENSITIVE: OpsLimit = OpsLimit(pwhash::OPSLIMIT_SENSITIVE.0 as u64);
pub const OPSLIMIT_INTERACTIVE: OpsLimit = OpsLimit(pwhash::OPSLIMIT_INTERACTIVE.0 as u64);

pub const MEMLIMIT_SENSITIVE: MemLimit = MemLimit(pwhash::MEMLIMIT_SENSITIVE.0 as u64);
pub const MEMLIMIT_INTERACTIVE: MemLimit = MemLimit(pwhash::MEMLIMIT_INTERACTIVE.0 as u64);

impl From<pwhash::OpsLimit> for OpsLimit {
    fn from(value: pwhash::OpsLimit) -> OpsLimit {
        OpsLimit(value.0 as u64)
    }
}

impl From<pwhash::MemLimit> for MemLimit {
    fn from(value: pwhash::MemLimit) -> MemLimit {
        MemLimit(value.0 as u64)
    }
}

impl From<OpsLimit> for pwhash::OpsLimit {
    fn from(value: OpsLimit) -> pwhash::OpsLimit {
        pwhash::OpsLimit(value.0 as usize)
    }
}

impl From<MemLimit> for pwhash::MemLimit {
    fn from(value: MemLimit) -> pwhash::MemLimit {
        pwhash::MemLimit(value.0 as usize)
    }
}
