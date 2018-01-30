use std::sync::RwLock;
use std::mem;
use std::collections::HashMap;
use sodiumoxide::crypto::box_::{self, PrecomputedKey, PublicKey, SecretKey};
use simple_crypt_util::serde_arrays::FixedArray;
use simple_crypt_util::memory_security;
use failure::{Error, ResultExt};

pub struct KeyStore {
    inner: RwLock<KeyStoreInner>,
}

struct KeyStoreInner {
    secret_keys: Box<[SecretKey]>,
    free_slots: Vec<usize>,
    public_key_mapping: HashMap<PublicKey, usize>,
}

#[derive(Debug, Fail)]
#[fail(display = "Out of secret key capacity")]
pub struct OutOfCapacity;

#[derive(Debug, Fail)]
#[fail(display = "Key not found in keystore")]
pub struct KeyNotFound;

impl KeyStore {
    pub fn new() -> Result<KeyStore, Error> {
        Ok(KeyStore {
            inner: RwLock::new(KeyStoreInner::new()?),
        })
    }

    fn with_inner<F, R>(&self, f: F) -> R
    where
        for<'a> F: FnOnce(&'a KeyStoreInner) -> R,
    {
        let guard = self.inner.read().expect("lock poisoned");
        f(&guard)
    }

    fn with_mut_inner<F, R>(&self, f: F) -> R
    where
        for<'a> F: FnOnce(&'a mut KeyStoreInner) -> R,
    {
        let mut guard = self.inner.write().expect("lock poisoned");
        f(&mut guard)
    }

    pub fn list_keys(&self) -> Vec<PublicKey> {
        let mut keys: Vec<PublicKey> =
            self.with_inner(|inner| inner.public_key_mapping.keys().cloned().collect());
        keys.sort_unstable();
        keys
    }

    pub fn add_key(
        &self,
        public_key: PublicKey,
        secret_key: SecretKey,
    ) -> Result<(), OutOfCapacity> {
        self.with_mut_inner(|inner| inner.add_key(public_key, secret_key))
    }

    pub fn remove_key(&self, public_key: &PublicKey) -> Result<(), KeyNotFound> {
        self.with_mut_inner(|inner| inner.remove_key(public_key))
    }

    pub fn precompute(
        &self,
        public_key: &PublicKey,
        ephemeral_public_key: &PublicKey,
    ) -> Result<PrecomputedKey, KeyNotFound> {
        self.with_inner(|inner| inner.precompute(public_key, ephemeral_public_key))
    }
}

impl KeyStoreInner {
    fn new() -> Result<KeyStoreInner, Error> {
        KeyStoreInner::with_capacity(128)
    }

    fn with_capacity(size: usize) -> Result<KeyStoreInner, Error> {
        let secret_keys = vec![SecretKey::zero(); size];
        let secret_keys = secret_keys.into_boxed_slice();

        memory_security::lock_memory(
            0,
            mem::size_of_val::<[SecretKey]>(&secret_keys),
            &secret_keys,
        ).context("unable to lock memory for secret keys")?;

        Ok(KeyStoreInner {
            secret_keys: secret_keys,
            free_slots: Vec::new(),
            public_key_mapping: HashMap::with_capacity(size),
        })
    }

    fn add_key(
        &mut self,
        public_key: PublicKey,
        secret_key: SecretKey,
    ) -> Result<(), OutOfCapacity> {
        let ndx = if let Some(ndx) = self.free_slots.pop() {
            ndx
        } else if self.public_key_mapping.len() < self.secret_keys.len() {
            self.public_key_mapping.len()
        } else {
            return Err(OutOfCapacity);
        };

        self.secret_keys[ndx] = secret_key;
        self.public_key_mapping.insert(public_key, ndx);
        Ok(())
    }

    fn remove_key(&mut self, public_key: &PublicKey) -> Result<(), KeyNotFound> {
        if let Some(ndx) = self.public_key_mapping.remove(public_key) {
            self.secret_keys[ndx] = SecretKey::zero();
            Ok(())
        } else {
            Err(KeyNotFound)
        }
    }

    fn precompute(
        &self,
        public_key: &PublicKey,
        ephemeral_public_key: &PublicKey,
    ) -> Result<PrecomputedKey, KeyNotFound> {
        if let Some(ndx) = self.public_key_mapping.get(public_key) {
            Ok(box_::precompute(
                ephemeral_public_key,
                &self.secret_keys[*ndx],
            ))
        } else {
            Err(KeyNotFound)
        }
    }
}
