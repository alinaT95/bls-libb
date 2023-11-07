use super::converters::*;
use blst::*;
use blst::min_pk::*;
//use blst::min_sig::*;
use rand::Rng;
use rand::{RngCore};

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use std::collections::HashSet;

use ton_types::{fail, Result};

use crate::bls::BLS_PUBLIC_KEY_LEN;
use crate::bls::BLS_SECRET_KEY_LEN;
use crate::bls::BLS_KEY_MATERIAL_LEN;

pub struct KeyPair {
    pub sk: SecretKey,
    pub pk: PublicKey,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlsKeyPair {
    pub pk_bytes: [u8; BLS_PUBLIC_KEY_LEN],
    pub sk_bytes: [u8; BLS_SECRET_KEY_LEN]
}

impl BlsKeyPair {
    pub fn print_bls_public_key(bls_pk_bytes: &[u8]) {
        if bls_pk_bytes.len() != BLS_PUBLIC_KEY_LEN{
            panic!("Incorrect length of secret key byte array!")
        }
        println!("--------------------------------------------------");
        println!("Aggregated BLS public key");
        println!("--------------------------------------------------");
        println!("Public key bytes:");
        println!("{:?}", bls_pk_bytes);
        println!("--------------------------------------------------");
    }

    pub fn print(&self) {
        println!("--------------------------------------------------");
        println!("BLS key pair:");
        println!("--------------------------------------------------");
        println!("Secret key bytes:");
        println!("{:?}", &self.sk_bytes);
        println!("Secret key len: {}", &self.sk_bytes.len());
        println!("Public key bytes:");
        println!("{:?}", &self.pk_bytes);
        println!("Public key len: {}", &self.pk_bytes.len());
        println!("--------------------------------------------------");
    }


    pub fn serialize(&self) -> ([u8; BLS_PUBLIC_KEY_LEN], [u8; BLS_SECRET_KEY_LEN])  {
        (self.pk_bytes, self.sk_bytes)
    }

    pub fn deserialize(key_pair_data: &([u8; BLS_PUBLIC_KEY_LEN], [u8; BLS_SECRET_KEY_LEN])) -> Result<Self> {
        let sk = convert_secret_key_bytes_to_secret_key(&key_pair_data.1)?;
        let pk = sk.sk_to_pk();
        if key_pair_data.0 != pk.to_bytes() {
            fail!("Public key does not correspond to secret key!")
        }
        Ok(Self {
            pk_bytes: key_pair_data.0,
            sk_bytes: key_pair_data.1
        })
    }

    pub fn deserialize_based_on_secret_key(sk_bytes: &[u8; BLS_SECRET_KEY_LEN]) -> Result<Self> {
        let sk = convert_secret_key_bytes_to_secret_key(sk_bytes)?;
        let pk = sk.sk_to_pk();
        Ok(Self {
            pk_bytes: pk.to_bytes(),
            sk_bytes: sk.to_bytes()
        })
    }

    pub fn gen_bls_key_pair_based_on_key_material(ikm: &[u8; BLS_KEY_MATERIAL_LEN]) -> Result<Self> {
        let key_pair = BlsKeyPair::gen_key_pair_based_on_key_material(&ikm)?;
        Ok(BlsKeyPair::convert_key_pair_to_bls_key_pair(key_pair))
    }

    pub fn gen_bls_key_pair() -> Result<Self> {
        let key_pair = BlsKeyPair::gen_key_pair()?;
        Ok(BlsKeyPair::convert_key_pair_to_bls_key_pair(key_pair))
    }

    pub fn gen_key_pair() -> Result<KeyPair> {
        let mut ikm = [0u8; BLS_KEY_MATERIAL_LEN];
        rand::thread_rng().fill_bytes(&mut ikm);
        BlsKeyPair::gen_key_pair_based_on_key_material(&ikm)
    }

    pub fn gen_key_pair_based_on_key_material(ikm: &[u8; BLS_KEY_MATERIAL_LEN]) -> Result<KeyPair> {
        if ikm.len() != BLS_KEY_MATERIAL_LEN {
            fail!("Incorrect length of key material byte array!")
        }
        if let Ok(sk) = SecretKey::key_gen(ikm, &[]) {
            let pk = sk.sk_to_pk();
            Ok(KeyPair { sk: sk, pk: pk })
        } else {
            fail!("Failed while generate key")
        }
    }

    fn convert_key_pair_to_bls_key_pair(key_pair: KeyPair) -> Self {
        return BlsKeyPair {
            sk_bytes: key_pair.sk.to_bytes(),
            pk_bytes: key_pair.pk.to_bytes(),
        };
    }
}

#[cfg(test)]
mod tests_key_gen {
    use super::*;

    fn calculate_hash<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }

    #[test]
    fn test_serialize_deserialize() {
        let key_pair = BlsKeyPair::gen_bls_key_pair().unwrap();
        let key_pair_data = key_pair.serialize();
        let key_pair_new = BlsKeyPair::deserialize(&key_pair_data).unwrap();
        let res = key_pair == key_pair_new;
        assert_eq!(res, true);
    }

    #[test]
    fn test_serialize_deserialize_based_on_secret_key() {
        let key_pair = BlsKeyPair::gen_bls_key_pair().unwrap();
        let key_pair_data = key_pair.serialize();
        let key_pair_new = BlsKeyPair::deserialize_based_on_secret_key(&key_pair_data.1).unwrap();
        let res = key_pair == key_pair_new;
        assert_eq!(res, true);
    }

    #[test]
    fn test_deserialize_fail() {
        let key_pair = BlsKeyPair::gen_bls_key_pair().unwrap();
        let key_pair_data = key_pair.serialize();
        let new_key_pair_data = ([1u8; BLS_PUBLIC_KEY_LEN], key_pair_data.1);
        let err = BlsKeyPair::deserialize(&new_key_pair_data).err();
        //println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_gen_key_randomness() {
        let mut hashes = HashSet::new();

        for i in 0..1000 {
            let kp = BlsKeyPair::gen_bls_key_pair().unwrap();
            hashes.insert(calculate_hash(&kp.sk_bytes));
            println!("iter# {}", i);
            println!("key:");
            println!("{:?}", &kp.sk_bytes);
        }
        assert_eq!(hashes.len(), 1000);
    }
}












