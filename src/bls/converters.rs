
use blst::*;
use blst::min_pk::*;
//use blst::min_sig::*;
use ton_types::{fail, Result};
use std::convert::TryInto;

use crate::bls::BLS_PUBLIC_KEY_LEN;
use crate::bls::BLS_SECRET_KEY_LEN;
use crate::bls::BLS_KEY_MATERIAL_LEN;
use crate::bls::BLS_SIG_LEN;

pub fn convert_secret_key_bytes_to_secret_key(sk_bytes: &[u8; BLS_SECRET_KEY_LEN]) -> Result<SecretKey> {
    let sk = match SecretKey::from_bytes(sk_bytes) {
        Ok(sk) => sk,
        Err(err) => fail!("BLS secret key deserialize failure: {:?}", err),
    };
    Ok(sk)
}

pub fn convert_signature_bytes_to_signature(sig_bytes: &[u8; BLS_SIG_LEN]) -> Result<Signature> {
    let sig = match Signature::from_bytes(sig_bytes) {
        Ok(sig) => sig,
        Err(err) => fail!("BLS signature deserialize failure: {:?}", err),
    };
    Ok(sig)
}

pub fn convert_public_key_bytes_to_public_key(pk_bytes: &[u8; BLS_PUBLIC_KEY_LEN]) -> Result<PublicKey> {
    let pk = match PublicKey::from_bytes(pk_bytes) {
        Ok(pk) => pk,
        Err(err) => fail!("BLS public key deserialize failure: {:?}", err),
    };
    Ok(pk)
}

pub fn convert_vec_to_array(v: Vec<u8>) -> [u8; BLS_PUBLIC_KEY_LEN] {
    v.try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("Expected vector of length {} but it was {}", BLS_PUBLIC_KEY_LEN, v.len()))
}


pub fn convert_signature_to_signature_bytes(sig: Signature) -> [u8; BLS_SIG_LEN] {
    return sig.to_bytes();
}