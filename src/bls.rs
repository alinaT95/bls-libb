
mod key_gen;
mod sig;
mod nodes_info;
mod converters;
mod aggregate;
mod random_helper;

pub use self::key_gen::*;
pub use self::sig::*;
pub use self::aggregate::*;
pub use self::nodes_info::*;
pub use self::random_helper::*;
use blst::*;

use blst::min_pk::*;
//use blst::min_sig::*;

use rand::Rng;
use rand::RngCore;

use ton_types::{fail, Result};
use std::time::{Instant, Duration};
use std::convert::TryInto;
use crate::bls::random_helper::{generate_random_msg, generate_random_msg_of_fixed_len};

pub const BLS_SECRET_KEY_LEN: usize = 32;
pub const BLS_PUBLIC_KEY_LEN_FOR_MIN_PK_MODE: usize = 48;
pub const BLS_PUBLIC_KEY_LEN_FOR_MIN_SIG_MODE: usize = 96;
pub const BLS_PUBLIC_KEY_LEN: usize = BLS_PUBLIC_KEY_LEN_FOR_MIN_PK_MODE;
pub const BLS_KEY_MATERIAL_LEN: usize = 32;
pub const BLS_SIG_LEN_FOR_MIN_PK_MODE: usize = 96;
pub const BLS_SIG_LEN_FOR_MIN_SIG_MODE: usize = 48;
pub const BLS_SIG_LEN: usize = BLS_SIG_LEN_FOR_MIN_PK_MODE;
pub const BLS_SEED_LEN: usize = 32;


pub fn gen_bls_key_pair_based_on_key_material(ikm: &[u8; BLS_KEY_MATERIAL_LEN]) -> Result<([u8; BLS_PUBLIC_KEY_LEN], [u8; BLS_SECRET_KEY_LEN])> {
    let key_pair = BlsKeyPair::gen_bls_key_pair_based_on_key_material(ikm)?;
    Ok(key_pair.serialize())
}

pub fn gen_bls_key_pair() -> Result<([u8; BLS_PUBLIC_KEY_LEN], [u8; BLS_SECRET_KEY_LEN])> {
    let key_pair = BlsKeyPair::gen_bls_key_pair()?;
    Ok(key_pair.serialize())
}

pub fn gen_public_key_based_on_secret_key(sk: &[u8; BLS_SECRET_KEY_LEN]) -> Result<([u8; BLS_PUBLIC_KEY_LEN])> {
    let pk = BlsKeyPair::deserialize_based_on_secret_key(sk)?;
    Ok(pk.pk_bytes)
}

pub fn sign(sk_bytes: &[u8; BLS_SECRET_KEY_LEN], msg: &Vec<u8>) -> Result<[u8; BLS_SIG_LEN]>  {
    BlsSignature::simple_sign(sk_bytes, msg)
}

pub fn verify(sig_bytes: &[u8; BLS_SIG_LEN], msg: &Vec<u8>, pk_bytes: &[u8; BLS_PUBLIC_KEY_LEN]) -> Result<bool> {
    BlsSignature::simple_verify(sig_bytes, msg, pk_bytes)
}

pub fn add_node_info_to_sig(sig_bytes: [u8; BLS_SIG_LEN], node_index: u16, total_num_of_nodes: u16) -> Result<Vec<u8>> {
    BlsSignature::add_node_info_to_sig(sig_bytes, node_index, total_num_of_nodes)
}

pub fn sign_and_add_node_info(
    sk_bytes: &[u8; BLS_SECRET_KEY_LEN],
    msg: &Vec<u8>,
    node_index: u16,
    total_num_of_nodes: u16,
) -> Result<Vec<u8>> {
    BlsSignature::sign(sk_bytes, msg, node_index, total_num_of_nodes)
}

pub fn truncate_nodes_info_from_sig(sig_bytes_with_nodes_info: &Vec<u8>) -> Result<[u8; BLS_SIG_LEN]> {
    BlsSignature::truncate_nodes_info_from_sig(sig_bytes_with_nodes_info)
}

pub fn get_nodes_info_from_sig(sig_bytes_with_nodes_info: &Vec<u8>) -> Result<Vec<u8>> {
    BlsSignature::get_nodes_info_from_sig(sig_bytes_with_nodes_info)
}

pub fn truncate_nodes_info_and_verify(sig_bytes_with_nodes_info: &Vec<u8>, pk_bytes: &[u8; BLS_PUBLIC_KEY_LEN], msg: &Vec<u8>) -> Result<bool> {
    BlsSignature::verify(sig_bytes_with_nodes_info, pk_bytes, msg)
}

pub fn aggregate_bls_signatures(bls_sigs_bytes: &Vec<&Vec<u8>>) -> Result<Vec<u8>> {
    aggregate::aggregate_bls_signatures(bls_sigs_bytes)
}

pub fn aggregate_two_bls_signatures(bls_sig_1_bytes: &Vec<u8>, bls_sig_2_bytes: &Vec<u8>) -> Result<Vec<u8>> {
    aggregate::aggregate_two_bls_signatures(bls_sig_1_bytes, bls_sig_2_bytes)
}

pub fn aggregate_public_keys_based_on_nodes_info(bls_pks_bytes: &Vec<&[u8; BLS_PUBLIC_KEY_LEN]>, nodes_info_bytes: &Vec<u8>) -> Result<[u8; BLS_PUBLIC_KEY_LEN]> {
    aggregate::aggregate_public_keys_based_on_nodes_info(bls_pks_bytes, nodes_info_bytes)
}

pub fn aggregate_public_keys(bls_pks_bytes: &Vec<&[u8; BLS_PUBLIC_KEY_LEN]>) -> Result<[u8; BLS_PUBLIC_KEY_LEN]> {
    aggregate::aggregate_public_keys(bls_pks_bytes)
}

pub fn print_bls_public_key(bls_pk_bytes: &[u8]) {
    BlsKeyPair::print_bls_public_key(bls_pk_bytes)
}

pub fn print_signature_bytes(sig_bytes: &[u8]) {
    BlsSignature::print_signature_bytes(sig_bytes)
}

pub fn print_bls_signature(bls_sig_bytes: &Vec<u8>) {
    BlsSignature::print_bls_signature(bls_sig_bytes)
}


#[test]
fn test_gen_bls_key_pair() {
    for i in 0..100 {
        let now = Instant::now();
        let key_pair = gen_bls_key_pair().unwrap();
        let duration = now.elapsed();
      //  println!("Public key : {:?}", key_pair.0);
       // println!("Secret key : {:?}", key_pair.1);
        println!("Time elapsed by gen_bls_key_pair is: {:?}", duration);
    }
}

#[test]
fn test_gen_bls_key_pair_based_on_key_material() {
    let mut ikm = [0u8; BLS_KEY_MATERIAL_LEN];
    for i in 0..100 {
        let now = Instant::now();
        let key_pair = gen_bls_key_pair_based_on_key_material(&ikm).unwrap();
        let duration = now.elapsed();
        //  println!("Public key : {:?}", key_pair.0);
        println!("Secret key : {:?}", key_pair.1);
        println!("Time elapsed by gen_bls_key_pair_based_on_key_material is: {:?}", duration);
    }
}

#[test]
fn test_gen_public_key_based_on_secret_key() {
    for i in 0..100 {
        let key_pair = gen_bls_key_pair().unwrap();
        let now = Instant::now();
        let pk = gen_public_key_based_on_secret_key(&key_pair.1).unwrap();
        let duration = now.elapsed();
        //  println!("Public key : {:?}", key_pair.0);
        //println!("Secret key : {:?}", key_pair.1);
        println!("Time elapsed by gen_public_key_based_on_secret_key is: {:?}", duration);
        assert_eq!(pk, key_pair.0);
    }
}

#[test]
fn test_sign() {
    for i in 0..100 {
        let key_pair = gen_bls_key_pair().unwrap();
        let msg = generate_random_msg_of_fixed_len(10000000);
        let now = Instant::now();
        let sig = sign(&key_pair.1, &msg).unwrap();
        let duration = now.elapsed();
        //  println!("Public key : {:?}", key_pair.0);
        //println!("Secret key : {:?}", key_pair.1);
        println!("Time elapsed by sign is: {:?}", duration);
       // assert_eq!(pk, key_pair.0);
    }
}

#[test]
fn test_verify() {
    for i in 0..100 {
        let key_pair = gen_bls_key_pair().unwrap();
        let msg = generate_random_msg_of_fixed_len(1000);
        let sig = sign(&key_pair.1, &msg).unwrap();
        let now = Instant::now();
        let res = verify(&sig, &msg, &key_pair.0).unwrap();
        let duration = now.elapsed();
        //  println!("Public key : {:?}", key_pair.0);
        //println!("Secret key : {:?}", key_pair.1);
        println!("Time elapsed by verify is: {:?}", duration);
         assert_eq!(res, true);
    }
}

#[test]
fn test_add_node_info_to_sig() {
    let index = 100;
    let total_num_of_index = 10000;
    for i in 0..100 {
        let key_pair = gen_bls_key_pair().unwrap();
        let msg = generate_random_msg_of_fixed_len(500000);
        let sig = sign(&key_pair.1, &msg).unwrap();
        let now = Instant::now();
        let res = add_node_info_to_sig(sig, index, total_num_of_index).unwrap();
        let duration = now.elapsed();
        //  println!("Public key : {:?}", key_pair.0);
        //println!("Secret key : {:?}", key_pair.1);
        println!("Time elapsed by add_node_info_to_sig is: {:?}", duration);
    }
}

#[test]
fn test_sign_and_add_node_info() {
    let index = 100;
    let total_num_of_index = 1000;
    for i in 0..100 {
        let key_pair = gen_bls_key_pair().unwrap();
        let msg = generate_random_msg_of_fixed_len(10000000);
        let now = Instant::now();
        let res = sign_and_add_node_info(&key_pair.1, &msg, index, total_num_of_index).unwrap();
        let duration = now.elapsed();
        //  println!("Public key : {:?}", key_pair.0);
        //println!("Secret key : {:?}", key_pair.1);
        println!("Time elapsed by sign_and_add_node_info is: {:?}", duration);
    }
}

#[test]
fn test_aggregate_public_keys() {
    let number_of_keys = 10000;
    for i in 0..10 {
        let mut public_keys = Vec::new();
        for j in 0..number_of_keys {
            let key_pair = gen_bls_key_pair().unwrap();
            public_keys.push(key_pair.0);
        }
        let public_keys_refs: Vec<&[u8; BLS_PUBLIC_KEY_LEN]> = public_keys.iter().map(|pk| pk).collect();
        let now = Instant::now();
        let res = aggregate_public_keys(&public_keys_refs).unwrap();
        let duration = now.elapsed();
        //  println!("Public key : {:?}", key_pair.0);
        //println!("Secret key : {:?}", key_pair.1);
        println!("Time elapsed by aggregate_public_keys is: {:?}", duration);
    }
}

#[test]
fn test_aggregate_public_keys_based_on_nodes_info() {
    let total_num_of_nodes = 10000;
    for i in 0..10 {
        let indexes: Vec<u16> =  gen_signer_indexes(total_num_of_nodes, total_num_of_nodes * 2);
        let mut node_info_vec = Vec::new();
        for ind in &indexes {
            //println!("Node index = {}", ind);
            let nodes_info = NodesInfo::create_node_info(total_num_of_nodes, *ind).unwrap();
            node_info_vec.push(nodes_info)

        }
        let node_info_vec_refs: Vec<&NodesInfo> = node_info_vec.iter().map(|info| info).collect();
        let info = NodesInfo::merge_multiple(&node_info_vec_refs).unwrap();
        println!("Node info size = {}", info.map.len());
       // info.print();

        let mut public_keys = Vec::new();
        for j in 0..total_num_of_nodes {
            let key_pair = gen_bls_key_pair().unwrap();
            public_keys.push(key_pair.0);
        }
        let public_keys_refs: Vec<&[u8; BLS_PUBLIC_KEY_LEN]> = public_keys.iter().map(|pk| pk).collect();
        let now = Instant::now();
        let res = aggregate_public_keys_based_on_nodes_info(&public_keys_refs, &info.serialize()).unwrap();
        let duration = now.elapsed();

        println!("Time elapsed by aggregate_public_keys is: {:?}", duration);
    }
}

#[test]
fn test_aggregate_two_bls_signatures() {
    let number_of_keys = 100;
    for i in 0..10 {
        let key_pair_1 = gen_bls_key_pair().unwrap();
        let key_pair_2 = gen_bls_key_pair().unwrap();
        let msg = generate_random_msg();
        let ind_1 = gen_random_index(number_of_keys);
        let ind_2 = gen_random_index(number_of_keys);
        let sig_1 = sign_and_add_node_info(&key_pair_1.1, &msg, ind_1, number_of_keys).unwrap();
        let sig_2 = sign_and_add_node_info(&key_pair_2.1, &msg, ind_2, number_of_keys).unwrap();
        let now = Instant::now();
        let res = aggregate_two_bls_signatures(&sig_1, &sig_2).unwrap();
        let duration = now.elapsed();
        //  println!("Public key : {:?}", key_pair.0);
        //println!("Secret key : {:?}", key_pair.1);
        println!("Time elapsed by aggregate_two_bls_signatures is: {:?}", duration);
    }
}

#[test]
fn test_aggregate_two_bls_signatures_2() {
    let number_of_keys = 10000;
    for i in 0..10 {
        let key_pair_1 = gen_bls_key_pair().unwrap();
        let key_pair_2 = gen_bls_key_pair().unwrap();
        let msg = generate_random_msg();

        let sig_1 = sign(&key_pair_1.1, &msg).unwrap();
        let sig_2 = sign(&key_pair_2.1, &msg).unwrap();
        let info_1 = create_random_nodes_info(number_of_keys, number_of_keys * 2);
        let info_2 = create_random_nodes_info(number_of_keys, number_of_keys * 2);
        println!("info_1 size: {:?}", &info_1.map.len());

        let bls_sig_1 =  BlsSignature {
            sig_bytes: sig_1,
            nodes_info: info_1
        }.serialize();

        println!("info_2 size: {:?}", &info_2.map.len());

        let bls_sig_2 =  BlsSignature {
            sig_bytes: sig_2,
            nodes_info: info_2
        }.serialize();

        let now = Instant::now();
        let res = aggregate_two_bls_signatures(&bls_sig_1, &bls_sig_2).unwrap();
        let duration = now.elapsed();
        //  println!("Public key : {:?}", key_pair.0);
        //println!("Secret key : {:?}", key_pair.1);
        println!("Time elapsed by aggregate_two_bls_signatures is: {:?}", duration);
    }
}

#[test]
fn test_aggregate_bls_signatures() {
    let number_of_keys = 10000;
    let number_of_signatures = 50;
    for i in 0..10 {
        let mut sigs = Vec::new();
        let msg = generate_random_msg();
        for j in 0..number_of_signatures {
            let key_pair = gen_bls_key_pair().unwrap();
            let sig = sign(&key_pair.1, &msg).unwrap();
            let info = create_random_nodes_info(number_of_keys, number_of_keys * 2);
            println!("info size: {:?}", &info.map.len());
            let bls_sig =  BlsSignature {
                sig_bytes: sig,
                nodes_info: info
            }.serialize();
            sigs.push(bls_sig);
        }
        let sigs_refs: Vec<&Vec<u8>> = sigs.iter().map(|sig| sig).collect();

        let now = Instant::now();
        let res = aggregate_bls_signatures(&sigs_refs).unwrap();
        let duration = now.elapsed();

        println!("Time elapsed by aggregate_bls_signatures is: {:?}", duration);
    }
}