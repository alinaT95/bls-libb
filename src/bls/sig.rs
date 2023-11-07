use super::converters::*;
use super::key_gen::*;
use super::nodes_info::*;
use super::random_helper::*;
use std::convert::TryInto;
use blst::*;

use blst::min_pk::*;
//use blst::min_sig::*;

use ton_types::{fail, Result};

use crate::bls::{add_node_info_to_sig, BLS_PUBLIC_KEY_LEN, BLS_SIG_LEN};
use crate::bls::BLS_SECRET_KEY_LEN;
use crate::bls::BLS_KEY_MATERIAL_LEN;

pub const DST: [u8; 43] = *b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlsSignature {
    pub sig_bytes: [u8; BLS_SIG_LEN],
    pub nodes_info: NodesInfo,
}

impl BlsSignature {
    pub fn serialize(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.sig_bytes);
        let nodes_info_bytes = &self.nodes_info.serialize();
        vec.extend_from_slice(&nodes_info_bytes);
        vec
    }

    pub fn deserialize(sig_bytes_with_nodes_info: &Vec<u8>) -> Result<Self> {
        if sig_bytes_with_nodes_info.len() < BLS_SIG_LEN + 6 {
            fail!("Length of sig_bytes_with_nodes_info is too short!")
        }
        let mut sig_bytes: [u8; BLS_SIG_LEN] = [0; BLS_SIG_LEN];
        sig_bytes.copy_from_slice(&sig_bytes_with_nodes_info[0..BLS_SIG_LEN]);
        let len = sig_bytes_with_nodes_info.len() - BLS_SIG_LEN;
        let mut nodes_info_data = vec![0; len];
        nodes_info_data.copy_from_slice(&sig_bytes_with_nodes_info[BLS_SIG_LEN..]);
        let nodes_info = NodesInfo::deserialize(&nodes_info_data)?;
        Ok(Self{sig_bytes, nodes_info})
    }

    pub fn simple_sign(sk_bytes: &[u8; BLS_SECRET_KEY_LEN], msg: &Vec<u8>) -> Result<[u8; BLS_SIG_LEN]> {
        if msg.len() == 0 {
            fail!("Msg to sign can not be empty!")
        }
        let sk = convert_secret_key_bytes_to_secret_key(sk_bytes)?;
        let sig = sk.sign(msg, &DST, &[]);
        Ok(sig.to_bytes())
    }

    pub fn simple_verify(sig_bytes: &[u8; BLS_SIG_LEN], msg: &Vec<u8>, pk_bytes: &[u8; BLS_PUBLIC_KEY_LEN]) -> Result<bool> {
        if msg.len() == 0 {
            fail!("Msg to sign can not be empty!")
        }
        let sig = convert_signature_bytes_to_signature(sig_bytes)?;
        let pk = convert_public_key_bytes_to_public_key(pk_bytes)?;
        let res = sig.verify(true, msg, &DST, &[], &pk, true);
        Ok(res == BLST_ERROR::BLST_SUCCESS)
    }

    pub fn add_node_info_to_sig(sig_bytes: [u8; BLS_SIG_LEN], node_index: u16, total_num_of_nodes: u16) -> Result<Vec<u8>> {
        if total_num_of_nodes == 0 {
            fail!("Total number of nodes can not be zero!");
        }
        if node_index >= total_num_of_nodes {
            fail!("Index of node can not be greater than total number of nodes!");
        }
        let nodes_info = NodesInfo::create_node_info(total_num_of_nodes, node_index)?;
        let sig = Self {
            sig_bytes,
            nodes_info,
        };
        let sig_bytes = BlsSignature::serialize(&sig);
        Ok(sig_bytes)
    }

    pub fn sign(
        sk_bytes: &[u8; BLS_SECRET_KEY_LEN],
        msg: &Vec<u8>,
        node_index: u16,
        total_num_of_nodes: u16,
    ) -> Result<Vec<u8>> {
        let sig = BlsSignature::simple_sign(sk_bytes, msg)?;
        add_node_info_to_sig(sig, node_index, total_num_of_nodes)
    }

    pub fn get_nodes_info_from_sig(sig_bytes_with_nodes_info: &Vec<u8>) -> Result<Vec<u8>> {
        let bls_sig = BlsSignature::deserialize(sig_bytes_with_nodes_info)?;
        Ok(bls_sig.nodes_info.serialize())
    }

    pub fn truncate_nodes_info_from_sig(sig_bytes_with_nodes_info: &Vec<u8>) -> Result<[u8; BLS_SIG_LEN]> {
        let bls_sig = BlsSignature::deserialize(sig_bytes_with_nodes_info)?;
        Ok(bls_sig.sig_bytes)
    }

    pub fn verify(sig_bytes_with_nodes_info: &Vec<u8>, pk_bytes: &[u8; BLS_PUBLIC_KEY_LEN], msg: &Vec<u8>) -> Result<bool> {
        let sig_bytes = BlsSignature::truncate_nodes_info_from_sig(sig_bytes_with_nodes_info)?;
        let res = BlsSignature::simple_verify(&sig_bytes, msg, pk_bytes)?;
        Ok(res)
    }

    pub fn print_signature_bytes(sig_bytes: &[u8]) {
        if sig_bytes.len() != BLS_SIG_LEN {
            panic!("Incorrect length of signature byte array!")
        }
        println!("--------------------------------------------------");
        println!("BLS Signature bytes:");
        println!("--------------------------------------------------");
        println!("{:?}", sig_bytes);
        println!("--------------------------------------------------");
    }

    pub fn print_bls_signature(bls_sig_bytes: &Vec<u8>) {
        let bls_sig = BlsSignature::deserialize(bls_sig_bytes).unwrap();
        bls_sig.print();
    }

    pub fn print(&self) {
        println!("--------------------------------------------------");
        println!("Aggregated BLS signature:");
        println!("--------------------------------------------------");
        println!("Signature bytes:");
        println!("{:?}", &self.sig_bytes);
        &self.nodes_info.print();
        println!("--------------------------------------------------");
    }
}

#[cfg(test)]
mod sig_tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::fs::File;
    use std::io::{Read, Write};
    use super::*;
    use rand::SeedableRng;
    use rand::Rng;
    use rand::{RngCore};
    use crate::bls::sign;

    /** zero keys and incorrect subgroup checking **/

    #[test]
    fn test_pk_is_point_of_infinity_or_not_in_group() {
        let total_num_of_nodes = 100;
        let node_index = 2;
        let kp = BlsKeyPair::gen_bls_key_pair().unwrap();
        kp.print();
        let mut msg = generate_random_msg();
        let bls_sig_bytes = BlsSignature::sign(&kp.sk_bytes, &msg, node_index, total_num_of_nodes).unwrap();

        let a1 = [0xC0]; //11000000, here first two bits shows that public key is in compressed form and it's gonna be a point of infinity (zero vector)
        // all other bits will be zero
        let a2 = [0; BLS_PUBLIC_KEY_LEN - 1];

        let mut key_2: Vec<u8> = a1.iter().chain(a2.iter()).map(|v| *v).collect();
        let key_2: [u8; BLS_PUBLIC_KEY_LEN] = key_2.try_into().unwrap();
        println!("{:?}", key_2);

        let res = BlsSignature::verify(&bls_sig_bytes,  &key_2, &msg).unwrap();
        println!("res = {}", res);
        assert_eq!(res, false);

        let key_3 = [130, 70, 150, 125, 169, 172, 192, 188, 9, 54, 153, 180, 207, 211, 148, 25, 5, 82, 202, 176, 6, 166, 177, 79, 220, 204, 168, 36, 162, 159, 172, 63, 141, 16, 248, 139, 97, 73, 38, 154, 188, 186, 72, 188, 75, 27, 199, 44];
        let err = BlsSignature::verify(&bls_sig_bytes,  &key_3, &msg).err();
        println!("{}",err.unwrap().to_string());
        //assert!(err.is_some());
    }


    #[test]
    fn test_sig_not_in_group() {
        let sig: [u8; BLS_SIG_LEN] = [145, 159, 130, 216, 123, 12, 196, 4, 178, 40, 10, 4, 206, 211, 143, 207, 233, 217, 193, 27, 251, 138, 210, 17, 189, 65, 10, 145, 47, 247, 82, 94, 15, 139, 219, 83, 9, 60, 251, 70, 121, 176, 26, 94, 188, 188, 243, 225, 17, 176, 133, 133, 150, 81, 226, 69, 136, 52, 209, 39, 19, 18, 110, 53, 61, 144, 227, 207, 190, 158, 54, 169, 113, 34, 57, 161, 90, 110, 33, 46, 164, 236, 52, 251, 142, 236, 246, 173, 1, 183, 66, 238, 48, 140, 170, 141];
        let kp = BlsKeyPair::gen_bls_key_pair().unwrap();
        let mut msg = generate_random_msg();
        let err = BlsSignature::simple_verify(&sig, &msg, &kp.pk_bytes).err();
       // println!("{}",err.unwrap().to_string());
        //assert!(err.is_some());
    }

    /** serialize/deserialize **/

    #[test]
    fn test_serialize_deserialize() {
        let mut sig_bytes = [1; BLS_SIG_LEN];
        let total_num_of_nodes = 100;
        let mut new_info = HashMap::from([(9, 1), (10, 4)]);
        let nodes_info = NodesInfo::with_data(new_info, total_num_of_nodes).unwrap();
        let bls_sig = BlsSignature {
            sig_bytes,
            nodes_info,
        };
        let vec = bls_sig.serialize();
        assert_eq!(vec.len(), BLS_SIG_LEN + 10);
        let bls_sig_new = BlsSignature::deserialize(&vec).unwrap();
        assert_eq!(bls_sig.sig_bytes, bls_sig_new.sig_bytes);
        assert_eq!(bls_sig.sig_bytes, [1; BLS_SIG_LEN]);
        assert_eq!(bls_sig.nodes_info, bls_sig_new.nodes_info)
    }

    /** deserialize **/

    #[test]
    fn test_deserialize_fail_too_short_input() {
        let vec: Vec<u8> = Vec::new();
        let mut vec= Vec::new();
        for n in 0..(BLS_SIG_LEN + 6){
            let err = BlsSignature::deserialize(&vec).err();
            //println!("{}",err.unwrap().to_string());
            assert!(err.is_some());
            vec.push(100);
        }
    }

    #[test]
    fn test_deserialize_fail_input_len_incorrect() {
        let mut vec = vec![0; BLS_SIG_LEN];
        let mut nodes_info: Vec<u8> = vec![0, 100, 0, 99, 0, 100, 3];
        vec.append(&mut nodes_info);
        let err = BlsSignature::deserialize(&vec).err();
       // println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_deserialize_fail_index_bigger_than_total_num_of_nodes() {
        let mut vec = vec![0; BLS_SIG_LEN];
        let mut nodes_info: Vec<u8> = vec![0, 100, 0, 100, 0, 99];
        vec.append(&mut nodes_info);
        let err = BlsSignature::deserialize(&vec).err();
       // println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_deserialize_fail_zero_total_num_of_nodes() {
        let mut vec = vec![0; BLS_SIG_LEN];
        let mut nodes_info: Vec<u8> = vec![0, 0, 0, 100, 0, 99];
        vec.append(&mut nodes_info);
        let err = BlsSignature::deserialize(&vec).err();
        //println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_deserialize_fail_zero_number_of_occurrences() {
        let mut vec = vec![0; BLS_SIG_LEN];
        let mut nodes_info: Vec<u8> = vec![0, 2, 0, 1, 0, 0];
        vec.append(&mut nodes_info);
        let err = BlsSignature::deserialize(&vec).err();
      //  println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_deserialize() {
        let mut vec = vec![1; BLS_SIG_LEN];
        let mut nodes_info: Vec<u8> =  vec![0, 100, 0, 99, 0, 120, 0, 70, 1, 0];
        vec.append(&mut nodes_info);
        let bls_sig = BlsSignature::deserialize(&vec).unwrap();
        bls_sig.print();
        assert_eq!(bls_sig.nodes_info.total_num_of_nodes, 100);
        let mut new_info: HashMap<u16, u16> = HashMap::from([(99, 120), (70, 256)]);
        assert_eq!(new_info, bls_sig.nodes_info.map);
        assert_eq!(vec![1; BLS_SIG_LEN], bls_sig.sig_bytes);
    }

    /** simple_sign/simple_verify **/

    #[test]
    fn test_simple_sign_fail_empty_msg() {
        let sk_bytes = [1; BLS_SECRET_KEY_LEN];
        let msg = Vec::new();
        let err = BlsSignature::simple_sign(&sk_bytes, &msg).err();
        //println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_simple_verify_fail_empty_msg() {
        let sig_bytes = [1; BLS_SIG_LEN];
        let pk_bytes = [1; BLS_PUBLIC_KEY_LEN];
        let msg = Vec::new();
        let err = BlsSignature::simple_verify(&sig_bytes, &msg, &pk_bytes).err();
        //println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_simple_sign_verify() {
        let kp = BlsKeyPair::gen_bls_key_pair().unwrap();
        kp.print();
        let mut msg = generate_random_msg();
        let sig = BlsSignature::simple_sign(&kp.sk_bytes, &msg).unwrap();
        println!("Signature:");
        println!("{:?}", sig);
        let res = BlsSignature::simple_verify(&sig, &msg, &kp.pk_bytes).unwrap();
        println!("res = {}", res);
        assert_eq!(res, true);
    }

    #[test]
    fn test_simple_sign_verify_with_wrong_key() {
        let kp_1 = BlsKeyPair::gen_bls_key_pair().unwrap();
        kp_1.print();
        let kp_2 = BlsKeyPair::gen_bls_key_pair().unwrap();
        kp_2.print();
        let mut msg = generate_random_msg();
        let sig = BlsSignature::simple_sign(&kp_1.sk_bytes, &msg).unwrap();
        println!("Signature:");
        println!("{:?}", sig);
        let res = BlsSignature::simple_verify(&sig, &msg, &kp_2.pk_bytes).unwrap();
        println!("res = {}", res);
        assert_eq!(res, false);
    }

    /** add_node_info_to_sig **/

    #[test]
    fn test_add_node_info_to_sig_fail_zero_total_num_of_nodes() {
        let total_num_of_nodes = 0;
        let node_index = 2;
        let sig_bytes: [u8; BLS_SIG_LEN] = [1; BLS_SIG_LEN];
        let err = add_node_info_to_sig(sig_bytes, node_index, total_num_of_nodes).err();
        assert!(err.is_some());
    }

    #[test]
    fn test_add_node_info_to_sig_fail_node_index_bigger_than_total_num_of_nodes() {
        let total_num_of_nodes = 100;
        let node_index = 100;
        let sig_bytes: [u8; BLS_SIG_LEN] = [1; BLS_SIG_LEN];
        let err = add_node_info_to_sig(sig_bytes, node_index, total_num_of_nodes).err();
        assert!(err.is_some());
    }

    #[test]
    fn test_add_node_info() {
        let total_num_of_nodes = 100;
        let node_index = 2;
        let sig_bytes: [u8; BLS_SIG_LEN] = [1; BLS_SIG_LEN];
        let bls_sig_bytes = add_node_info_to_sig(sig_bytes, node_index, total_num_of_nodes).unwrap();
        let bls_sig = BlsSignature::deserialize(&bls_sig_bytes).unwrap();
        assert_eq!(bls_sig.sig_bytes, [1; BLS_SIG_LEN]);
        assert_eq!(bls_sig.nodes_info.total_num_of_nodes, total_num_of_nodes);
        assert_eq!(bls_sig.nodes_info.map, HashMap::from([(2, 1)]));
    }

    /** sign ***/

    #[test]
    fn test_sign_fail_empty_msg() {
        let total_num_of_nodes = 100;
        let node_index = 2;
        let sk_bytes = [1; BLS_SECRET_KEY_LEN];
        let msg = Vec::new();
        let err = BlsSignature::sign(&sk_bytes, &msg, node_index, total_num_of_nodes).err();
        assert!(err.is_some());
    }

    #[test]
    fn test_sign_fail_zero_total_num_of_nodes() {
        let total_num_of_nodes = 0;
        let node_index = 2;
        let kp = BlsKeyPair::gen_bls_key_pair().unwrap();
        kp.print();
        let mut msg = generate_random_msg();
        let err = BlsSignature::sign(&kp.sk_bytes, &msg, node_index, total_num_of_nodes).err();
       // println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_sign_fail_node_index_bigger_than_total_num_of_nodes() {
        let total_num_of_nodes = 100;
        let node_index = 100;
        let kp = BlsKeyPair::gen_bls_key_pair().unwrap();
        kp.print();
        let mut msg = generate_random_msg();
        let err = BlsSignature::sign(&kp.sk_bytes, &msg, node_index, total_num_of_nodes).err();
        //println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_sign() {
        let total_num_of_nodes = 300;
        let node_index = 33;
        let kp = BlsKeyPair::gen_bls_key_pair().unwrap();
        kp.print();
        let mut msg = generate_random_msg();
        let sig_bytes = BlsSignature::simple_sign(&kp.sk_bytes, &msg).unwrap();
        let bls_sig_bytes = BlsSignature::sign(&kp.sk_bytes, &msg, node_index, total_num_of_nodes).unwrap();
        let bls_sig = BlsSignature::deserialize(&bls_sig_bytes).unwrap();
        assert_eq!(sig_bytes, bls_sig.sig_bytes);
        assert_eq!(bls_sig.nodes_info.total_num_of_nodes, total_num_of_nodes);
        assert_eq!(bls_sig.nodes_info.map, HashMap::from([(33, 1)]));
    }

    /** get_nodes_info_from_sig **/

    #[test]
    fn test_get_nodes_info_from_sig_fail_too_short_input() {
        let vec: Vec<u8> = Vec::new();
        let mut vec= Vec::new();
        for n in 0..(BLS_SIG_LEN + 6){
            let err = BlsSignature::get_nodes_info_from_sig(&vec).err();
            //println!("{}",err.unwrap().to_string());
            assert!(err.is_some());
            vec.push(100);
        }
    }

    #[test]
    fn test_get_nodes_info_from_sig_fail_input_len_incorrect() {
        let mut vec = vec![0; BLS_SIG_LEN];
        let mut nodes_info: Vec<u8> = vec![0, 100, 0, 99, 0, 100, 3];
        vec.append(&mut nodes_info);
        let err = BlsSignature::get_nodes_info_from_sig(&vec).err();
        // println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_get_nodes_info_from_sig_fail_index_bigger_than_total_num_of_nodes() {
        let mut vec = vec![0; BLS_SIG_LEN];
        let mut nodes_info: Vec<u8> = vec![0, 100, 0, 100, 0, 99];
        vec.append(&mut nodes_info);
        let err = BlsSignature::get_nodes_info_from_sig(&vec).err();
        // println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_get_nodes_info_from_sig_fail_zero_total_num_of_nodes() {
        let mut vec = vec![0; BLS_SIG_LEN];
        let mut nodes_info: Vec<u8> = vec![0, 0, 0, 1, 0, 99];
        vec.append(&mut nodes_info);
        let err = BlsSignature::get_nodes_info_from_sig(&vec).err();
        // println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_get_nodes_info_from_sig_fail_zero_number_of_occurrences() {
        let mut vec = vec![0; BLS_SIG_LEN];
        let mut nodes_info: Vec<u8> = vec![0, 7, 0, 1, 0, 0];
        vec.append(&mut nodes_info);
        let err = BlsSignature::get_nodes_info_from_sig(&vec).err();
        // println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_get_nodes_info_from_sig() {
        let mut vec = vec![1; BLS_SIG_LEN];
        let mut nodes_info: Vec<u8> =  vec![0, 100, 0, 98, 0, 120, 0, 70, 1, 1];
        vec.append(&mut nodes_info);
        let nodes_info = NodesInfo::deserialize(&BlsSignature::get_nodes_info_from_sig(&vec).unwrap()).unwrap();
        nodes_info.print();
        assert_eq!(nodes_info.total_num_of_nodes, 100);
        let mut new_info: HashMap<u16, u16> = HashMap::from([(98, 120), (70, 257)]);
        assert_eq!(new_info, nodes_info.map);
    }

    /** truncate_nodes_info_from_sig **/

    #[test]
    fn test_truncate_nodes_info_from_sig_fail_too_short_input() {
        let vec: Vec<u8> = Vec::new();
        let mut vec= Vec::new();
        for n in 0..(BLS_SIG_LEN + 6){
            let err = BlsSignature::truncate_nodes_info_from_sig(&vec).err();
            //println!("{}",err.unwrap().to_string());
            assert!(err.is_some());
            vec.push(100);
        }
    }

    #[test]
    fn test_truncate_nodes_info_from_sig_fail_input_len_incorrect() {
        let mut vec = vec![0; BLS_SIG_LEN];
        let mut nodes_info: Vec<u8> = vec![0, 100, 0, 99, 0, 100, 3];
        vec.append(&mut nodes_info);
        let err = BlsSignature::truncate_nodes_info_from_sig(&vec).err();
        // println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_truncate_nodes_info_from_sig_fail_index_bigger_than_total_num_of_nodes() {
        let mut vec = vec![0; BLS_SIG_LEN];
        let mut nodes_info: Vec<u8> = vec![0, 100, 0, 100, 0, 99];
        vec.append(&mut nodes_info);
        let err = BlsSignature::truncate_nodes_info_from_sig(&vec).err();
        // println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_truncate_nodes_info_from_sig__fail_zero_total_num_of_nodes() {
        let mut vec = vec![0; BLS_SIG_LEN];
        let mut nodes_info: Vec<u8> = vec![0, 0, 0, 1, 0, 99];
        vec.append(&mut nodes_info);
        let err = BlsSignature::truncate_nodes_info_from_sig(&vec).err();
        // println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_truncate_nodes_info_from_sig_fail_zero_number_of_occurrences() {
        let mut vec = vec![0; BLS_SIG_LEN];
        let mut nodes_info: Vec<u8> = vec![0, 7, 0, 1, 0, 0];
        vec.append(&mut nodes_info);
        let err = BlsSignature::truncate_nodes_info_from_sig(&vec).err();
        // println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_truncate_nodes_info_from_sig_from_sig() {
        let mut vec = vec![10; BLS_SIG_LEN];
        let mut nodes_info: Vec<u8> =  vec![0, 100, 0, 98, 0, 120, 0, 70, 1, 1];
        vec.append(&mut nodes_info);
        let sig_bytes = &BlsSignature::truncate_nodes_info_from_sig(&vec).unwrap();
        assert_eq!(vec![10; BLS_SIG_LEN], sig_bytes);
    }

    /** verify **/

    #[test]
    fn test_verify_fail_empty_msg() {
        let mut bls_sig_bytes = vec![10; BLS_SIG_LEN];
        let mut nodes_info: Vec<u8> =  vec![0, 100, 0, 98, 0, 120, 0, 70, 1, 1];
        bls_sig_bytes.append(&mut nodes_info);
        let pk_bytes = [1; BLS_PUBLIC_KEY_LEN];
        let msg = Vec::new();
        let err = BlsSignature::verify(&bls_sig_bytes, &pk_bytes, &msg).err();
       // println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_verify_fail_too_short_input() {
        let pk_bytes = [1; BLS_PUBLIC_KEY_LEN];
        let msg = generate_random_msg();
        let vec: Vec<u8> = Vec::new();
        let mut vec= Vec::new();
        for n in 0..(BLS_SIG_LEN + 6){
            let err = BlsSignature::verify(&vec, &pk_bytes, &msg).err();
            //println!("{}",err.unwrap().to_string());
            assert!(err.is_some());
            vec.push(100);
        }
    }

    #[test]
    fn test_verify_fail_input_len_incorrect() {
        let mut bls_sig_bytes = vec![10; BLS_SIG_LEN];
        let mut nodes_info: Vec<u8> = vec![0, 100, 0, 99, 0, 100, 3];
        bls_sig_bytes.append(&mut nodes_info);
        let pk_bytes = [1; BLS_PUBLIC_KEY_LEN];
        let msg = Vec::new();
        let err = BlsSignature::verify(&bls_sig_bytes, &pk_bytes, &msg).err();
      //  println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_verify_fail_index_bigger_than_total_num_of_nodes() {
        let mut bls_sig_bytes = vec![10; BLS_SIG_LEN];
        let mut nodes_info: Vec<u8> = vec![0, 100, 0, 100, 0, 99];
        bls_sig_bytes.append(&mut nodes_info);
        let pk_bytes = [1; BLS_PUBLIC_KEY_LEN];
        let msg = Vec::new();
        let err = BlsSignature::verify(&bls_sig_bytes, &pk_bytes, &msg).err();
        //  println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_verify_fail_zero_total_num_of_nodes() {
        let mut bls_sig_bytes = vec![10; BLS_SIG_LEN];
        let mut nodes_info: Vec<u8> = vec![0, 0, 0, 100, 0, 99];
        bls_sig_bytes.append(&mut nodes_info);
        let pk_bytes = [1; BLS_PUBLIC_KEY_LEN];
        let msg = Vec::new();
        let err = BlsSignature::verify(&bls_sig_bytes, &pk_bytes, &msg).err();
         // println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_verify_fail_zero_number_of_occurrences() {
        let mut bls_sig_bytes = vec![10; BLS_SIG_LEN];
        let mut nodes_info: Vec<u8> = vec![0, 3, 0, 2, 0, 0];
        bls_sig_bytes.append(&mut nodes_info);
        let pk_bytes = [1; BLS_PUBLIC_KEY_LEN];
        let msg = Vec::new();
        let err = BlsSignature::verify(&bls_sig_bytes, &pk_bytes, &msg).err();
        // println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    /** sign/verify **/

    #[test]
    fn test_sign_verify() {
        let total_num_of_nodes = 100;
        let node_index = 2;
        let kp = BlsKeyPair::gen_bls_key_pair().unwrap();
        kp.print();
        let mut msg = generate_random_msg();
        let bls_sig_bytes = BlsSignature::sign(&kp.sk_bytes, &msg, node_index, total_num_of_nodes).unwrap();
        let res = BlsSignature::verify(&bls_sig_bytes,  &kp.pk_bytes, &msg).unwrap();
        println!("res = {}", res);
        assert_eq!(res, true);
    }

    #[test]
    fn test_sign_verify_with_wrong_key() {
        let total_num_of_nodes = 100;
        let node_index = 2;
        let kp_1 = BlsKeyPair::gen_bls_key_pair().unwrap();
        kp_1.print();
        let kp_2 = BlsKeyPair::gen_bls_key_pair().unwrap();
        kp_2.print();
        let mut msg = generate_random_msg();
        let bls_sig_bytes = BlsSignature::sign(&kp_1.sk_bytes, &msg, node_index, total_num_of_nodes).unwrap();
        let res = BlsSignature::verify(&bls_sig_bytes,  &kp_2.pk_bytes, &msg).unwrap();
        println!("res = {}", res);
        assert_eq!(res, false);
    }

    /** additional test for intersection **/

    #[test]
    fn test_agg_sig_intersection_issue() {
        let kp1 = BlsKeyPair::gen_key_pair().unwrap();
        let kp2 = BlsKeyPair::gen_key_pair().unwrap();
        let kp3 = BlsKeyPair::gen_key_pair().unwrap();

        println!("PK1 = {:?}", &kp1.pk.to_bytes());
        println!("PK2 = {:?}", &kp2.pk.to_bytes());
        println!("PK3 = {:?}", &kp3.pk.to_bytes());

        let mut pks_refs: Vec<&PublicKey> = Vec::new();
        pks_refs.push(&kp1.pk);
        pks_refs.push(&kp2.pk);
        pks_refs.push(&kp3.pk);

        let agg_pk = match AggregatePublicKey::aggregate(&pks_refs, false) {
            Ok(agg_pk) => agg_pk,
            Err(err) => panic!("aggregate failure: {:?}", err),
        };
        let pk = agg_pk.to_public_key();

        println!("{:?}", &pk.to_bytes());
        println!("!the slice has {} elements", &pk.to_bytes().len());

        let mut msg = generate_random_msg();

        let mut sigs_from_nodes_part1: Vec<Signature> = Vec::new();
        sigs_from_nodes_part1.push(kp1.sk.sign(&msg, &DST, &[]));
        sigs_from_nodes_part1.push(kp2.sk.sign(&msg, &DST, &[]));
        println!("sig len = {}", sigs_from_nodes_part1[0].to_bytes().len());
        println!("sig len = {}", sigs_from_nodes_part1[1].to_bytes().len());

        let mut sig_refs1: Vec<&Signature> = Vec::new();
        for sig in &sigs_from_nodes_part1 {
            sig_refs1.push(&sig);
        }

        let mut agg_temp1 = AggregateSignature::from_signature(&sig_refs1[0]);
        AggregateSignature::add_signature(&mut agg_temp1, &sig_refs1[1], false).unwrap();

        let sigg1 = agg_temp1.to_signature();

        let mut sigs_from_nodes_part2: Vec<Signature> = Vec::new();
        sigs_from_nodes_part2.push(kp3.sk.sign(&msg, &DST, &[]));
        sigs_from_nodes_part2.push(kp1.sk.sign(&msg, &DST, &[]));

        println!("sig len = {}", sigs_from_nodes_part2[0].to_bytes().len());
        println!("sig len = {}", sigs_from_nodes_part2[1].to_bytes().len());

        let mut sig_refs2: Vec<&Signature> = Vec::new();
        for sig in &sigs_from_nodes_part2 {
            sig_refs2.push(&sig);
        }

        let mut agg_temp2 = AggregateSignature::from_signature(&sig_refs2[0]);
        AggregateSignature::add_signature(&mut agg_temp2, &sig_refs2[1], false).unwrap();

        let sigg2 = agg_temp2.to_signature();

        let mut agg_temp_last = AggregateSignature::from_signature(&sigg1);
        AggregateSignature::add_signature(&mut agg_temp_last, &sigg2, false).unwrap();

        let agg_final = agg_temp_last.to_signature();
        println!("@@sig len = {}", agg_final.to_bytes().len());
        println!("{:?}", &agg_final.to_bytes());

        let res = BlsSignature::simple_verify(&agg_final.to_bytes(), &msg, &pk.to_bytes()).unwrap();

        println!("res = {}", res);

        assert_eq!(res, false);
    }

    #[test]
    fn test_agg_sig_intersection_issue2() {
        let kp1 = BlsKeyPair::gen_key_pair().unwrap();
        let kp2 = BlsKeyPair::gen_key_pair().unwrap();
        let kp3 = BlsKeyPair::gen_key_pair().unwrap();

        println!("PK1 = {:?}", &kp1.pk.to_bytes());
        println!("PK2 = {:?}", &kp2.pk.to_bytes());
        println!("PK3 = {:?}", &kp3.pk.to_bytes());

        let mut pks_refs1: Vec<&PublicKey> = Vec::new();
        pks_refs1.push(&kp1.pk);
        pks_refs1.push(&kp2.pk);
        // pks_refs.push(&kp3.pk);

        let agg_pk1 = match AggregatePublicKey::aggregate(&pks_refs1, false) {
            Ok(agg_pk) => agg_pk,
            Err(err) => panic!("aggregate failure: {:?}", err),
        };

        let pk12 = agg_pk1.to_public_key();

        let mut pks_refs2: Vec<&PublicKey> = Vec::new();
        pks_refs2.push(&kp3.pk);
        pks_refs2.push(&kp1.pk);

        let agg_pk2 = match AggregatePublicKey::aggregate(&pks_refs2, false) {
            Ok(agg_pk) => agg_pk,
            Err(err) => panic!("aggregate failure: {:?}", err),
        };

        let pk13 = agg_pk2.to_public_key();

        let mut agg_pk_final = AggregatePublicKey::from_public_key(&pk12);
        AggregatePublicKey::add_public_key(&mut agg_pk_final, &pk13, false).unwrap();

        let pk = agg_pk_final.to_public_key();

        println!("{:?}", &pk.to_bytes());
        println!("!the slice has {} elements", &pk.to_bytes().len());

        let mut msg = generate_random_msg();

        let mut sigs_from_nodes_part1: Vec<Signature> = Vec::new();
        sigs_from_nodes_part1.push(kp1.sk.sign(&msg, &DST, &[]));
        sigs_from_nodes_part1.push(kp2.sk.sign(&msg, &DST, &[]));
        println!("sig len = {}", sigs_from_nodes_part1[0].to_bytes().len());
        println!("sig len = {}", sigs_from_nodes_part1[1].to_bytes().len());

        let mut sig_refs1: Vec<&Signature> = Vec::new();
        for sig in &sigs_from_nodes_part1 {
            sig_refs1.push(&sig);
        }

        let mut agg_temp1 = AggregateSignature::from_signature(&sig_refs1[0]);
        AggregateSignature::add_signature(&mut agg_temp1, &sig_refs1[1], false).unwrap();

        let sigg1 = agg_temp1.to_signature();

        let mut sigs_from_nodes_part2: Vec<Signature> = Vec::new();
        sigs_from_nodes_part2.push(kp1.sk.sign(&msg, &DST, &[]));
        sigs_from_nodes_part2.push(kp3.sk.sign(&msg, &DST, &[]));

        println!("sig len = {}", sigs_from_nodes_part2[0].to_bytes().len());
        println!("sig len = {}", sigs_from_nodes_part2[1].to_bytes().len());

        let mut sig_refs2: Vec<&Signature> = Vec::new();
        for sig in &sigs_from_nodes_part2 {
            sig_refs2.push(&sig);
        }

        let mut agg_temp2 = AggregateSignature::from_signature(&sig_refs2[0]);
        AggregateSignature::add_signature(&mut agg_temp2, &sig_refs2[1], false).unwrap();

        let sigg2 = agg_temp2.to_signature();

        let mut agg_temp_last = AggregateSignature::from_signature(&sigg1);
        AggregateSignature::add_signature(&mut agg_temp_last, &sigg2, false).unwrap();

        let agg_final = agg_temp_last.to_signature();
        println!("@@sig len = {}", agg_final.to_bytes().len());
        println!("{:?}", &agg_final.to_bytes());

        let res = BlsSignature::simple_verify(&agg_final.to_bytes(), &msg, &pk.to_bytes()).unwrap();

        println!("res = {}", res);

        assert_eq!(res, true);

        //  assert_eq!(res, false);
    }

    #[test]
    fn test_agg_sig_intersection_issue3() {
        let kp1 = BlsKeyPair::gen_key_pair().unwrap();
        let kp2 = BlsKeyPair::gen_key_pair().unwrap();
        let kp3 = BlsKeyPair::gen_key_pair().unwrap();

        println!("PK1 = {:?}", &kp1.pk.to_bytes());
        println!("PK2 = {:?}", &kp2.pk.to_bytes());
        println!("PK3 = {:?}", &kp3.pk.to_bytes());

        let mut pks_refs1: Vec<&PublicKey> = Vec::new();
        pks_refs1.push(&kp1.pk);
        pks_refs1.push(&kp2.pk);
        pks_refs1.push(&kp3.pk);
        pks_refs1.push(&kp1.pk);

        let agg_pk = match AggregatePublicKey::aggregate(&pks_refs1, false) {
            Ok(agg_pk) => agg_pk,
            Err(err) => panic!("aggregate failure: {:?}", err),
        };

        let pk = agg_pk.to_public_key();

        println!("{:?}", &pk.to_bytes());
        println!("!the slice has {} elements", &pk.to_bytes().len());

        let mut msg = generate_random_msg();

        let mut sigs_from_nodes_part1: Vec<Signature> = Vec::new();
        sigs_from_nodes_part1.push(kp1.sk.sign(&msg, &DST, &[]));
        sigs_from_nodes_part1.push(kp2.sk.sign(&msg, &DST, &[]));
        println!("sig len = {}", sigs_from_nodes_part1[0].to_bytes().len());
        println!("sig len = {}", sigs_from_nodes_part1[1].to_bytes().len());

        let mut sig_refs1: Vec<&Signature> = Vec::new();
        for sig in &sigs_from_nodes_part1 {
            sig_refs1.push(&sig);
        }

        let mut agg_temp1 = AggregateSignature::from_signature(&sig_refs1[0]);
        AggregateSignature::add_signature(&mut agg_temp1, &sig_refs1[1], false).unwrap();

        let sigg1 = agg_temp1.to_signature();

        let mut sigs_from_nodes_part2: Vec<Signature> = Vec::new();
        sigs_from_nodes_part2.push(kp1.sk.sign(&msg, &DST, &[]));
        sigs_from_nodes_part2.push(kp3.sk.sign(&msg, &DST, &[]));

        println!("sig len = {}", sigs_from_nodes_part2[0].to_bytes().len());
        println!("sig len = {}", sigs_from_nodes_part2[1].to_bytes().len());

        let mut sig_refs2: Vec<&Signature> = Vec::new();
        for sig in &sigs_from_nodes_part2 {
            sig_refs2.push(&sig);
        }

        let mut agg_temp2 = AggregateSignature::from_signature(&sig_refs2[0]);
        AggregateSignature::add_signature(&mut agg_temp2, &sig_refs2[1], false).unwrap();

        let sigg2 = agg_temp2.to_signature();

        let mut agg_temp_last = AggregateSignature::from_signature(&sigg1);
        AggregateSignature::add_signature(&mut agg_temp_last, &sigg2, false).unwrap();

        let agg_final = agg_temp_last.to_signature();
        println!("@@sig len = {}", agg_final.to_bytes().len());
        println!("{:?}", &agg_final.to_bytes());

        let res = BlsSignature::simple_verify(&agg_final.to_bytes(), &msg, &pk.to_bytes()).unwrap();

        println!("res = {}", res);

        assert_eq!(res, true);
    }

    #[test]
    fn test() {
        let total_num_of_nodes = 100;
        let node_index = 3;
        let nodes_info = NodesInfo::create_node_info(total_num_of_nodes, node_index).unwrap();
        nodes_info.print();

        let kp = BlsKeyPair::gen_bls_key_pair().unwrap();
        kp.print();

        let mut msg = generate_random_msg();
        let sig_bytes = BlsSignature::simple_sign(&kp.sk_bytes, &msg).unwrap();

        println!("Signature:");
        println!("{:?}", sig_bytes);

        let acc_sig = BlsSignature {
            sig_bytes,
            nodes_info,
        };
        let acc_sig_serialized = BlsSignature::serialize(&acc_sig);

        println!("acc_sig_serialized:");
        println!("{:?}", acc_sig_serialized);

        let acc_sig_new = BlsSignature::deserialize(&acc_sig_serialized).unwrap();

        assert_eq!(acc_sig_new.nodes_info, acc_sig.nodes_info);

        acc_sig_new.nodes_info.print();
        acc_sig.nodes_info.print();

        assert_eq!(acc_sig.sig_bytes, acc_sig_new.sig_bytes);

        let res = BlsSignature::simple_verify(&acc_sig_new.sig_bytes, &msg, &kp.pk_bytes).unwrap();

        println!("res = {}", res);
        assert_eq!(res, true);
    }

    #[test]
    fn test_point_of_infinity_agg()  {
        let kp = BlsKeyPair::gen_bls_key_pair().unwrap();
        kp.print();
        let kp1 = BlsKeyPair::gen_bls_key_pair().unwrap();
        kp1.print();
        let kp2 = BlsKeyPair::gen_bls_key_pair().unwrap();
        kp2.print();
        let kp3 = BlsKeyPair::gen_bls_key_pair().unwrap();
        kp3.print();
        let kp4 = BlsKeyPair::gen_bls_key_pair().unwrap();
        kp4.print();

       // let arr: [u8; BLS_PUBLIC_KEY_LEN] = [129, 70, 150, 125, 169, 172, 192, 188, 9, 54, 153, 180, 207, 211, 148, 25, 5, 82, 202, 176, 6, 166, 177, 79, 220, 204, 168, 36, 162, 159, 172, 63, 141, 16, 248, 139, 97, 73, 38, 154, 188, 186, 72, 188, 75, 27, 199, 44];

       //  let mut arr = vec![0; 47];//[130, 70, 150, 125, 169, 172, 192, 188, 9, 54, 153, 180, 207, 211, 148, 25, 5, 82, 202, 176, 6, 166, 177, 79, 220, 204, 168, 36, 162, 159, 172, 63, 141, 16, 248, 139, 97, 73, 38, 154, 188, 186, 72, 188, 75, 27, 199, 44];

     /*   let left: [u8; 1] = [0x80];
        let right: [u8; 47] = [0; 47];
        let v = [left, right].concat();
        let mut arr: [u8; 48] = v.try_into().unwrap();


      //  assert_eq!([left, right].concat(), [1,2,3,4]);

      */
        let a1 = [0xC0];
        let a2 = [0; 47];

        let mut whole: Vec<u8> = a1.iter().chain(a2.iter()).map(|v| *v).collect();
        let whole: [u8; 48] = whole.try_into().unwrap();
        println!("{:?}", whole);

        let pk  = convert_public_key_bytes_to_public_key(&whole).unwrap();
       // println!("{}",err.unwrap().to_string());


        let mut pks: Vec<PublicKey> = Vec::new();
        pks.push(pk);


        let pk_refs: Vec<&PublicKey> = pks.iter().map(|pk| pk).collect();
        let err = AggregatePublicKey::aggregate(&pk_refs, true).err();
        assert!(err.is_some());
    }


}

