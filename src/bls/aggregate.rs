use super::converters::*;
use super::random_helper::*;
use super::nodes_info::*;
use super::key_gen::*;
use super::sig::*;
use crate::bls::*;
use blst::*;
use blst::min_pk::*;
//use blst::min_sig::*;
use ton_types::{fail, Result};
use std::collections::HashMap;

pub fn aggregate_public_keys(bls_pks_bytes: &Vec<&[u8; BLS_PUBLIC_KEY_LEN]>) -> Result<[u8; BLS_PUBLIC_KEY_LEN]> {
    if bls_pks_bytes.len() == 0 {
        fail!("Vector of public keys can not be empty!");
    }
    let mut pks: Vec<PublicKey> = Vec::new();
    for bls_pk in bls_pks_bytes {
        pks.push(convert_public_key_bytes_to_public_key(bls_pk)?);
    }
    let pk_refs: Vec<&PublicKey> = pks.iter().map(|pk| pk).collect();
    let agg = match AggregatePublicKey::aggregate(&pk_refs, true) {
        Ok(agg) => agg,
        Err(err) => fail!("aggregate failure: {:?}", err),
    };
    Ok(agg.to_public_key().to_bytes())
}

pub fn aggregate_public_keys_based_on_nodes_info(bls_pks_bytes: &Vec<&[u8; BLS_PUBLIC_KEY_LEN]>, nodes_info_bytes: &Vec<u8>) -> Result<[u8; BLS_PUBLIC_KEY_LEN]> {
    if bls_pks_bytes.len() == 0 {
        fail!("Vector of public keys can not be empty!");
    }
    let nodes_info = NodesInfo::deserialize(nodes_info_bytes)?;
    if bls_pks_bytes.len() != nodes_info.total_num_of_nodes as usize {
        fail!("Vector of public keys is too short!");
    }
    let mut apk_pks_required_refs: Vec<&[u8; BLS_PUBLIC_KEY_LEN]> = Vec::new();
    for (index, number_of_occurrence) in &nodes_info.map {
        for i in 0..*number_of_occurrence {
            apk_pks_required_refs.push(bls_pks_bytes[*index as usize]);
        }
    }
    let now = Instant::now();
    let result = aggregate_public_keys(&apk_pks_required_refs)?;
    let duration = now.elapsed();

    println!("Time elapsed by !!!aggregate_public_keys is: {:?}", duration);
    Ok(result)
}

pub fn aggregate_two_bls_signatures(sig_bytes_with_nodes_info_1: &Vec<u8>, sig_bytes_with_nodes_info_2: &Vec<u8>) -> Result<Vec<u8>> {
    let bls_sig_1 = BlsSignature::deserialize(sig_bytes_with_nodes_info_1)?;
    let bls_sig_2 = BlsSignature::deserialize(sig_bytes_with_nodes_info_2)?;
    let new_nodes_info = NodesInfo::merge(&bls_sig_1.nodes_info, &bls_sig_2.nodes_info)?;
    let sig1 = convert_signature_bytes_to_signature(&bls_sig_1.sig_bytes)?;
    let sig2 = convert_signature_bytes_to_signature(&bls_sig_2.sig_bytes)?;
    let sig_validate_res = sig1.validate(false); //set true to exclude infinite point, i.e. zero sig
    if sig_validate_res.is_err() {
        fail!("Signature is not in group.");
    }
    let mut agg_sig = AggregateSignature::from_signature(&sig1);
    let res = AggregateSignature::add_signature(&mut agg_sig, &sig2, true);
    if res.is_err() {
        fail!("Failure while concatenate signatures");
    }
    let new_sig = agg_sig.to_signature();
    let new_agg_sig = BlsSignature {
        sig_bytes: new_sig.to_bytes(),
        nodes_info: new_nodes_info,
    };
    let new_agg_sig_bytes = BlsSignature::serialize(&new_agg_sig);
    Ok(new_agg_sig_bytes)
}

pub fn aggregate_bls_signatures(sig_bytes_with_nodes_info_vec: &Vec<&Vec<u8>>) -> Result<Vec<u8>> {
    if sig_bytes_with_nodes_info_vec.len() == 0 {
        fail!("Vector of signatures can not be empty!");
    }
    let mut bls_sigs: Vec<BlsSignature> = Vec::new();
    for bytes in sig_bytes_with_nodes_info_vec {
        let agg_sig = BlsSignature::deserialize(&bytes)?;
        bls_sigs.push(agg_sig);
    }

    let bls_sigs_refs: Vec<&BlsSignature> = bls_sigs.iter().map(|sig| sig).collect();
    let mut nodes_info_refs: Vec<&NodesInfo> = Vec::new();
    let mut sigs: Vec<Signature> = Vec::new();
    for i in 0..bls_sigs_refs.len() {
        nodes_info_refs.push(&bls_sigs_refs[i].nodes_info);
        let sig = convert_signature_bytes_to_signature(&bls_sigs_refs[i].sig_bytes)?;
        println!("{:?}", &sig.to_bytes());
        //return this part to exclude zero sig
       /* let res = sig.validate(true);
        if res.is_err() {
            fail!("Sig is point of infinity or does not belong to group.");
        }*/
        sigs.push(sig);
    }

    let new_nodes_info = NodesInfo::merge_multiple(&nodes_info_refs)?;

    let sig_refs: Vec<&Signature> = sigs.iter().map(|sig| sig).collect();

    let agg = match AggregateSignature::aggregate(&sig_refs, true) {
        Ok(agg) => agg,
        Err(err) => fail!("aggregate failure: {:?}", err),
    };
    let new_sig = agg.to_signature();
    let new_sig_bytes = convert_signature_to_signature_bytes(new_sig);
    let new_agg_sig = BlsSignature {
        sig_bytes: new_sig_bytes,
        nodes_info: new_nodes_info,
    };
    let new_agg_sig_bytes = BlsSignature::serialize(&new_agg_sig);
    Ok(new_agg_sig_bytes)
}


#[cfg(test)]
mod tests_aggregate {
    use super::*;
    use super::*;
    use std::collections::HashSet;
    use std::error::Error;
    use std::fs::File;
    use std::io::{Read, Write};
    use failure::err_msg;
    use super::*;
    use rand::SeedableRng;
    use rand::Rng;
    use rand::{RngCore};

    /** zero split prevention and correct group checking **/

    #[test]
    //this is for zero public key
    fn test_aggregate_public_keys_fail_pk_is_infinity_point_for_min_pk_mode() {
        let mut bls_pk_vec: Vec<&[u8; BLS_PUBLIC_KEY_LEN]> = Vec::new();
        let kp_1 = BlsKeyPair::gen_bls_key_pair().unwrap();
        let key_1: [u8; BLS_PUBLIC_KEY_LEN] = kp_1.pk_bytes;

        // public key in compressed form in min_pk mode has size 381 bits
        // in reality we have array of length 384 bits, where first three bits of first byte are reserved
        let a1 = [0xC0]; //11000000, here first two bits shows that public key is in compressed form and it's gonna be a point of infinity (zero vector)
        // all other bits will be zero
        let a2 = [0; BLS_PUBLIC_KEY_LEN - 1];

        let mut key_2: Vec<u8> = a1.iter().chain(a2.iter()).map(|v| *v).collect();
        let key_2: [u8; BLS_PUBLIC_KEY_LEN] = key_2.try_into().unwrap();
        println!("{:?}", key_2);
        //key_2 now is really zero public key for blst lib, it will not throw bad encoding error and we can work with it
        //but to exclude zero split attack cases we setup additional verification everywhere to exclude zero public key

        let  mut keys = Vec::new();
        keys.push(&key_2);
         keys.push(&key_1);

         let err = aggregate_public_keys(&keys).err();
         println!("{}",err.unwrap().to_string());
        //assert!(err.is_some());
    }

    #[test]
    //this is for zero public key
    fn test_infinity_pk_compressed_validate() {
        // public key in compressed form in min_pk mode has size 381 bits
        // in reality we have array of length 384 bits, where first three bits of first byte are reserved
        let a1 = [0xC0]; //11000000, here first two bits shows that public key is in compressed form and it's gonna be a point of infinity (zero vector)
        // all other bits will be zero
        let a2 = [0; BLS_PUBLIC_KEY_LEN - 1];
        let mut key_2: Vec<u8> = a1.iter().chain(a2.iter()).map(|v| *v).collect();
        let key_2: [u8; BLS_PUBLIC_KEY_LEN] = key_2.try_into().unwrap();
        println!("{:?}", key_2);
        //key_2 now is really zero public key for blst lib, it will not throw bad encoding error and we can work with it
        //but to exclude zero split attack cases we setup additional verification everywhere to exclude zero public key
        let pkk =  PublicKey::from_bytes(&key_2).unwrap();
        //let pkk = //convert_public_key_bytes_to_public_key(&key_2).unwrap();
        let err = pkk.validate().err();
        println!("ERROR {:?}", err);
    }

    #[test]
    fn test_infinity_pk_uncompressed_validate() {
        let a1 = [0x40]; //01000000, here first two bits shows that public key is in compressed form and it's gonna be a point of infinity (zero vector)
        // all other bits will be zero
        let a2 = [0; 2*BLS_PUBLIC_KEY_LEN - 1];
        let mut key_2: Vec<u8> = a1.iter().chain(a2.iter()).map(|v| *v).collect();
        let key_2: [u8; 2*BLS_PUBLIC_KEY_LEN] = key_2.try_into().unwrap();
        println!("{:?}", key_2);
        let pkk =  PublicKey::from_bytes(&key_2).unwrap();
        let err = pkk.validate().err();
        println!("ERROR {:?}", err);
    }

    #[test]
    fn test_aggregate_public_keys_fail_pk_not_in_group() {
        let mut bls_pk_vec: Vec<&[u8; BLS_PUBLIC_KEY_LEN]> = Vec::new();
        let kp_1 = BlsKeyPair::gen_bls_key_pair().unwrap();
        let key_1: [u8; BLS_PUBLIC_KEY_LEN] = kp_1.pk_bytes;
        let key_2 = [130, 70, 150, 125, 169, 172, 192, 188, 9, 54, 153, 180, 207, 211, 148, 25, 5, 82, 202, 176, 6, 166, 177, 79, 220, 204, 168, 36, 162, 159, 172, 63, 141, 16, 248, 139, 97, 73, 38, 154, 188, 186, 72, 188, 75, 27, 199, 44];
        let  mut keys = Vec::new();
        keys.push(&key_1);
        keys.push(&key_2);
        let err = aggregate_public_keys(&keys).err();
        println!("{}",err.unwrap().to_string());
        //assert!(err.is_some());
    }

    #[test]
    fn test_infinity_sig_compressed_validate() {
        let a1 = [0xC0]; //11000000, here first two bits shows that public key is in compressed form and it's gonna be a point of infinity (zero vector)
        // all other bits will be zero
        let a2 = [0; BLS_SIG_LEN - 1];

        let mut sig_2: Vec<u8> = a1.iter().chain(a2.iter()).map(|v| *v).collect();
        let sig_2: [u8; BLS_SIG_LEN] = sig_2.try_into().unwrap();
        println!("{:?}", sig_2);

        let ss = Signature::from_bytes(&sig_2).unwrap();
        let err = ss.validate(true).err();
        println!("ERROR {:?}", err);/**/
        //assert!(err.is_some());
    }

    #[test]
    fn test_infinity_sig_uncompressed_validate() {
        let a1 = [0x40]; //11000000, here first two bits shows that public key is in compressed form and it's gonna be a point of infinity (zero vector)
        // all other bits will be zero
        let a2 = [0; 2*BLS_SIG_LEN - 1];

        let mut sig_2: Vec<u8> = a1.iter().chain(a2.iter()).map(|v| *v).collect();
        let sig_2: [u8; 2*BLS_SIG_LEN] = sig_2.try_into().unwrap();
        println!("{:?}", sig_2);

        let ss = Signature::from_bytes(&sig_2).unwrap();
        let err = ss.validate(true).err();
        println!("ERROR {:?}", err);/**/
        //assert!(err.is_some());
    }

    #[test]
    fn test_aggregate_two_bls_signatures_sig_not_in_group() {
        let total = 3;
        let ind_1 = 0;
        let ind_2 = 2;
        let kp_1 = BlsKeyPair::gen_bls_key_pair().unwrap();
        kp_1.print();
        let mut msg = generate_random_msg();
        let agg_sig_1_bytes = BlsSignature::sign(&kp_1.sk_bytes, &msg, ind_1, total).unwrap();
        let sig_2: [u8; BLS_SIG_LEN] = [145, 159, 130, 216, 123, 12, 196, 4, 178, 40, 10, 4, 206, 211, 143, 207, 233, 217, 193, 27, 251, 138, 210, 17, 189, 65, 10, 145, 47, 247, 82, 94, 15, 139, 219, 83, 9, 60, 251, 70, 121, 176, 26, 94, 188, 188, 243, 225, 17, 176, 133, 133, 150, 81, 226, 69, 136, 52, 209, 39, 19, 18, 110, 53, 61, 144, 227, 207, 190, 158, 54, 169, 113, 34, 57, 161, 90, 110, 33, 46, 164, 236, 52, 251, 142, 236, 246, 173, 1, 183, 66, 238, 48, 140, 170, 141];
        let agg_sig_2_bytes = BlsSignature::add_node_info_to_sig(sig_2, ind_2, total).unwrap();
        let err = aggregate_two_bls_signatures(&agg_sig_2_bytes, &agg_sig_1_bytes).err();
        println!("{}",err.unwrap().to_string());
    }

    #[test]
    fn test_aggregate_bls_signatures_sig_not_in_group() {
        let total = 3;
        let ind_1 = 0;
        let ind_2 = 2;
        let kp_1 = BlsKeyPair::gen_bls_key_pair().unwrap();
        kp_1.print();
        let mut msg = generate_random_msg();
        let agg_sig_1_bytes = BlsSignature::sign(&kp_1.sk_bytes, &msg, ind_1, total).unwrap();
        let sig_2: [u8; BLS_SIG_LEN] = [145, 159, 130, 216, 123, 12, 196, 4, 178, 40, 10, 4, 206, 211, 143, 207, 233, 217, 193, 27, 251, 138, 210, 17, 189, 65, 10, 145, 47, 247, 82, 94, 15, 139, 219, 83, 9, 60, 251, 70, 121, 176, 26, 94, 188, 188, 243, 225, 17, 176, 133, 133, 150, 81, 226, 69, 136, 52, 209, 39, 19, 18, 110, 53, 61, 144, 227, 207, 190, 158, 54, 169, 113, 34, 57, 161, 90, 110, 33, 46, 164, 236, 52, 251, 142, 236, 246, 173, 1, 183, 66, 238, 48, 140, 170, 141];
        let agg_sig_2_bytes = BlsSignature::add_node_info_to_sig(sig_2, ind_2, total).unwrap();
        let mut sigs = Vec::new();
        sigs.push(&agg_sig_2_bytes);
        sigs.push(&agg_sig_1_bytes);
        let err = aggregate_bls_signatures(&sigs).err();
        println!("{}",err.unwrap().to_string());
    }


    /** aggregate_public_keys **/

    #[test]
    fn test_aggregate_public_keys_fail_input_empty() {
        let bls_pk_vec = Vec::new();
        let err = aggregate_public_keys(&bls_pk_vec).err();
        assert!(err.is_some());
    }

    #[test]
    fn test_aggregate_public_keys_fail_to_aggregate_strange_public_keys() {
        let mut bls_pk_vec: Vec<&[u8; BLS_PUBLIC_KEY_LEN]> = Vec::new();
        let key_1: [u8; BLS_PUBLIC_KEY_LEN] = [1; BLS_PUBLIC_KEY_LEN];
        let key_2: [u8; BLS_PUBLIC_KEY_LEN] = [2; BLS_PUBLIC_KEY_LEN];
        bls_pk_vec.push(&key_1);
        bls_pk_vec.push(&key_2);
        let err = aggregate_public_keys(&bls_pk_vec).err();
       // println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_aggregate_public_keys_fail_to_aggregate_strange_public_keys_2() {
        let mut bls_pk_vec: Vec<&[u8; BLS_PUBLIC_KEY_LEN]> = Vec::new();
        let kp_1 = BlsKeyPair::gen_bls_key_pair().unwrap();
        let key_1: [u8; BLS_PUBLIC_KEY_LEN] = kp_1.pk_bytes;
        let key_2: [u8; BLS_PUBLIC_KEY_LEN] = [0; BLS_PUBLIC_KEY_LEN];
        bls_pk_vec.push(&key_1);
        bls_pk_vec.push(&key_2);
        let err = aggregate_public_keys(&bls_pk_vec).err();
         println!("{}",err.unwrap().to_string());
        //assert!(err.is_some());
    }


    /** aggregate_public_keys_based_on_nodes_info **/

    #[test]
    fn test_aggregate_public_keys_based_on_nodes_info_fail_bls_pks_bytes_empty() {
        let bls_pk_vec = Vec::new();
        let total_num_of_nodes = 80;
        let mut new_info = HashMap::from([(1, 1)]);
        let node_info = NodesInfo::with_data(new_info, total_num_of_nodes).unwrap().serialize();
        let err = aggregate_public_keys_based_on_nodes_info(&bls_pk_vec, &node_info).err();
        assert!(err.is_some());
    }

    #[test]
    fn test_aggregate_public_keys_based_on_nodes_info_fail_node_info_len_too_small() {
        let mut bls_pk_vec: Vec<&[u8; BLS_PUBLIC_KEY_LEN]> = Vec::new();
        let key_1: [u8; BLS_PUBLIC_KEY_LEN] = [1; BLS_PUBLIC_KEY_LEN];
        bls_pk_vec.push(&key_1);
        let mut node_info= Vec::new();
        for n in 0..6 {
            let err = aggregate_public_keys_based_on_nodes_info(&bls_pk_vec, &node_info).err();
            assert!(err.is_some());
            node_info.push(100);
        }
    }

    #[test]
    fn test_aggregate_public_keys_based_on_nodes_info_fail_node_info_len_incorrect() {
        let mut bls_pk_vec: Vec<&[u8; BLS_PUBLIC_KEY_LEN]> = Vec::new();
        let key_1: [u8; BLS_PUBLIC_KEY_LEN] = [1; BLS_PUBLIC_KEY_LEN];
        bls_pk_vec.push(&key_1);
        let mut node_info = vec![0, 100, 0, 99, 0, 100, 3];
        let err = aggregate_public_keys_based_on_nodes_info(&bls_pk_vec, &node_info).err();
        assert!(err.is_some());
    }

    #[test]
    fn test_aggregate_public_keys_based_on_nodes_info_fail_zero_total_num_of_nodes() {
        let mut bls_pk_vec: Vec<&[u8; BLS_PUBLIC_KEY_LEN]> = Vec::new();
        let key_1: [u8; BLS_PUBLIC_KEY_LEN] = [1; BLS_PUBLIC_KEY_LEN];
        bls_pk_vec.push(&key_1);
        let mut node_info = vec![0, 0, 0, 5, 0, 99];
        let err = aggregate_public_keys_based_on_nodes_info(&bls_pk_vec, &node_info).err();
        assert!(err.is_some());
    }

    #[test]
    fn test_aggregate_public_keys_based_on_nodes_info_fail_index_bigger_than_total_num_of_nodes() {
        let mut bls_pk_vec: Vec<&[u8; BLS_PUBLIC_KEY_LEN]> = Vec::new();
        let key_1: [u8; BLS_PUBLIC_KEY_LEN] = [1; BLS_PUBLIC_KEY_LEN];
        bls_pk_vec.push(&key_1);
        let mut node_info = vec![0, 100, 0, 100, 0, 99];
        let err = aggregate_public_keys_based_on_nodes_info(&bls_pk_vec, &node_info).err();
        println!("{}",err.unwrap().to_string());
        //assert!(err.is_some());
    }

    #[test]
    fn test_aggregate_public_keys_based_on_nodes_info_fail_zero_number_of_occurrences() {
        let mut bls_pk_vec: Vec<&[u8; BLS_PUBLIC_KEY_LEN]> = Vec::new();
        let key_1: [u8; BLS_PUBLIC_KEY_LEN] = [1; BLS_PUBLIC_KEY_LEN];
        bls_pk_vec.push(&key_1);
        let mut node_info = vec![0, 100, 0, 66, 0, 0];
        let err = aggregate_public_keys_based_on_nodes_info(&bls_pk_vec, &node_info).err();
        //println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_aggregate_public_keys_based_on_nodes_fail_number_of_pks_not_equal_to_total_number_of_nodes() {
        let mut bls_pk_vec: Vec<&[u8; BLS_PUBLIC_KEY_LEN]> = Vec::new();
        let key_1: [u8; BLS_PUBLIC_KEY_LEN] = [1; BLS_PUBLIC_KEY_LEN];
        let key_2: [u8; BLS_PUBLIC_KEY_LEN] = [2; BLS_PUBLIC_KEY_LEN];
        bls_pk_vec.push(&key_1);
        bls_pk_vec.push(&key_2);
        let mut node_info = vec![0, 1, 0, 0, 0, 99];
        let err = aggregate_public_keys_based_on_nodes_info(&bls_pk_vec, &node_info).err();
        println!("{}",err.unwrap().to_string());
        //assert!(err.is_some());
    }

    #[test]
    fn test_aggregate_public_keys_based_on_nodes_fail_strange_public_keys() {
        let mut bls_pk_vec: Vec<&[u8; BLS_PUBLIC_KEY_LEN]> = Vec::new();
        let key_1: [u8; BLS_PUBLIC_KEY_LEN] = [1; BLS_PUBLIC_KEY_LEN];
        let key_2: [u8; BLS_PUBLIC_KEY_LEN] = [2; BLS_PUBLIC_KEY_LEN];
        bls_pk_vec.push(&key_1);
        bls_pk_vec.push(&key_2);
        let mut node_info = vec![0, 2, 0, 0, 0, 99];
        let err = aggregate_public_keys_based_on_nodes_info(&bls_pk_vec, &node_info).err();
       // println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    /** aggregate_two_bls_signatures **/

    fn create_bls_sig() -> Vec<u8> {
        let kp = BlsKeyPair::gen_bls_key_pair().unwrap();
        kp.print();
        let mut msg = generate_random_msg();
        BlsSignature::sign(&kp.sk_bytes, &msg, 0, 100).unwrap()
    }

    #[test]
    fn test_aggregate_two_bls_signatures_fail_sig_bytes_len_too_small() {
        let bls_sig_bytes = create_bls_sig();
        let mut vec= Vec::new();
        for n in 0..BLS_SIG_LEN + 6 {
            let err1 = aggregate_two_bls_signatures(&bls_sig_bytes, &vec).err();
            assert!(err1.is_some());
           // println!("{}",err1.unwrap().to_string());
            let err2 = aggregate_two_bls_signatures(&vec, &bls_sig_bytes).err();
            assert!(err2.is_some());
            //println!("{}",err2.unwrap().to_string());
            vec.push(100);
        }
    }

    #[test]
    fn test_aggregate_two_bls_signatures_fail_node_info_incorrect_len() {
        let bls_sig_bytes = create_bls_sig();
        let mut vec = vec![0; BLS_SIG_LEN];
        let mut node_info_vec: Vec<u8> = vec![0, 100, 0, 99, 0, 100, 3];
        vec.append(&mut node_info_vec);
        let err1 = aggregate_two_bls_signatures(&bls_sig_bytes, &vec).err();
        assert!(err1.is_some());
        let err2 = aggregate_two_bls_signatures(&vec, &bls_sig_bytes).err();
        assert!(err2.is_some());
    }

    #[test]
    fn test_aggregate_two_bls_signatures_fail_zero_total_number_of_nodes() {
        let bls_sig_bytes = create_bls_sig();
        let mut vec = vec![0; BLS_SIG_LEN];
        let mut node_info_vec: Vec<u8> = vec![0, 0, 0, 99, 0, 100];
        vec.append(&mut node_info_vec);
        let err1 = aggregate_two_bls_signatures(&bls_sig_bytes, &vec).err();
        assert!(err1.is_some());
        let err2 = aggregate_two_bls_signatures(&vec, &bls_sig_bytes).err();
        assert!(err2.is_some());
        //println!("{}",err2.unwrap().to_string());
    }

    #[test]
    fn test_aggregate_two_bls_signatures_fail_index_bigger_than_total_num_of_nodes() {
        let bls_sig_bytes = create_bls_sig();
        let mut vec = vec![0; BLS_SIG_LEN];
        let mut node_info_vec: Vec<u8> = vec![0, 100, 0, 100, 0, 99];
        vec.append(&mut node_info_vec);
        let err1 = aggregate_two_bls_signatures(&bls_sig_bytes, &vec).err();
        assert!(err1.is_some());
        let err2 = aggregate_two_bls_signatures(&vec, &bls_sig_bytes).err();
        assert!(err2.is_some());
    }

    #[test]
    fn test_aggregate_two_bls_signatures_fail_zero_number_of_occurrences() {
        let bls_sig_bytes = create_bls_sig();
        let mut vec = vec![0; BLS_SIG_LEN];
        let mut node_info_vec: Vec<u8> = vec![0, 100, 0, 99, 0, 0];
        vec.append(&mut node_info_vec);
        let err1 = aggregate_two_bls_signatures(&bls_sig_bytes, &vec).err();
        assert!(err1.is_some());
        let err2 = aggregate_two_bls_signatures(&vec, &bls_sig_bytes).err();
        assert!(err2.is_some());
      //  println!("{}",err2.unwrap().to_string());
    }

    #[test]
    fn test_aggregate_two_bls_signatures_fail_total_number_of_nodes_not_the_same() {
        let mut vec_1 = vec![1; BLS_SIG_LEN];
        let mut node_info_vec_1: Vec<u8> = vec![0, 103, 0, 99, 0, 1];
        vec_1.append(&mut node_info_vec_1);
        let mut vec_2 = vec![2; BLS_SIG_LEN];
        let mut node_info_vec_2: Vec<u8> = vec![0, 100, 0, 98, 0, 1];
        vec_2.append(&mut node_info_vec_2);
        let err = aggregate_two_bls_signatures(&vec_1, &vec_2).err();
        assert!(err.is_some());
        //println!("{}",err.unwrap().to_string());
    }

    #[test]
    fn test_aggregate_two_bls_signatures_fail_strange_sigs() {
        let mut vec_1 = vec![1; BLS_SIG_LEN];
        let mut node_info_vec_1: Vec<u8> = vec![0, 100, 0, 99, 0, 1];
        vec_1.append(&mut node_info_vec_1);
        let mut vec_2 = vec![2; BLS_SIG_LEN];
        let mut node_info_vec_2: Vec<u8> = vec![0, 100, 0, 98, 0, 1];
        vec_2.append(&mut node_info_vec_2);
        let err = aggregate_two_bls_signatures(&vec_1, &vec_2).err();
        assert!(err.is_some());
        //println!("{}",err.unwrap().to_string());
    }


    /** aggregate_bls_signatures **/

    #[test]
    fn test_aggregate_bls_signatures_fail_empty_input() {
        let mut vec= Vec::new();
        let err = aggregate_bls_signatures(&vec).err();
        assert!(err.is_some());
     //   println!("{}",err.unwrap().to_string());
    }

    #[test]
    fn test_aggregate_bls_signatures_fail_sig_bytes_len_too_small() {
        let bls_sig_bytes = create_bls_sig();
        let mut vec= Vec::new();
        for n in 0..BLS_SIG_LEN + 6 {
            let mut input = vec![&bls_sig_bytes, &vec];
            let err = aggregate_bls_signatures(&input).err();
            assert!(err.is_some());
            //println!("{}",err.unwrap().to_string());
            vec.push(100);
        }
    }

    #[test]
    fn test_aggregate_bls_signatures_fail_node_info_incorrect_len() {
        let bls_sig_bytes = create_bls_sig();
        let mut vec = vec![0; BLS_SIG_LEN];
        let mut node_info_vec: Vec<u8> = vec![0, 100, 0, 99, 0, 100, 3];
        vec.append(&mut node_info_vec);
        let mut input = vec![&bls_sig_bytes, &vec];
        let err = aggregate_bls_signatures(&input).err();
        //println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_aggregate_bls_signatures_fail_zero_total_number_of_nodes() {
        let bls_sig_bytes = create_bls_sig();
        let mut vec = vec![0; BLS_SIG_LEN];
        let mut node_info_vec: Vec<u8> = vec![0, 0, 0, 99, 0, 100];
        vec.append(&mut node_info_vec);
        let mut input = vec![&bls_sig_bytes, &vec];
        let err = aggregate_bls_signatures(&input).err();
        assert!(err.is_some());
       // println!("{}",err.unwrap().to_string());
    }

    #[test]
    fn test_aggregate_bls_signatures_fail_index_bigger_than_total_num_of_nodes() {
        let bls_sig_bytes = create_bls_sig();
        let mut vec = vec![0; BLS_SIG_LEN];
        let mut node_info_vec: Vec<u8> = vec![0, 100, 0, 100, 0, 99];
        vec.append(&mut node_info_vec);
        let mut input = vec![&bls_sig_bytes, &vec];
        let err = aggregate_bls_signatures(&input).err();
        assert!(err.is_some());
    }

    #[test]
    fn test_aggregate_bls_signatures_fail_zero_number_of_occurrences() {
        let bls_sig_bytes = create_bls_sig();
        let mut vec = vec![0; BLS_SIG_LEN];
        let mut node_info_vec: Vec<u8> = vec![0, 100, 0, 99, 0, 0];
        vec.append(&mut node_info_vec);
        let mut input = vec![&bls_sig_bytes, &vec];
        let err = aggregate_bls_signatures(&input).err();
        assert!(err.is_some());
    }

    #[test]
    fn test_aggregate_bls_signatures_fail_total_number_of_nodes_not_the_same() {
        let mut vec_1 = vec![1; BLS_SIG_LEN];
        let mut node_info_vec_1: Vec<u8> = vec![0, 103, 0, 99, 0, 1];
        vec_1.append(&mut node_info_vec_1);
        let mut vec_2 = vec![2; BLS_SIG_LEN];
        let mut node_info_vec_2: Vec<u8> = vec![0, 100, 0, 98, 0, 1];
        vec_2.append(&mut node_info_vec_2);
        let mut input = vec![&vec_1, &vec_2];
        let err = aggregate_bls_signatures(&input).err();
        assert!(err.is_some());
       // println!("{}",err.unwrap().to_string());
    }

    #[test]
    fn test_aggregate_bls_signatures_fail_strange_sigs() {
        let mut vec_1 = vec![1; BLS_SIG_LEN];
        let mut node_info_vec_1: Vec<u8> = vec![0, 100, 0, 99, 0, 1];
        vec_1.append(&mut node_info_vec_1);
        let mut vec_2 = vec![2; BLS_SIG_LEN];
        let mut node_info_vec_2: Vec<u8> = vec![0, 100, 0, 98, 0, 1];
        vec_2.append(&mut node_info_vec_2);
        let mut input = vec![&vec_1, &vec_2];
        let err = aggregate_bls_signatures(&input).err();
        assert!(err.is_some());
        //println!("{}",err.unwrap().to_string());
    }

    #[test]
    fn test_aggregate_bls_signatures_fail_one_sig_not_enough() {
        let bls_sig_bytes = create_bls_sig();
        let mut vec= Vec::new();
        vec.push(&bls_sig_bytes);
        let err = aggregate_bls_signatures(&vec).err();
        assert!(err.is_some());
        //println!("{}",err.unwrap().to_string());
    }

    /** other tests of correctness for aggregation and verification **/



    #[test]
    fn test_create_agg_sig_verify() {
        let total = 3;
        let ind_1 = 0;
        let ind_2 = 2;
        let kp_1 = BlsKeyPair::gen_bls_key_pair().unwrap();
        kp_1.print();
        let kp_2 = BlsKeyPair::gen_bls_key_pair().unwrap();
        kp_2.print();
        let mut msg = generate_random_msg();
        let agg_sig_1_bytes = BlsSignature::sign(&kp_1.sk_bytes, &msg, ind_1, total).unwrap();
        let agg_sig_2_bytes = BlsSignature::sign(&kp_2.sk_bytes, &msg, ind_2, total).unwrap();

        let agg_sig_1 = BlsSignature::deserialize(&agg_sig_1_bytes).unwrap();
        let agg_sig_2 = BlsSignature::deserialize(&agg_sig_2_bytes).unwrap();

        assert_eq!(agg_sig_1.nodes_info.total_num_of_nodes, total);
        assert_eq!(agg_sig_1.nodes_info.map.len(), 1);
        assert_eq!(agg_sig_1.nodes_info.map.contains_key(&ind_1), true);
        match agg_sig_1.nodes_info.map.get(&ind_1) {
            Some(number_of_occurrence) => assert_eq!(*number_of_occurrence, 1),
            None => panic!("Node index not found"),
        }
        assert_eq!(agg_sig_2.nodes_info.total_num_of_nodes, total);
        assert_eq!(agg_sig_2.nodes_info.map.len(), 1);
        assert_eq!(agg_sig_2.nodes_info.map.contains_key(&ind_2), true);
        match agg_sig_2.nodes_info.map.get(&ind_2) {
            Some(number_of_occurrence) => assert_eq!(*number_of_occurrence, 1),
            None => panic!("Node index not found"),
        }

        let agg_sig_1_2_bytes = aggregate_two_bls_signatures(&agg_sig_1_bytes, &agg_sig_2_bytes).unwrap();
        let agg_sig_1_2 = BlsSignature::deserialize(&agg_sig_1_2_bytes).unwrap();
        agg_sig_1_2.print();

        let mut apks = Vec::new();
        apks.push(&kp_1.pk_bytes);
        apks.push(&kp_2.pk_bytes);

        let apk_1_2 = aggregate_public_keys(&apks).unwrap();

        let res = BlsSignature::verify(&agg_sig_1_2_bytes, &apk_1_2, &msg).unwrap();
        println!("res = {}", res);
        assert_eq!(res, true);
    }

    #[test]
    fn test_bls() {
        let mut msg = generate_random_msg();

        let total_num_of_nodes = 10;
        let indexes: Vec<u16> = gen_signer_indexes(total_num_of_nodes, 20);

        println!("Indexes = {:?}", indexes);

        let mut bls_sig_from_nodes: Vec<Vec<u8>> = Vec::new();
        let mut pk_from_nodes: Vec<[u8; BLS_PUBLIC_KEY_LEN]> = Vec::new();
        let mut sk_from_nodes: Vec<[u8; BLS_SECRET_KEY_LEN]> = Vec::new();

        for i in 0..total_num_of_nodes {
            println!("Key pair # {}", i);
            let kp = BlsKeyPair::gen_bls_key_pair().unwrap();
            kp.print();
            pk_from_nodes.push(kp.pk_bytes);
            sk_from_nodes.push(kp.sk_bytes);
            println!();
        }

        println!();
        println!("Signatures from nodes:");
        println!();

        for ind in &indexes {
            println!("Node index = {}", ind);
            let nodes_info = NodesInfo::create_node_info(total_num_of_nodes, *ind).unwrap();
            nodes_info.print();
            let sig = BlsSignature::sign(&sk_from_nodes[*ind as usize], &msg, *ind, total_num_of_nodes).unwrap();
            println!("sig = {:?}", &sig);
            println!("sig len = {}", &sig.len());
            bls_sig_from_nodes.push(sig);
        }

        let bls_sig_from_nodes_refs: Vec<&Vec<u8>> = bls_sig_from_nodes.iter().map(|sig| sig).collect();
        let pk_from_nodes_refs: Vec<&[u8; BLS_PUBLIC_KEY_LEN]> = pk_from_nodes.iter().map(|pk| pk).collect();

        let res_sig = aggregate_bls_signatures(&bls_sig_from_nodes_refs).unwrap();

        println!();
        println!("Aggregated Signature:");
        println!();

        println!("aggregated sig = {:?}", &res_sig);
        println!("aggregated sig len = {}", &res_sig.len());

        println!();
        println!("Deserialized Aggregated Signature:");
        println!();

        let agg_sig = BlsSignature::deserialize(&res_sig).unwrap();
        agg_sig.nodes_info.print();

        println!("aggregated sig bytes = {:?}", agg_sig.sig_bytes);
        println!("aggregated sig bytes len = {}", &agg_sig.sig_bytes.len());

        let len = agg_sig.nodes_info.map.keys().len();

        println!("len = {}", len);

        let res_pk = aggregate_public_keys_based_on_nodes_info(&pk_from_nodes_refs, &agg_sig.nodes_info.serialize()).unwrap();

        println!();
        println!("Aggregated public key:");
        println!();

        println!("aggregated pk = {:?}", &res_pk);
        println!("aggregated pk len = {}", &res_pk.len());

        let res = BlsSignature::verify(&res_sig, &res_pk, &msg).unwrap();

        println!("res = {}", res);
        assert_eq!(res, true);
    }

}

