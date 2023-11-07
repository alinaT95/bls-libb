use rand::SeedableRng;
use rand::Rng;
use rand::{RngCore};
use super::nodes_info::*;

pub fn generate_random_msg() -> Vec<u8> {
    let msg_len = rand::thread_rng().gen_range(2, 100);
  //  println!("Msg len = {}", msg_len);
    let mut msg = vec![0u8; msg_len as usize];
    rand::thread_rng().fill_bytes(&mut msg);
    //println!("Msg:");
   // println!("{:?}", msg);
    msg
}

pub fn generate_random_msg_of_fixed_len( msg_len: i32) -> Vec<u8> {
   // println!("Msg len = {}", msg_len);
    let mut msg = vec![0u8; msg_len as usize];
    rand::thread_rng().fill_bytes(&mut msg);
  //  println!("Msg:");
  //  println!("{:?}", msg);
    msg
}

pub fn gen_signer_indexes(n: u16, k: u16) -> Vec<u16> {
    let mut rng = rand::thread_rng();

    loop {
        let mut indexes = Vec::new();

        for i in 0..k {
            indexes.push(rng.gen_range(0, n));
        }

        if indexes.len() == (k as usize) {
            return indexes;
        }
    }
}

pub fn gen_random_index(n: u16) -> u16 {
    let mut rng = rand::thread_rng();
    rng.gen_range(0, n)
}

pub fn create_random_nodes_info(total_num_of_nodes: u16, attempts: u16) -> NodesInfo{
    let indexes: Vec<u16> =  gen_signer_indexes(total_num_of_nodes, attempts);
    let mut node_info_vec = Vec::new();
    for ind in &indexes {
        //println!("Node index = {}", ind);
        let nodes_info = NodesInfo::create_node_info(total_num_of_nodes, *ind).unwrap();
        node_info_vec.push(nodes_info)

    }
    let node_info_vec_refs: Vec<&NodesInfo> = node_info_vec.iter().map(|info| info).collect();
    let info = NodesInfo::merge_multiple(&node_info_vec_refs).unwrap();
    info
}