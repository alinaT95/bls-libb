use std::collections::HashMap;
use super::random_helper::*;
use ton_types::{fail, Result};
use std::time::{Instant, Duration};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NodesInfo {
    pub map: HashMap<u16, u16>,
    pub total_num_of_nodes: u16,
}

impl NodesInfo {
    pub fn create_node_info(total_num_of_nodes: u16, node_index: u16) -> Result<Self> {
        if total_num_of_nodes == 0 {
            fail!("Total number of nodes can not be zero!");
        }
        if node_index >= total_num_of_nodes {
            fail!("Index of node can not be greater than total number of nodes!");
        }
        let mut info = HashMap::new();
        let num_of_occurrences = 1;
        info.insert(node_index, num_of_occurrences);
        Ok(Self {
            map: info,
            total_num_of_nodes,
        })
    }

    pub fn with_data(info: HashMap<u16, u16>, total_num_of_nodes: u16) -> Result<Self> {
        if total_num_of_nodes == 0 {
            fail!("Total number of nodes can not be zero!");
        }
        if info.len() == 0 {
            fail!("Node info should not be empty!")
        }
        for (index, number_of_occurrence) in &info {
            if *index >= total_num_of_nodes {
                fail!("Index of node can not be greater than total number of nodes!")
            }
            if *number_of_occurrence == 0 {
                fail!("Number of occurrence for node can not be zero!")
            }
        }
        let nodes_info = NodesInfo {
            map: info,
            total_num_of_nodes,
        };
        Ok(nodes_info)
    }

    pub fn print(&self) {
        println!("--------------------------------------------------");
        println!("Total number of nodes: {}", &self.total_num_of_nodes);
        println!("Indexes -- occurrences: ");
        for (index, number_of_occurrence) in &self.map {
            println!("{}: \"{}\"", index, number_of_occurrence);
        }
        println!("--------------------------------------------------");
        println!("--------------------------------------------------");
    }

    pub fn merge(info1: &NodesInfo, info2: &NodesInfo) -> Result<NodesInfo> {
        if info1.total_num_of_nodes != info2.total_num_of_nodes {
            fail!("Total number of nodes must be the same!");
        }
        let mut new_info = info1.map.clone();
        for (index, number_of_occurrence) in &info2.map {
            new_info.insert(
                *index,
                if new_info.contains_key(&index) {
                    new_info[index] + *number_of_occurrence
                   } else {
                    *number_of_occurrence
                   },
            );
        }
        Ok(NodesInfo {
            map: new_info,
            total_num_of_nodes: info1.total_num_of_nodes,
        })
    }

    pub fn merge_multiple(info_vec: &Vec<&NodesInfo>) -> Result<NodesInfo> {
        if info_vec.len() <= 1 {
            fail!("Nodes info collection must have at least two elements!!")
        }
        let mut final_nodes_info = NodesInfo::merge(&info_vec[0], &info_vec[1])?;
        for i in 2..info_vec.len() {
            final_nodes_info = NodesInfo::merge(&final_nodes_info, &info_vec[i])?;
        }
        Ok(final_nodes_info)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result_vec = Vec::new();
        let total_num_of_nodes = &self.total_num_of_nodes;
        let total_num_of_nodes_bytes = total_num_of_nodes.to_be_bytes();
        result_vec.extend_from_slice(&total_num_of_nodes_bytes);
        for (index, number_of_occurrence) in &self.map {
            let index_bytes = index.to_be_bytes();
            result_vec.extend_from_slice(&index_bytes);
            let number_of_occurrence_bytes = number_of_occurrence.to_be_bytes();
            result_vec.extend_from_slice(&number_of_occurrence_bytes);
        }
        result_vec
    }

    pub fn deserialize(info_bytes: &Vec<u8>) -> Result<NodesInfo> {
        if info_bytes.len() <= 2 || (info_bytes.len() % 4) != 2 {
            fail!("node_info_bytes must have non zero length (> 2) being of form 4*k+2!");
        }
        let total_num_of_nodes = ((info_bytes[0] as u16) << 8) | info_bytes[1] as u16;
        if total_num_of_nodes == 0 {
            fail!("Total number of nodes can not be zero!");
        }
        let mut new_info = HashMap::new();
        for i in (2..info_bytes.len()).step_by(4) {
            let index = ((info_bytes[i] as u16) << 8) | info_bytes[i + 1] as u16;
            if index >= total_num_of_nodes {
                fail!("Index can not be greater than total_num_of_nodes!");
            }
            let number_of_occurrence = ((info_bytes[i + 2] as u16) << 8) | info_bytes[i + 3] as u16;
            new_info.insert(index, number_of_occurrence);
        }

        NodesInfo::with_data(new_info, total_num_of_nodes)
    }
}

#[cfg(test)]
mod tests_nodes_info {
    use super::*;

    /** with_data **/

    #[test]
    fn test_with_data_fail_empty_map() {
        let total_num_of_nodes = 100;
        let mut new_info = HashMap::new();
        let err = NodesInfo::with_data(new_info, total_num_of_nodes).err();
        assert!(err.is_some());
    }

    #[test]
    fn test_with_data_fail_zero_number_of_occurrences() {
        let total_num_of_nodes = 100;
        let mut new_info = HashMap::from([(9, 0)]);
        let err = NodesInfo::with_data(new_info, total_num_of_nodes).err();
        assert!(err.is_some());
    }

    #[test]
    fn test_with_data_fail_zero_total_num_of_nodes() {
        let total_num_of_nodes = 0;
        let mut new_info = HashMap::from([(9, 1)]);
        let err = NodesInfo::with_data(new_info, total_num_of_nodes).err();
        assert!(err.is_some());
    }

    #[test]
    fn test_with_data_fail_node_index_bigger_than_total_num_of_nodes() {
        let total_num_of_nodes = 80;
        let mut new_info = HashMap::from([(80, 1)]);
        let err = NodesInfo::with_data(new_info, total_num_of_nodes).err();
        assert!(err.is_some());
    }

    #[test]
    fn test_with_data() {
        let total_num_of_nodes = 80;
        let mut new_info = HashMap::from([(0, 1), (6, 2), (79, 3)]);
        let mut new_info_clone = new_info.clone();
        let nodes_info = NodesInfo::with_data(new_info, total_num_of_nodes).unwrap();
        assert_eq!(nodes_info.total_num_of_nodes, total_num_of_nodes);
        assert_eq!(&nodes_info.map, &new_info_clone);
    }

    /** create_node_info **/

    #[test]
    fn test_create_node_info_fail_zero_total_num_of_nodes() {
        let total_num_of_nodes = 0;
        let node_index = 3;
        let err = NodesInfo::create_node_info(total_num_of_nodes, node_index).err();
        assert!(err.is_some());
    }

    #[test]
    fn test_create_node_info_fail_node_index_bigger_than_total_num_of_nodes() {
        let total_num_of_nodes = 100;
        let node_index = 100;
        let err = NodesInfo::create_node_info(total_num_of_nodes, node_index).err();
        assert!(err.is_some());
    }

    #[test]
    fn test_create_node() {
        let total_num_of_nodes = 100;
        let node_index = 3;
        let nodes_info = NodesInfo::create_node_info(total_num_of_nodes, node_index).unwrap();
        assert_eq!(nodes_info.total_num_of_nodes, total_num_of_nodes);
        assert_eq!(nodes_info.map.len(), 1);
        assert_eq!(nodes_info.map.contains_key(&node_index), true);
        match nodes_info.map.get(&node_index) {
            Some(number_of_occurence) => assert_eq!(*number_of_occurence, 1),
            None => panic!("Node index not found"),
        }
    }

    /** merge **/

    #[test]
    fn test_merge() {
        let total_num_of_nodes = 100;
        let node_index = 3;
        let nodes_info_1 = NodesInfo::create_node_info(total_num_of_nodes, node_index).unwrap();
        let nodes_info_2 = nodes_info_1.clone();
        let new_nodes_info = NodesInfo::merge(&nodes_info_1, &nodes_info_2).unwrap();
        new_nodes_info.print();
        assert_eq!(new_nodes_info.map.len(), 1);
        match new_nodes_info.map.get(&node_index) {
            Some(number_of_occurrence) => assert_eq!(*number_of_occurrence, 2),
            None => panic!("Node index not found"),
        }
        assert_eq!(new_nodes_info.total_num_of_nodes, total_num_of_nodes);
    }

    #[test]
    fn test_merge_extended() {
        let total_num_of_nodes = 80;
        let mut info_1 = HashMap::from([(0, 1), (6, 2), (79, 3)]);
        let mut info_2 = HashMap::from([(0, 2), (2, 8), (45, 6), (79, 9)]);
        let mut info = HashMap::from([(0, 3), (2, 8), (6, 2), (45, 6), (79, 12)]);

        let nodes_info_1 = NodesInfo::with_data(info_1, total_num_of_nodes).unwrap();
        let nodes_info_2 = NodesInfo::with_data(info_2, total_num_of_nodes).unwrap();

        let new_nodes_info = NodesInfo::merge(&nodes_info_1, &nodes_info_2).unwrap();
        new_nodes_info.print();

        assert_eq!(new_nodes_info.map.len(), 5);
        assert_eq!(&new_nodes_info.map, &info);
        assert_eq!(new_nodes_info.total_num_of_nodes, total_num_of_nodes);
    }

    #[test]
    fn test_merge_fail_total_num_of_nodes_not_the_same() {
        let total_num_of_nodes_1 = 80; let total_num_of_nodes_2 = 81;
        let mut info_1 = HashMap::from([(0, 1), (6, 2), (79, 3)]);
        let mut info_2 = HashMap::from([(0, 2), (2, 8), (45, 6), (79, 9)]);
        let nodes_info_1 = NodesInfo::with_data(info_1, total_num_of_nodes_1).unwrap();
        let nodes_info_2 = NodesInfo::with_data(info_2, total_num_of_nodes_2).unwrap();
        let err = NodesInfo::merge(&nodes_info_1, &nodes_info_2).err();
        assert!(err.is_some());
    }

    /** merge_multiple **/

    #[test]
    fn test_merge_multiple_fail_vector_of_nodes_info_is_empty() {
        let mut nodes_info_vec = Vec::new();
        let err = NodesInfo::merge_multiple(&nodes_info_vec).err();
        assert!(err.is_some());
    }

    #[test]
    fn test_merge_multiple_fail_vector_of_nodes_info_is_too_small() {
        let total_num_of_nodes = 100;
        let node_index_1 = 71;
        let nodes_info_1 = NodesInfo::create_node_info(total_num_of_nodes, node_index_1).unwrap();
        let mut nodes_info_vec = Vec::new();
        nodes_info_vec.push(&nodes_info_1);
        let err = NodesInfo::merge_multiple(&nodes_info_vec).err();
        assert!(err.is_some());
    }

    #[test]
    fn test_merge_multiple_fail_total_num_of_nodes_not_the_same() {
        let total_num_of_nodes_1 = 80; let total_num_of_nodes_2 = 80; let total_num_of_nodes_3 = 81;
        let mut info_1 = HashMap::from([(0, 1), (6, 2), (79, 3)]);
        let mut info_2 = HashMap::from([(0, 2), (2, 8), (45, 6), (79, 9)]);
        let mut info_3 = HashMap::from([(0, 2), (2, 8), (45, 6), (78, 9)]);
        let nodes_info_1 = NodesInfo::with_data(info_1, total_num_of_nodes_1).unwrap();
        let nodes_info_2 = NodesInfo::with_data(info_2, total_num_of_nodes_2).unwrap();
        let nodes_info_3 = NodesInfo::with_data(info_3, total_num_of_nodes_3).unwrap();
        let mut nodes_info_vec = vec![&nodes_info_1, &nodes_info_2, &nodes_info_3];
        let err = NodesInfo::merge_multiple(&nodes_info_vec).err();
        assert!(err.is_some());
    }

    #[test]
    fn test_merge_multiple() {
        let total_num_of_nodes = 100;
        let node_index_1 = 71;
        let node_index_2 = 3;
        let node_index_3 = 3;
        let node_index_4 = 99;
        let node_index_5 = 99;
        let node_index_6 = 99;
        let node_index_7 = 90;
        let nodes_info_1 = NodesInfo::create_node_info(total_num_of_nodes, node_index_1).unwrap();
        let nodes_info_2 = NodesInfo::create_node_info(total_num_of_nodes, node_index_2).unwrap();
        let nodes_info_3 = NodesInfo::create_node_info(total_num_of_nodes, node_index_3).unwrap();
        let nodes_info_4 = NodesInfo::create_node_info(total_num_of_nodes, node_index_4).unwrap();
        let nodes_info_5 = NodesInfo::create_node_info(total_num_of_nodes, node_index_5).unwrap();
        let nodes_info_6 = NodesInfo::create_node_info(total_num_of_nodes, node_index_6).unwrap();
        let nodes_info_7 = NodesInfo::create_node_info(total_num_of_nodes, node_index_7).unwrap();

        let mut info = HashMap::from([(3, 2), (71, 1), (90, 1), (99, 3)]);

        let mut nodes_info_vec = vec![&nodes_info_1, &nodes_info_2, &nodes_info_3, &nodes_info_4, &nodes_info_5, &nodes_info_6, &nodes_info_7];
        let new_nodes_info = NodesInfo::merge_multiple(&nodes_info_vec).unwrap();
        new_nodes_info.print();

        assert_eq!(new_nodes_info.map.len(), 4);
        assert_eq!(&new_nodes_info.map, &info);
        assert_eq!(new_nodes_info.total_num_of_nodes, total_num_of_nodes);
    }

    #[test]
    fn test_is_equal() {
        let total_num_of_nodes = 100;
        let node_index_1 = 3;
        let node_index_2 = 9;
        let nodes_info_1 = NodesInfo::create_node_info(total_num_of_nodes, node_index_1).unwrap();
        let nodes_info_2 = NodesInfo::create_node_info(total_num_of_nodes, node_index_2).unwrap();
        assert_eq!(nodes_info_1 == nodes_info_2, false);

        let mut new_info = HashMap::from([(9, 1), (10, 4)]);
        let nodes_info_3 = NodesInfo::with_data(new_info, total_num_of_nodes).unwrap();
        let mut new_info_2 = HashMap::from([(9, 2), (10, 4)]);
        let nodes_info_4 = NodesInfo::with_data(new_info_2, total_num_of_nodes).unwrap();
        assert_eq!(nodes_info_3 == nodes_info_4, false);

        let mut new_info_3 = HashMap::from([(9, 2), (10, 4)]);
        let nodes_info_3 = NodesInfo::with_data(new_info_3, total_num_of_nodes).unwrap();
        let mut new_info_4 = HashMap::from([(9, 2), (10, 4)]);
        let nodes_info_4 = NodesInfo::with_data(new_info_4, total_num_of_nodes).unwrap();
        assert_eq!(nodes_info_3 == nodes_info_4, true);
    }

    /** serialize/deserialize **/

    #[test]
    fn test_serialize_vec_len() {
        let total_num_of_nodes = 100;
        let mut new_info = HashMap::from([(9, 1), (10, 4)]);
        let nodes_info = NodesInfo::with_data(new_info, total_num_of_nodes).unwrap();
        let vec = nodes_info.serialize();
        assert_eq!(vec.len(), 10);
    }

    #[test]
    fn test_serialize_deserialize() {
        let total_num_of_nodes = 100;
        let mut new_info = HashMap::from([(77, 2222), (9, 3000), (10, 4)]);
        let nodes_info = NodesInfo::with_data(new_info, total_num_of_nodes).unwrap();
        nodes_info.print();
        let vec = nodes_info.serialize();
        let new_nodes_info = NodesInfo::deserialize(&vec).unwrap();
        new_nodes_info.print();
        assert_eq!(nodes_info == new_nodes_info, true);
    }

    /** deserialize **/

    #[test]
    fn test_deserialize_fail_input_len_too_small() {
        let mut vec= Vec::new();
        for n in 0..6 {
            let err = NodesInfo::deserialize(&vec).err();
            assert!(err.is_some());
            vec.push(100);
        }
    }

    #[test]
    fn test_deserialize_fail_input_len_incorrect() {
        let mut vec = vec![0, 100, 0, 99, 0, 100, 3];
        let err = NodesInfo::deserialize(&vec).err();
        assert!(err.is_some());
    }

    #[test]
    fn test_deserialize_fail_zero_total_number_of_nodes() {
        let mut vec = vec![0, 0, 0, 99, 0, 100];
        let err = NodesInfo::deserialize(&vec).err();
         //println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_deserialize_fail_index_bigger_than_total_num_of_nodes() {
        let mut vec = vec![0, 100, 0, 100, 0, 99];
        let err = NodesInfo::deserialize(&vec).err();
        assert!(err.is_some());
    }

    #[test]
    fn test_deserialize_fail_zero_number_of_occurrences() {
        let mut vec = vec![0, 100, 0, 99, 0, 0];
        let err = NodesInfo::deserialize(&vec).err();
        //println!("{}",err.unwrap().to_string());
        assert!(err.is_some());
    }

    #[test]
    fn test_deserialize() {
        let mut vec = vec![0, 100, 0, 99, 0, 120, 0, 70, 1, 0];
        let new_nodes_info = NodesInfo::deserialize(&vec).unwrap();
        new_nodes_info.print();
        assert_eq!(new_nodes_info.total_num_of_nodes, 100);
        let mut new_info = HashMap::from([(99, 120), (70, 256)]);
        assert_eq!(new_info, new_nodes_info.map);
    }

    #[test]
    fn test_merge_timing() {
        let total_num_of_nodes = 10000;
        let indexes: Vec<u16> = gen_signer_indexes(total_num_of_nodes, 20000);
        let mut node_info_vec = Vec::new();
        for ind in &indexes {
            println!("Node index = {}", ind);
            let nodes_info = NodesInfo::create_node_info(total_num_of_nodes, *ind).unwrap();
            node_info_vec.push(nodes_info)

        }
        let node_info_vec_refs: Vec<&NodesInfo> = node_info_vec.iter().map(|info| info).collect();
        let now = Instant::now();
        let res = NodesInfo::merge_multiple(&node_info_vec_refs).unwrap();
        let duration = now.elapsed();
        println!("Time elapsed merge is: {:?}", duration);
        res.print();
    }
}

