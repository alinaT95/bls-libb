# ton-bls-lib

This library is developed to handle BLS signature for TON blockchain. It is responsible for generation BLS keys and provides basic signing/verification functionality. Also it provides aggregation functionality for public keys and signatures. 
Basic BLS functionality is provided by [blst](https://github.com/supranational/blst) library. _ton-bls-lib_ exploits it and adds additional infrastracture and extra data parsing.

Raw BLS signature is a byte array of length 96 (or 48) bytes. Each BLS signature is produced initially by some node with unique index _node_index_. Also there is some fixed number of nodes for current validation session. Node concatenates BLS signature with _node_index_ and _total_number_of_nodes_. So it looks as follows.

<p align="center">
<img src="../master/bls_diag.jpg" width="600">
</p>

We need to add information about node indexes because in the end we (masterchain validator) should be able to compose appropriate aggregated BLS public key for verification of obtained (from workchain) BLS signature
  
So this wrapped BLS signature is broadcasted and aggregated with other BLS signatures for the same block candidate hash.
  
We need extra field for number of occurrences because we gonna use decentralized algorithm for BLS signatures broadcast and aggregation. So we may get the following situation. 
  
<p align="center">
<img src="../master/decentral.jpg" width="600">
</p>
  
When we will calculate aggregated public key to verify the final signature we should take into account how many times each node took part. So the final aggregated signature will look like this.
  
<p align="center">
<img src="../master/bls_diag_4.jpg" width="800">
</p>

When masterchain validator gets such aggregated BLS signature in broadcast protection message, he will parse it. He will take respective BLS public keys based on indexes in wrapped BLS signature. It will take into account the number of repetitions for each public key and compute the appropriate aggregation of public keys. Then it will verify the signature.

## API description

Below there are constants and functions that are provided by _ton-bls-lib_.

```rust
pub const BLS_SECRET_KEY_LEN: usize = 32;
pub const BLS_PUBLIC_KEY_LEN_FOR_MIN_PK_MODE: usize = 48;
pub const BLS_PUBLIC_KEY_LEN_FOR_MIN_SIG_MODE: usize = 96;
pub const BLS_PUBLIC_KEY_LEN: usize = BLS_PUBLIC_KEY_LEN_FOR_MIN_PK_MODE;
pub const BLS_KEY_MATERIAL_LEN: usize = 32;
pub const BLS_SIG_LEN_FOR_MIN_PK_MODE: usize = 96;
pub const BLS_SIG_LEN_FOR_MIN_SIG_MODE: usize = 48;
pub const BLS_SIG_LEN: usize = BLS_SIG_LEN_FOR_MIN_PK_MODE;
pub const BLS_SEED_LEN: usize = 32;
```
- **gen_bls_key_pair_based_on_key_material**  
  
  ```rust 
  pub fn gen_bls_key_pair_based_on_key_material(ikm: &[u8; BLS_KEY_MATERIAL_LEN]) -> Result<([u8; BLS_PUBLIC_KEY_LEN], [u8; BLS_SECRET_KEY_LEN])> 
  ```
  Generate random BLS key pair based on key material array. Key material is not equal to future secret key in the end.

- **gen_bls_key_pair**  

  ```rust 
  pub fn gen_bls_key_pair() -> Result<([u8; BLS_PUBLIC_KEY_LEN], [u8; BLS_SECRET_KEY_LEN])>
  ```
  Generate random BLS key pair.
    
- **gen_public_key_based_on_secret_key**
  
   ```rust 
  pub fn gen_public_key_based_on_secret_key(sk: &[u8; BLS_SECRET_KEY_LEN]) -> Result<([u8; BLS_PUBLIC_KEY_LEN])>)>
  ```
  
  Generate public key using bytes of secret key.
  
- **sign** 

  ```rust 
  pub fn sign(sk_bytes: &[u8; BLS_SECRET_KEY_LEN], msg: &Vec<u8>) -> Result<[u8; BLS_SIG_LEN]>
  ```
  
  Compute raw 96/48-bytes BLS signature.

- **verify**

  ```rust 
  pub fn verify(sig_bytes: &[u8; BLS_SIG_LEN], msg: &Vec<u8>, pk_bytes: &[u8; BLS_PUBLIC_KEY_LEN]) -> Result<bool>
  ```
  
  Verify raw BLS signature.
  
- **add_node_info_to_sig**
  
  ```rust 
  pub fn add_node_info_to_sig(sig_bytes: [u8; BLS_SIG_LEN], node_index: u16, total_num_of_nodes: u16) -> Result<Vec<u8>>
  ```
  
  Concatenate raw BLS signature bytes with node index and total number of nodes.
  
- **sign_and_add_node_info**
  
  ```rust 
    pub fn sign_and_add_node_info(sk_bytes: &[u8; BLS_SECRET_KEY_LEN], msg: &Vec<u8>, node_index: u16, total_num_of_nodes: u16) -> Result<Vec<u8>>
  ```
  
  Create raw BLS signature and concatenate it with node index and total number of nodes.
  
- **truncate_nodes_info_from_sig**

  ```rust 
    pub fn truncate_nodes_info_from_sig(sig_bytes_with_nodes_info: &Vec<u8>) -> Result<[u8; BLS_SIG_LEN]>
  ```
  
  Truncare raw BLS signature bytes from wrapped signature.
  
- **get_nodes_info_from_sig**
  
  ```rust 
    pub fn get_nodes_info_from_sig(sig_bytes_with_nodes_info: &Vec<u8>) -> Result<Vec<u8>>
  ```
  Truncate info about nodes (indexes, number of occurrences, total number of nodes) from wrapped BLS signature.
  
- **truncate_nodes_info_and_verify**

  ```rust 
    pub fn truncate_nodes_info_and_verify(sig_bytes_with_nodes_info: &Vec<u8>, pk_bytes: &[u8; BLS_PUBLIC_KEY_LEN], msg: &Vec<u8>) ->Result<bool>
  ```

  Truncate info about nodes (indexes, number of occurrences, total number of nodes) from wrapped BLS signature and then verify raw signature.

- **aggregate_public_keys**

  ```rust 
    pub fn aggregate_public_keys(bls_pks_bytes: &Vec<&[u8; BLS_PUBLIC_KEY_LEN]>) -> Result<[u8; BLS_PUBLIC_KEY_LEN]>
  ```
  
  Aggregate all public keys taken from vector.

- **aggregate_public_keys_based_on_nodes_info**

  ```rust 
    pub fn aggregate_public_keys_based_on_nodes_info(bls_pks_bytes: &Vec<&[u8; BLS_PUBLIC_KEY_LEN]>, nodes_info_bytes: &Vec<u8>) -> Result<[u8; BLS_PUBLIC_KEY_LEN]> 
  ```
  
  Aggregate public keys based on nodes_info map containing indexes of nodes. Here node_info_bytes has the same structure as described before: first 2 bytes contains total number of nodes and then array of pairs [index (2 bytes), number of occurrences (2 bytes)].

- **aggregate_two_bls_signatures**

  ```rust 
    pub fn aggregate_two_bls_signatures(bls_sig_1_bytes: &Vec<u8>, bls_sig_2_bytes: &Vec<u8>) -> Result<Vec<u8>> 
  ```
  
  Aggregate two BLS signatures and merge their node info.
  
- **aggregate_bls_signatures**

  ```rust 
    pub fn aggregate_bls_signatures(bls_sigs_bytes: &Vec<&Vec<u8>>) -> Result<Vec<u8>> 
  ```
  
  Aggregate multiple BLS signatures and merge their node info.
