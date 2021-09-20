use blake3::Hash as Blake3Hash;
use bls12_381::{Bls12, Scalar};
use kzg::{KZGParams, KZGProver};
use std::cmp::{Ord, PartialEq, PartialOrd};
use std::{
    cell::RefCell,
    fmt,
    fmt::{Debug, Formatter},
    rc::Rc,
};
use bitvec::vec::BitVec;

mod error;
mod node;
mod proofs;

#[cfg(test)]
mod test_utils;

use error::BerkleError;
use node::{InternalNode, LeafNode, Node};
use proofs::{ContainsResult, GetResult, InnerNodeProof, MembershipProof, NonMembershipProof, RangePath, RangeProof, RangeResult};

use crate::proofs::DeleteResult;

/// this wrapper struct denotes a hash that lies in Bls12_381's Scalar Field
/// it is computed by chopping off the two most-significant bits of the hash
/// A field hash should not be constructed directly, only from a Blake3hash
// INVARIANT: LE interpretation of the bytes always < Bls12_281 modulus
#[derive(Debug, Copy, Clone, PartialEq)]
struct FieldHash([u8; 32]);

impl From<Blake3Hash> for FieldHash {
    fn from(inner: Blake3Hash) -> Self {
        let mut inner: [u8; 32] = inner.into();
        inner[31] &= 0x4F;
        FieldHash(inner)
    }
}

impl From<Scalar> for FieldHash {
    fn from(inner: Scalar) -> Self {
        let inner = inner.to_bytes();
        FieldHash(inner)
    }
}

impl Into<Scalar> for FieldHash {
    fn into(self) -> Scalar {
        // unwrap OK because invariant guarantees self to be < modulus
        Scalar::from_bytes(&self.0).unwrap()
    }
}

// assumes there will be no more than 255 duplicate keys in a single node
#[derive(Debug, Clone, Eq, PartialOrd, Ord)]
pub struct KeyWithCounter<const MAX_KEY_LEN: usize>([u8; MAX_KEY_LEN], usize);

impl<const MAX_KEY_LEN: usize> KeyWithCounter<MAX_KEY_LEN> {
    pub(crate) fn new(key: [u8; MAX_KEY_LEN], count: usize) -> Self {
        KeyWithCounter(key, count)
    }
}

impl<const MAX_KEY_LEN: usize> PartialEq for KeyWithCounter<MAX_KEY_LEN> {
    fn eq(&self, other: &KeyWithCounter<MAX_KEY_LEN>) -> bool {
        self.0 == other.0 && self.1 == other.1
    }
}

// impl<const MAX_KEY_LEN: usize> Eq for KeyWithCounter<MAX_KEY_LEN> {}

// impl<const MAX_KEY_LEN: usize> PartialOrd for KeyWithCounter<MAX_KEY_LEN> {
//     fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
//         PartialOrd::partial_cmp(&self.0, &other.0)
//     }
// }

// impl<const MAX_KEY_LEN: usize> Ord for KeyWithCounter<MAX_KEY_LEN> {
//     fn cmp(&self, other: &Self) -> Ordering {
//         Ord::cmp(&self.0, &other.0)
//     }
// }

impl<const MAX_KEY_LEN: usize> AsRef<[u8]> for KeyWithCounter<MAX_KEY_LEN> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const MAX_KEY_LEN: usize> From<KeyWithCounter<MAX_KEY_LEN>> for [u8; MAX_KEY_LEN] {
    fn from(k: KeyWithCounter<MAX_KEY_LEN>) -> Self {
        k.0
    }
}

pub(crate) fn null_key<const MAX_KEY_LEN: usize>() -> KeyWithCounter<MAX_KEY_LEN> {
    KeyWithCounter([0; MAX_KEY_LEN], 0)
}

/// High level struct that user interacts with
/// Q is the branching factor of the tree. More specifically, nodes can have at most Q - 1 keys.
pub struct BerkleTree<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> {
    params: &'params KZGParams<Bls12, Q>,
    root: Rc<RefCell<Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>>>,
    cnt: usize,
}

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> Debug
    for BerkleTree<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>
{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("BerkleTree")
            .field("root", &self.root.borrow())
            .finish()
    }
}

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize>
    BerkleTree<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>
{
    pub fn new(params: &'params KZGParams<Bls12, Q>) -> Self {
        assert!(Q > 2, "Branching factor Q must be greater than 2");
        BerkleTree {
            params,
            root: Rc::new(RefCell::new(LeafNode::new(&params).into())),
            cnt: 0,
        }
    }

    pub fn insert<K, V>(
        &mut self,
        key: K,
        value: V,
        hash: Blake3Hash,
    ) -> Result<MembershipProof<MAX_KEY_LEN>, BerkleError>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let key = key.as_ref();
        let value = value.as_ref();
        if key.len() > MAX_KEY_LEN {
            Err(BerkleError::KeyTooLong)
        } else if value.len() > MAX_VAL_LEN {
            Err(BerkleError::ValueTooLong)
        } else {
            let mut key_padded = [0; MAX_KEY_LEN];
            key_padded[0..key.len()].copy_from_slice(key.as_ref());

            let mut value_padded = [0; MAX_VAL_LEN];
            value_padded[0..value.len()].copy_from_slice(value.as_ref());

            let key = KeyWithCounter(key_padded, self.cnt);

            let (mut proof, new_node) =
                self.root
                    .borrow_mut()
                    .insert(&key, &value_padded, hash);

            self.cnt += 1;

            match new_node {
                Some((split_key, child)) => {
                    let proof_in_new_node = key.0 >= split_key.0;

                    let new_root = InternalNode {
                        keys: vec![null_key(), split_key],
                        children: vec![child],
                        witnesses: vec![None; Q],
                        batch_witness: None,
                        prover: KZGProver::new(self.params),
                    };

                    let old_root = self.root.replace(new_root.into());

                    let mut new_root = self.root.borrow_mut();
                    match &mut *new_root {
                        Node::Internal(new_root) => {
                            new_root.children.insert(0, old_root);

                            let idx = if proof_in_new_node { 1 } else { 0 };
                            let (commitment, witness) =
                                new_root.reinterpolate_and_create_witness(idx);
                            let inner_proof = InnerNodeProof {
                                idx,
                                node_size: new_root.keys.len(),
                                key: new_root.keys[idx].clone().into(),
                                child_hash: new_root.children[idx].hash().unwrap(),
                                witness,
                            };

                            proof.path.push(inner_proof);
                            proof.commitments.push(commitment);
                        }
                        Node::Leaf(_) => panic!("should never happen!"),
                    };

                    Ok(proof)
                }
                None => Ok(proof),
            }
        }
    }

    pub fn get<K>(&mut self, key: &K) -> Result<GetResult<MAX_KEY_LEN, MAX_VAL_LEN>, BerkleError>
    where
        K: AsRef<[u8]>,
    {
        if key.as_ref().len() > MAX_KEY_LEN {
            Err(BerkleError::KeyTooLong)
        } else {
            let mut key_padded = [0; MAX_KEY_LEN];
            key_padded[0..key.as_ref().len()].copy_from_slice(key.as_ref());

            Ok(self.root.borrow_mut().get(&key_padded))
        }
    }

    pub fn contains_key<K>(
        &mut self,
        key: &K,
    ) -> Result<ContainsResult<MAX_KEY_LEN, MAX_VAL_LEN>, BerkleError>
    where
        K: AsRef<[u8]>,
    {
        if key.as_ref().len() > MAX_KEY_LEN {
            Err(BerkleError::KeyTooLong)
        } else {
            let mut key_padded = [0; MAX_KEY_LEN];
            key_padded[0..key.as_ref().len()].copy_from_slice(key.as_ref());

            match self.root.borrow_mut().get(&key_padded) {
                GetResult::Found(_value, proof) => Ok(ContainsResult::Found(proof)),
                GetResult::NotFound(proof) => Ok(ContainsResult::NotFound(proof)),
            }
        }
    }

    pub fn delete<K>(
        &mut self,
        key: &K,
    ) -> Result<DeleteResult<MAX_KEY_LEN, MAX_VAL_LEN>, BerkleError>
    where
        K: AsRef<[u8]>,
    {
        if key.as_ref().len() > MAX_KEY_LEN {
            Err(BerkleError::KeyTooLong)
        } else {
            let mut key_padded = [0; MAX_KEY_LEN];
            key_padded[0..key.as_ref().len()].copy_from_slice(key.as_ref());

            println!("delete({:?})", key_padded);

            // check to make sure key exists
            let path: Vec<usize> = match self.root.borrow_mut().get(&key_padded) {
                GetResult::NotFound(proof) => return Ok(DeleteResult::NotFound(proof)),
                GetResult::Found(_, proof) => {
                    proof.path.iter().rev().map(|inner_node_proof| inner_node_proof.idx).collect()
                }
            };

            let mut root = self.root.borrow_mut();

            let (res, new_root) = match root.delete(&key_padded, path.as_slice()) {
                ((value, hash), _idx, false) => (DeleteResult::Deleted(value, hash), None),
                ((value, hash), _idx, true) => {
                    // need to decrease height of the tree
                    match &mut *root {
                        Node::Internal(ref mut node) => {
                            // merge all the children
                            let mut key = node.keys.pop().unwrap();
                            let mut right = node.children.pop().unwrap();
                            while node.keys.len() > 0 {
                                let mut left = node.children.pop().unwrap();
                                left.merge_from_right(right, key);
                                
                                right = left;
                                key = node.keys.pop().unwrap();
                            }

                            (DeleteResult::Deleted(value, hash), Some(right))
                        },
                        // if root is leaf, we can ignore the min key constraint
                        Node::Leaf(_) => (DeleteResult::Deleted(value, hash), None)
                    }
                }
            };

            if let Some(new_root) = new_root {
                *root = new_root;
            }

            Ok(res)
        }
    }
}

impl<const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize>
    BerkleTree<'static, Q, MAX_KEY_LEN, MAX_VAL_LEN>
{
  pub fn range<K>(
        &'static mut self,
        left: &K,
        right: &K,
    ) -> Result<RangeResult<Q, MAX_KEY_LEN, MAX_VAL_LEN>, BerkleError>
    where
        K: AsRef<[u8]>,
    {

        let left = self.get(left)?;
        let right = self.get(right)?;

        let (left_path, left_range_path) = match left {
            GetResult::Found(_, proof) => {
                (proof.path.iter().rev().map(|inner_node_proof| inner_node_proof.idx).collect(), RangePath::KeyExists(proof))
            },
            GetResult::NotFound(proof) => {
                match proof {
                    NonMembershipProof::IntraNode { ref path, idx, .. } => {
                        let mut path: Vec<usize> = path.iter().rev().map(|pf| pf.idx).collect();
                        // idx of IntraNode proof is the left element - we want the right one in this case
                        path.push(idx + 1);
                        (path, RangePath::KeyDNE(proof))
                    },
                    NonMembershipProof::InterNode { ref common_path, ref right_path, ref right, ..} => {
                        let mut path: Vec<usize> = common_path.as_ref().map_or(Vec::with_capacity(right_path.len()), |p| p.iter().rev().map(|pf| pf.idx).collect());
                        path.extend(right_path.iter().map(|pf| pf.idx));
                        path.push(right.idx);
                        (path, RangePath::KeyDNE(proof))
                    },
                    NonMembershipProof::Edge { ref path, ref leaf_proof, ..} => {
                        let mut path: Vec<usize> = path.iter().rev().map(|pf| pf.idx).collect();
                        path.push(leaf_proof.idx);
                        (path, RangePath::KeyDNE(proof))
                    }
                }
            }
        };

        let (right_path, right_range_path)= match right {
            GetResult::Found(_, proof) => {
                (proof.path.iter().rev().map(|inner_node_proof| inner_node_proof.idx).collect(), RangePath::KeyExists(proof))
            },
            GetResult::NotFound(proof) => {
                match proof {
                    NonMembershipProof::IntraNode { ref path, idx, .. } => {
                        let mut path: Vec<usize> = path.iter().rev().map(|pf| pf.idx).collect();
                        path.push(idx);
                        (path, RangePath::KeyDNE(proof))
                    },
                    NonMembershipProof::InterNode { ref common_path, ref left_path, ref left, ..} => {
                        let mut path: Vec<usize> = common_path.as_ref().map_or(Vec::with_capacity(left_path.len()), |p| p.iter().rev().map(|pf| pf.idx).collect());
                        path.extend(left_path.iter().map(|pf| pf.idx));
                        path.push(left.idx);
                        (path, RangePath::KeyDNE(proof))
                    },
                    NonMembershipProof::Edge { ref path, ref leaf_proof, ..} => {
                        let mut path: Vec<usize> = path.iter().map(|pf| pf.idx).collect();
                        path.push(leaf_proof.idx);
                        (path, RangePath::KeyDNE(proof))
                    }
                }
            }
        };

        let (size, bvs) = self.root.borrow().compute_range_size(left_path.as_slice(), right_path.as_slice(), 0);

        let proof = RangeProof {
            left_path: left_range_path,
            right_path: right_range_path,
            bitvecs: bvs
        };

        Ok(RangeResult {
            proof,
            root: Rc::clone(&self.root),
            current_path: left_path.clone(),
            size
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use fastrand::Rng;
    use kzg::KZGVerifier;
    use test_utils::*;

    const RAND_SEED: u64 = 42;

    fn test_setup<const Q: usize>() -> KZGParams<Bls12, Q> {
        let rng = Rng::with_seed(420);
        let s: Scalar = rng.u64(0..u64::MAX).into();
        kzg::setup(s)
    }

    #[test]
    fn test_insert_no_dupes() {
        let params = test_setup::<3>();
        let mut tree = BerkleTree::<3, 4, 4>::new(&params);

        // no dupes
        let keys: Vec<u32> = vec![5, 9, 12, 3, 8, 10, 1, 4];
        let values: Vec<u32> = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let verifier = KZGVerifier::new(&params);

        for (key, value) in keys.iter().zip(values.iter()) {
            let hash = blake3::hash(&value.to_le_bytes());
            let proof = tree
                .insert(key.to_le_bytes(), value.to_le_bytes(), hash)
                .unwrap();

            assert_is_b_tree(&tree);

            println!("------\n");
            println!("{:#?}", tree);
            assert!(
                proof.verify(&key.to_le_bytes(), hash, &verifier),
                "proof verification for ({:?}, {:?}) failed",
                key,
                value
            );
        }
    }

    #[test]
    fn test_insert_with_dupes() {
        let params = test_setup::<4>();
        let mut tree = BerkleTree::<4, 4, 4>::new(&params);

        // with dupes
        let keys: Vec<u32> = vec![6, 2, 4, 1, 1, 3, 5, 7, 4];
        let values: Vec<u32> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let verifier = KZGVerifier::new(&params);

        for (key, value) in keys.iter().zip(values.iter()) {
            let hash = blake3::hash(&value.to_le_bytes());
            let proof = tree
                .insert(key.to_le_bytes(), value.to_le_bytes(), hash)
                .unwrap();

            assert_is_b_tree(&tree);

            println!("------\n");
            println!("{:#?}", tree);
            assert!(
                proof.verify(&key.to_le_bytes(), hash, &verifier),
                "proof verification for ({:?}, {:?}) failed",
                key,
                value
            );
        }
    }

    #[test]
    fn test_get() {
        let params = test_setup::<3>();
        let verifier = KZGVerifier::new(&params);
        let mut tree = BerkleTree::<3, 4, 4>::new(&params);

        // build tree
        let keys: Vec<u32> = vec![8, 2, 12, 1, 1, 3, 5, 9, 12];
        let values: Vec<u32> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];

        for (key, value) in keys.iter().zip(values.iter()) {
            let hash = blake3::hash(&value.to_le_bytes());
            tree.insert(key.to_le_bytes(), value.to_le_bytes(), hash)
                .unwrap();
            
            assert_is_b_tree(&tree);
        }

        // get stuff that exists in tree, including dupes
        let search_key_idxs: Vec<usize> = vec![0, 1, 5, 7, 8, 4];

        for &i in search_key_idxs.iter() {
            let res = tree.get(&keys[i].to_le_bytes()).unwrap();
            match res {
                GetResult::Found(value, proof) => {
                    assert_eq!(values[i].to_le_bytes(), value);
                    assert!(proof.verify(&keys[i].to_le_bytes(), blake3::hash(&value), &verifier));
                }
                GetResult::NotFound(_proof) => panic!("expected key {} to be in tree!", keys[i]),
            }
        }

        // get stuff that doesn't exist in tree
        let search_keys: Vec<u32> = vec![4, 10, 99, 0, 7];
        for &key in search_keys.iter() {
            let res = tree.get(&key.to_le_bytes()).unwrap();

            match res {
                GetResult::NotFound(proof) => {
                    println!("checking non-membership proof for key {:?}", key);
                    assert!(proof.verify(&key.to_le_bytes(), &verifier));
                }
                GetResult::Found(_, _) => panic!("expected key {} to not be in tree!", key),
            }
        }
    }

    #[test]
    fn test_delete() {
        let params = test_setup::<4>();
        let verifier = KZGVerifier::new(&params);
        let mut tree = BerkleTree::<4, 4, 4>::new(&params);

        // build tree
        let keys: Vec<u32> = vec![5, 12, 9, 12, 81, 32, 7, 2, 54, 69, 57, 23, 78, 13, 9, 12];
        let values: Vec<u32> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        let mut pairs = HashMap::<u32, Vec<u32>>::new();

        for (key, value) in keys.iter().zip(values.iter()) {
            let hash = blake3::hash(&value.to_le_bytes());
            tree.insert(key.to_le_bytes(), value.to_le_bytes(), hash)
                .unwrap();

            if let Some(v) = pairs.get_mut(key) {
                v.push(*value);
            } else {
                pairs.insert(*key, vec![*value]);
            }
            
            assert_is_b_tree(&tree);
        }

        // delete stuff
        for (key, value) in keys.iter().zip(values.iter()) {
            match tree.delete(&key.to_le_bytes()) {
                Ok(DeleteResult::Deleted(v, hash)) => {
                    assert_is_b_tree(&tree);

                    // check to make sure returned value is one of the dupes put in
                    let vs = pairs.get(key).expect("expect pairs to contain key");
                    assert!(vs.contains(&u32::from_le_bytes(v)));


                    // check hash
                    assert_eq!(blake3::hash(&v), hash);
                }
                _ => panic!("delete({}) either failed or was NotFound!", key)
            }

        }
    }
}
