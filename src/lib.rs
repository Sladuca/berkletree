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

mod error;
mod node;
mod proofs;

#[cfg(test)]
mod test_utils;

use error::BerkleError;
use node::{InternalNode, LeafNode, Node};
use proofs::{ContainsResult, GetResult, InnerNodeProof, MembershipProof, RangeResult};

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
pub struct KeyWithCounter<const MAX_KEY_LEN: usize>([u8; MAX_KEY_LEN], u8);

impl<const MAX_KEY_LEN: usize> KeyWithCounter<MAX_KEY_LEN> {
    pub(crate) fn new(key: [u8; MAX_KEY_LEN], mut count: u8) -> Self {
        if key == [0; MAX_KEY_LEN] {
            count += 1;
        }
        KeyWithCounter(key, count)
    }
}

impl<const MAX_KEY_LEN: usize> PartialEq for KeyWithCounter<MAX_KEY_LEN> {
    fn eq(&self, other: &KeyWithCounter<MAX_KEY_LEN>) -> bool {
        self.0 == other.0
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

            let (mut proof, new_node) =
                self.root
                    .borrow_mut()
                    .insert(&key_padded, &value_padded, hash);

            match new_node {
                Some((split_key, child)) => {
                    let proof_in_new_node = key_padded >= split_key;

                    let new_root = InternalNode {
                        keys: vec![null_key(), KeyWithCounter::new(split_key, 0)],
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

    pub fn bulk_insert<K, V>(
        &mut self,
        entries: Vec<(K, V, Blake3Hash)>,
    ) -> Result<Vec<MembershipProof<MAX_KEY_LEN>>, BerkleError>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        unimplemented!()
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

    pub fn contains_key<K>(&mut self, key: &K) -> Result<ContainsResult<MAX_KEY_LEN, MAX_VAL_LEN>, BerkleError>
    where
        K: AsRef<[u8]>,
    {
        unimplemented!()
    }

    pub fn contains_key_no_proof<K>(&self, key: &K) -> bool
    where
        K: AsRef<[u8]>,
    {
        unimplemented!()
    }

    pub fn range<K>(
        &mut self,
        left: &K,
        right: &K,
    ) -> Result<RangeResult<Q, MAX_KEY_LEN, MAX_VAL_LEN>, BerkleError>
    where
        K: AsRef<[u8]>,
    {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
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
        let params = test_setup::<3>();
        let mut tree = BerkleTree::<3, 4, 4>::new(&params);

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
    fn test_get_no_dupes() {
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
        }

        // get stuff that exists in tree
        let search_key_idxs: Vec<usize> = vec![0, 5, 7, 8, 4];

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
}
