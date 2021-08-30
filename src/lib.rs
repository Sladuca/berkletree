use bitvec::vec::BitVec;
use blake3::Hash as Blake3Hash;
use bls12_381::{Bls12, Scalar};
use kzg::{KZGCommitment, KZGParams, KZGWitness};
use std::{cell::RefCell, rc::Rc};

pub type Offset = usize;
mod error;
mod node;

use node::{Node, LeafNode, InternalNode};
use error::BerkleError;


#[cfg(test)]
mod test_utils;

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

/// High level struct that user interacts with
/// Q is the branching factor of the tree. More specifically, nodes can have at most Q - 1 keys.
pub struct BerkleTree<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> {
    params: &'params KZGParams<Bls12, Q>,
    root: Rc<RefCell<Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>>>,
}

pub struct KVProof {
    idx: usize,
	commitment: KZGCommitment<Bls12>,
    witness: KZGWitness<Bls12>,
}

pub struct InnerNodeProof<const MAX_KEY_LEN: usize> {
    idx: usize,
    key: [u8; MAX_KEY_LEN],
    child_hash: FieldHash,
    witness: KZGWitness<Bls12>,
}

pub struct MembershipProof<const MAX_KEY_LEN: usize> {
    commitments: Vec<KZGCommitment<Bls12>>,
    path: Vec<InnerNodeProof<MAX_KEY_LEN>>,
    leaf: KVProof,
}

pub enum NonMembershipProof<const MAX_KEY_LEN: usize> {
    /// path_to_leaf.len() == commitments.len() - 1. The last commitment is for the leaf node
    IntraNode {
        commitments: Vec<KZGCommitment<Bls12>>,
        path_to_leaf: Vec<InnerNodeProof<MAX_KEY_LEN>>,

        left_key: [u8; MAX_KEY_LEN],
        left: KVProof,

        right_key: [u8; MAX_KEY_LEN],
        right: KVProof,
    },
    InterNode {
        common_path: Option<Vec<InnerNodeProof<MAX_KEY_LEN>>>,
        common_commitments: Option<Vec<KZGCommitment<Bls12>>>,

        left: KVProof,
        left_key: [u8; MAX_KEY_LEN],
        left_commitment: KZGCommitment<Bls12>,

        right: KVProof,
        right_key: [u8; MAX_KEY_LEN],
        right_commitment: KZGCommitment<Bls12>,
    },
}

pub enum RangePath<const MAX_KEY_LEN: usize> {
    KeyExists(MembershipProof<MAX_KEY_LEN>),
    KeyDNE(NonMembershipProof<MAX_KEY_LEN>),
}

// TODO
pub struct RangeProof<const MAX_KEY_LEN: usize> {
    left_path: RangePath<MAX_KEY_LEN>,
    right_path: RangePath<MAX_KEY_LEN>,
    bitvecs: Vec<BitVec>,
}

pub enum GetResult<const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> {
    Found([u8; MAX_VAL_LEN], MembershipProof<MAX_KEY_LEN>),
    NotFound(NonMembershipProof<MAX_KEY_LEN>),
}

pub enum ContainsResult<const MAX_KEY_LEN: usize> {
    Found(MembershipProof<MAX_KEY_LEN>),
    NotFound(NonMembershipProof<MAX_KEY_LEN>),
}

pub struct RangeResult<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> {
    proof: RangeProof<MAX_KEY_LEN>,
    iter: RangeIter<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>,
}

pub struct RangeIter<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> {
    left_path: Vec<[u8; MAX_KEY_LEN]>,
    right_path: Vec<[u8; MAX_KEY_LEN]>,
    root: Rc<RefCell<Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>>>,
    current_key: [u8; MAX_KEY_LEN],
}

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> BerkleTree<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN> {
    pub fn new_with_params(params: &'params KZGParams<Bls12, Q>) -> Self {
        assert!(Q > 2, "Branching factor Q must be greater than 2");
		BerkleTree {
			params,
			root: Rc::new(RefCell::new(LeafNode::new(&params).into()))
		}
    }

    pub fn insert<K, V>(&mut self, key: K, value: V, hash: Blake3Hash) -> Result<MembershipProof<MAX_KEY_LEN>, BerkleError>
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

		    Ok(self.root.borrow_mut().insert(&key_padded, &value_padded, hash))
        }
    }

    pub fn insert_no_proof<K, V>(&mut self, key: K, value: V, hash: Blake3Hash) -> Result<(), BerkleError>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        unimplemented!()
    }

    pub fn bulk_insert<K, V>(&mut self, entries: Vec<(K, V, Blake3Hash)>) -> Result<Vec<MembershipProof<MAX_KEY_LEN>>, BerkleError>
    where
        K: AsRef<[u8]>,
    {
        unimplemented!()
    }

    pub fn bulk_insert_no_proof<K, V>(&mut self, entries: Vec<(K, V, Blake3Hash)>) -> Result<(), BerkleError>
    where
        K: AsRef<[u8]>,
    {
        unimplemented!()
    }

    pub fn get<K, V>(&self, key: &K) -> Result<GetResult<MAX_KEY_LEN, MAX_VAL_LEN>, BerkleError>
    where
        K: AsRef<[u8]>,
    {
        unimplemented!()
    }

    pub fn get_no_proof<K>(&self, key: &K) -> Result<Option<[u8; MAX_VAL_LEN]>, BerkleError>
    where
        K: AsRef<[u8]>,
    {
        unimplemented!()
    }

    pub fn contains_key<K>(&self, key: &K) -> Result<ContainsResult<MAX_KEY_LEN>, BerkleError>
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

    pub fn range<K>(&self, left: &K, right: &K) -> Result<RangeResult<Q, MAX_KEY_LEN, MAX_VAL_LEN>, BerkleError>
    where
        K: AsRef<[u8]>,
    {
        unimplemented!()
    }

    pub fn range_no_proof<K>(&self, left: &K, right: &K) -> Result<RangeIter<Q, MAX_KEY_LEN, MAX_VAL_LEN>, BerkleError>
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
    use std::fmt::Debug;
    use test_utils::*;

    const RAND_SEED: u64 = 42;

    fn test_setup<const Q: usize>() -> KZGParams<Bls12, Q> {
        let rng = Rng::with_seed(420);
        let s: Scalar = rng.u64(0..u64::MAX).into();
        kzg::setup(s)
    }

    #[test]
    fn test_non_bulk_only_root_no_proof() {
        let params = test_setup();
        let mut tree: BerkleTree<11, 8, 8> = BerkleTree::new_with_params(&params);

        let keys: Vec<usize> = (0..1000).step_by(10).collect();

        // ordered insert, oredered get
        for &i in keys.iter() {
            let b = &i.to_le_bytes();
            let hash = blake3::hash(b);
            tree.insert_no_proof(b, b, hash).unwrap();
            assert_is_b_tree(&tree);
        }

        for &i in keys.iter() {
            let b = &i.to_le_bytes();
            let v = tree
                .get_no_proof(b)
                .unwrap()
                .expect(&format!("could not find key {:?} in the tree", b));
            assert_eq!(&v, b);
            assert_is_b_tree(&tree);
        }

        let mut tree: BerkleTree<11, 8, 8> = BerkleTree::new_with_params(&params);
        let rng = Rng::with_seed(RAND_SEED);
        let mut keys_shuffled = keys.clone();

        // ordered insert, unordered get
        for &i in keys.iter() {
            let b = &i.to_le_bytes();
            let hash = blake3::hash(b);
            tree.insert_no_proof(b, b, hash).unwrap();
            assert_is_b_tree(&tree);
        }

        rng.shuffle(&mut keys_shuffled);

        for &i in keys_shuffled.iter() {
            let b = &i.to_le_bytes();
            let v = tree
                .get_no_proof(b)
                .unwrap()
                .expect(&format!("could not find key {} in the tree", i));
            assert_eq!(&v, b);
            assert_is_b_tree(&tree);
        }

        let mut tree: BerkleTree<11, 8, 8> = BerkleTree::new_with_params(&params);
        // unordered insert, ordered get
        rng.shuffle(&mut keys_shuffled);
        for &i in keys_shuffled.iter() {
            let b = &i.to_le_bytes();
            let hash = blake3::hash(b);
            tree.insert_no_proof(b, b, hash).unwrap();
            assert_is_b_tree(&tree);
        }

        for &i in keys.iter() {
            let b = &i.to_le_bytes();
            let v = tree
                .get_no_proof(b)
                .unwrap()
                .expect(&format!("could not find key {} in the tree", i));
            assert_eq!(&v, b);
            assert_is_b_tree(&tree);
        }

        let mut tree: BerkleTree<11, 8, 8> = BerkleTree::new_with_params(&params);
        // unordered insert, unordered get
        rng.shuffle(&mut keys_shuffled);
        for &i in keys_shuffled.iter() {
            let b = &i.to_le_bytes();
            let hash = blake3::hash(b);
            tree.insert_no_proof(b, b, hash).unwrap();
            assert_is_b_tree(&tree);
        }

        rng.shuffle(&mut keys_shuffled);
        for &i in keys.iter() {
            let b = &i.to_le_bytes();
            let v = tree
                .get_no_proof(b)
                .unwrap()
                .expect(&format!("could not find key {} in the tree", i));
            assert_eq!(&v, b);
            assert_is_b_tree(&tree);
        }
    }
}
