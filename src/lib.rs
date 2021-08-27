use bitvec::vec::BitVec;
use blake3::Hash as Blake3Hash;
use bls12_381::{Bls12, Scalar};
use bytes::Bytes;
use kzg::{KZGBatchWitness, KZGCommitment, KZGParams, KZGProver, KZGWitness};
use std::{cell::RefCell, convert::TryFrom, rc::Rc};

mod error;
use error::{BerkleError, NodeConvertError};

#[cfg(test)]
mod test_utils;

pub type Offset = usize;

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
pub struct BerkleTree<'params, const Q: usize> {
    params: &'params KZGParams<Bls12, Q>,
    root: Rc<RefCell<Node<'params, Q>>>,
}

/// enum reprenting the different kinds of nodes for
#[derive(Clone)]
enum Node<'params, const Q: usize> {
    Internal {
        hash: Option<FieldHash>,
        node: InternalNode<'params, Q>,
    },
    Leaf {
        hash: Option<FieldHash>,
        node: LeafNode<'params, Q>,
    },
}

impl<'params, const Q: usize> From<InternalNode<'params, Q>> for Node<'params, Q> {
    fn from(node: InternalNode<'params, Q>) -> Self {
        Node::Internal {
            hash: node.hash().ok(),
            node,
        }
    }
}

impl<'params, const Q: usize> From<LeafNode<'params, Q>> for Node<'params, Q> {
    fn from(node: LeafNode<'params, Q>) -> Self {
        Node::Leaf {
            hash: node.hash().ok(),
            node,
        }
    }
}

impl<'params, const Q: usize> TryFrom<Node<'params, Q>> for LeafNode<'params, Q> {
    type Error = NodeConvertError;
    fn try_from(node: Node<'params, Q>) -> Result<Self, NodeConvertError> {
        match node {
            Node::Leaf { hash: _, node } => Ok(node),
            _ => Err(NodeConvertError::NotLeafNode),
        }
    }
}

impl<'params, const Q: usize> TryFrom<Node<'params, Q>> for InternalNode<'params, Q> {
    type Error = NodeConvertError;
    fn try_from(node: Node<'params, Q>) -> Result<Self, NodeConvertError> {
        match node {
            Node::Internal { hash: _, node } => Ok(node),
            _ => Err(NodeConvertError::NotInternalNode),
        }
    }
}

#[derive(Clone)]
pub(crate) struct InternalNode<'params, const Q: usize> {
    children: Vec<Node<'params, Q>>,
    keys: Vec<Bytes>,
    // witnesses are lazily-computed - none if any particular witness hasn't been computed yet.
    witnesses: Vec<Option<KZGWitness<Bls12>>>,
    batch_witness: Option<KZGBatchWitness<Bls12, Q>>,
    prover: KZGProver<'params, Bls12, Q>,
}

impl<'params, const Q: usize> InternalNode<'params, Q> {
    fn new(
        params: &'params KZGParams<Bls12, Q>,
        key: Bytes,
        left: Node<'params, Q>,
        right: Node<'params, Q>,
    ) -> Self {
        let left_key = match left {
            Node::Internal { hash, ref node } => node.keys[0].clone(),
            Node::Leaf { hash, ref node } => node.keys[0].clone(),
        };

        InternalNode {
            children: vec![left, right],
            keys: vec![key],
            witnesses: Vec::new(),
            batch_witness: None,
            prover: KZGProver::new(params),
        }
    }

    fn hash(&self) -> Result<FieldHash, BerkleError> {
        let commitment = self
            .prover
            .commitment_ref()
            .ok_or(BerkleError::NotCommitted)?
            .inner();
        Ok(blake3::hash(&commitment.to_uncompressed()).into())
    }
}

#[derive(Clone)]
pub(crate) struct LeafNode<'params, const Q: usize> {
    keys: Vec<Bytes>,
    offsets: Vec<Offset>,
    hashes: Vec<FieldHash>,
    witnesses: Vec<Option<KZGWitness<Bls12>>>,
    batch_witness: Option<KZGBatchWitness<Bls12, Q>>,
    prover: KZGProver<'params, Bls12, Q>, // no next / prev pointers here since we need to traverse the tree up/down
                                          // anyways to get a range proof
}

impl<'params, const Q: usize> LeafNode<'params, Q> {
    /// new *does not* immediately commit
    // for the commitment to occur, you must call commit()
    fn new(params: &'params KZGParams<Bls12, Q>) -> Self {
        LeafNode {
            offsets: Vec::with_capacity(Q),
            keys: Vec::with_capacity(Q),
            hashes: Vec::with_capacity(Q),
            witnesses: Vec::with_capacity(Q),
            batch_witness: None,
            prover: KZGProver::new(params),
        }
    }

    fn hash(&self) -> Result<FieldHash, BerkleError> {
        let commitment = self
            .prover
            .commitment_ref()
            .ok_or(BerkleError::NotCommitted)?
            .inner();
        Ok(blake3::hash(&commitment.to_uncompressed()).into())
    }
}

pub struct KVProof {
    idx: usize,
    witness: KZGWitness<Bls12>,
}

pub struct InnerNodeProof {
    idx: usize,
    key: Bytes,
    child_hash: FieldHash,
    witness: KZGWitness<Bls12>,
}

pub struct MembershipProof {
    commitments: Vec<KZGCommitment<Bls12>>,
    path: Vec<InnerNodeProof>,
    leaf: KVProof,
}

pub enum NonMembershipProof {
    /// path_to_leaf.len() == commitments.len() - 1. The last commitment is for the leaf node
    IntraNode {
        commitments: Vec<KZGCommitment<Bls12>>,
        path_to_leaf: Vec<InnerNodeProof>,

        left: KVProof,
        right: KVProof,
    },
    InterNode {
        common_path: Option<Vec<InnerNodeProof>>,
        common_commitments: Option<Vec<KZGCommitment<Bls12>>>,

        left: KVProof,
        left_commitment: KZGCommitment<Bls12>,

        right: KVProof,
        right_commitment: KZGCommitment<Bls12>,
    },
}

pub enum RangePath {
    KeyExists(MembershipProof),
    KeyDNE(NonMembershipProof),
}

// TODO
pub struct RangeProof {
    left_path: RangePath,
    right_path: RangePath,
    bitvecs: Vec<BitVec>,
}

pub enum GetResult {
    Found(Offset, MembershipProof),
    NotFound(NonMembershipProof),
}

pub enum ContainsResult {
    Found(MembershipProof),
    NotFound(NonMembershipProof),
}

pub struct RangeResult<'params, const Q: usize> {
    proof: RangeProof,
    iter: RangeIter<'params, Q>,
}

pub struct RangeIter<'params, const Q: usize> {
    left_path: Vec<Bytes>,
    right_path: Vec<Bytes>,
    root: Rc<RefCell<Node<'params, Q>>>,
    current_key: Bytes,
}

impl<'params, const Q: usize> BerkleTree<'params, Q> {
    pub fn new_with_params(params: &'params KZGParams<Bls12, Q>) -> Self {
        assert!(Q > 2, "Branching factor Q must be greater than 2");
        let prover = KZGProver::new(params);
        unimplemented!();
    }

    pub fn insert<K>(&mut self, key: K, value: Offset, hash: Blake3Hash) -> MembershipProof
    where
        K: AsRef<[u8]>,
    {
        unimplemented!()
    }

    pub fn insert_no_proof<K>(&mut self, key: K, value: Offset, hash: Blake3Hash)
    where
        K: AsRef<[u8]>,
    {
        unimplemented!()
    }

    pub fn bulk_insert<K>(&mut self, entries: Vec<(K, Offset, Blake3Hash)>) -> Vec<MembershipProof>
    where
        K: AsRef<[u8]>,
    {
        unimplemented!()
    }

    pub fn bulk_insert_no_proof<K>(&mut self, entries: Vec<(K, Offset, Blake3Hash)>)
    where
        K: AsRef<[u8]>,
    {
        unimplemented!()
    }

    pub fn get<K>(&self, key: &K) -> GetResult
    where
        K: AsRef<[u8]>,
    {
        unimplemented!()
    }

    pub fn get_no_proof<K>(&self, key: &K) -> Option<Offset>
    where
        K: AsRef<[u8]>,
    {
        unimplemented!()
    }

    pub fn contains_key<K>(&self, key: &K) -> ContainsResult
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

    pub fn range<K>(&self, left: &K, right: &K) -> RangeResult<Q>
    where
        K: AsRef<[u8]>,
    {
        unimplemented!()
    }

    pub fn range_no_proof<K>(&self, key: &K) -> RangeIter<Q>
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
        let mut tree: BerkleTree<11> = BerkleTree::new_with_params(&params);

        let keys: Vec<usize> = (0..1000).step_by(10).collect();

        // ordered insert, oredered get
        for &i in keys.iter() {
            let b = &i.to_le_bytes();
            let hash = blake3::hash(b);
            tree.insert_no_proof(b, i, hash);
            assert_is_b_tree(&tree);
        }

        for &i in keys.iter() {
            let b = &i.to_le_bytes();
            let v = tree
                .get_no_proof(b)
                .expect(&format!("could not find key {} in the tree", i));
            assert_eq!(v, i);
            assert_is_b_tree(&tree);
        }

        let mut tree: BerkleTree<11> = BerkleTree::new_with_params(&params);
        let rng = Rng::with_seed(RAND_SEED);
        let mut keys_shuffled = keys.clone();

        // ordered insert, unordered get
        for &i in keys.iter() {
            let b = &i.to_le_bytes();
            let hash = blake3::hash(b);
            tree.insert_no_proof(b, i, hash);
            assert_is_b_tree(&tree);
        }

        rng.shuffle(&mut keys_shuffled);

        for &i in keys_shuffled.iter() {
            let b = &i.to_le_bytes();
            let v = tree
                .get_no_proof(b)
                .expect(&format!("could not find key {} in the tree", i));
            assert_eq!(v, i);
            assert_is_b_tree(&tree);
        }

        let mut tree: BerkleTree<11> = BerkleTree::new_with_params(&params);
        // unordered insert, ordered get
        rng.shuffle(&mut keys_shuffled);
        for &i in keys_shuffled.iter() {
            let b = &i.to_le_bytes();
            let hash = blake3::hash(b);
            tree.insert_no_proof(b, i, hash);
            assert_is_b_tree(&tree);
        }

        for &i in keys.iter() {
            let b = &i.to_le_bytes();
            let v = tree
                .get_no_proof(b)
                .expect(&format!("could not find key {} in the tree", i));
            assert_eq!(v, i);
            assert_is_b_tree(&tree);
        }

        let mut tree: BerkleTree<11> = BerkleTree::new_with_params(&params);
        // unordered insert, unordered get
        rng.shuffle(&mut keys_shuffled);
        for &i in keys_shuffled.iter() {
            let b = &i.to_le_bytes();
            let hash = blake3::hash(b);
            tree.insert_no_proof(b, i, hash);
            assert_is_b_tree(&tree);
        }

        rng.shuffle(&mut keys_shuffled);
        for &i in keys.iter() {
            let b = &i.to_le_bytes();
            let v = tree
                .get_no_proof(b)
                .expect(&format!("could not find key {} in the tree", i));
            assert_eq!(v, i);
            assert_is_b_tree(&tree);
        }
    }
}
