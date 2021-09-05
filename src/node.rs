use kzg::{
    polynomial::Polynomial, KZGBatchWitness, KZGCommitment, KZGParams, KZGProver, KZGWitness,
};
use std::convert::{TryFrom, TryInto};

use blake3::{Hash as Blake3Hash, Hasher as Blake3Hasher};
use bls12_381::{Bls12, Scalar};
use either::Either;

use crate::error::{BerkleError, NodeConvertError};
use crate::{KeyWithCounter, null_key, FieldHash};
use crate::proofs::{ContainsResult, GetResult, InnerNodeProof, KVProof, MembershipProof, NonMembershipProof, RangeIter, RangeResult};

/// enum reprenting the different kinds of nodes for
#[derive(Clone)]
pub enum Node<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> {
    Internal(InternalNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>),
    Leaf(LeafNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>),
}

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize>
    From<InternalNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>>
    for Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>
{
    fn from(node: InternalNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>) -> Self {
        Node::Internal(node)
    }
}

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize>
    From<LeafNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>>
    for Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>
{
    fn from(node: LeafNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>) -> Self {
        Node::Leaf(node)
    }
}

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize>
    TryFrom<Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>>
    for LeafNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>
{
    type Error = NodeConvertError;
    fn try_from(
        node: Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>,
    ) -> Result<Self, NodeConvertError> {
        match node {
            Node::Leaf(node) => Ok(node),
            _ => Err(NodeConvertError::NotLeafNode),
        }
    }
}

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize>
    TryFrom<Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>>
    for InternalNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>
{
    type Error = NodeConvertError;
    fn try_from(
        node: Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>,
    ) -> Result<Self, NodeConvertError> {
        match node {
            Node::Internal(node) => Ok(node),
            _ => Err(NodeConvertError::NotInternalNode),
        }
    }
}

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize>
    Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>
{

    pub(crate) fn hash(&self) -> Result<FieldHash, BerkleError> {
        match self {
            Node::Internal(node) => node.hash(),
            Node::Leaf(node) => node.hash()
        } 
    }


    pub(crate) fn insert(
        &mut self,
        key: &[u8; MAX_KEY_LEN],
        value: &[u8; MAX_VAL_LEN],
        hash: Blake3Hash,
    ) -> (MembershipProof<MAX_KEY_LEN>, Option<([u8; MAX_KEY_LEN], Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>)>) {
        match self {
            Node::Internal(node) => {
                let (proof, new_node) = node.insert(key, value, hash);

                match new_node {
					Some((key, node)) => (proof, Some((key, node.into()))),
                    None => (proof, None)
                }
            },
            Node::Leaf(node) => {
                let (proof, new_node) = node.insert(key, value, hash);
                let proof = MembershipProof {
                    commitments: Vec::new(),
                    path: Vec::new(),
                    leaf: proof,
                };

                (proof, new_node.map(|(k, n)| (k, n.into())))
            }
        }
    }

    pub(crate) fn bulk_insert(
        &mut self,
        entries: Vec<(&[u8; MAX_KEY_LEN], &[u8; MAX_VAL_LEN], Blake3Hash)>,
    ) -> Vec<MembershipProof<MAX_KEY_LEN>> {
        unimplemented!()
    }

    pub(crate) fn get(&mut self, key: &[u8; MAX_KEY_LEN]) -> GetResult<MAX_KEY_LEN, MAX_VAL_LEN> {
        match self {
            Node::Internal(node) => node.get(key),
            Node::Leaf(node) => match node.get(key) {
                Either::Left(LeafGetFound(val, leaf)) => GetResult::Found(
                    val,
                    MembershipProof {
                        commitments: Vec::new(),
                        path: Vec::new(),
                        leaf,
                    },
                ),
                Either::Right(res) => GetResult::NotFound(match res {
                    LeafGetNotFound::Mid {
                        idx,
                        commitment,
                        left_witness,
                        left_key,
                        right_witness,
                        right_key,
                    } => NonMembershipProof::IntraNode {
                        path: Vec::new(),
                        leaf_commitment: commitment,
                        idx,
                        left_key,
                        left_witness,
                        right_key,
                        right_witness,
                    },
                    LeafGetNotFound::Left { right, right_key } => NonMembershipProof::Edge {
                        is_left: true,
                        path: Vec::new(),
                        leaf_proof: right,
                        key: right_key,
                    },
                    LeafGetNotFound::Right { left, left_key } => NonMembershipProof::Edge {
                        is_left: false,
                        path: Vec::new(),
                        leaf_proof: left,
                        key: left_key,
                    },
                }),
            },
        }
    }

    pub(crate) fn contains_key(&self, key: &[u8; MAX_KEY_LEN]) -> ContainsResult<MAX_KEY_LEN> {
        unimplemented!()
    }

    pub(crate) fn range(
        &self,
        left: &[u8; MAX_KEY_LEN],
        right: &[u8; MAX_KEY_LEN],
    ) -> RangeResult<Q, MAX_KEY_LEN, MAX_VAL_LEN> {
        unimplemented!()
    }
}



impl<const MAX_KEY_LEN: usize> KeyWithCounter<MAX_KEY_LEN> {
    pub(crate) fn hash(&self) -> Blake3Hash {
        let mut hasher = Blake3Hasher::new();
        hasher.update(&self.0);
        hasher.update(&[self.1]);
        hasher.finalize()
    }

    pub(crate) fn hash_with_idx(&self, idx: usize) -> Blake3Hash {
        let mut hasher = Blake3Hasher::new();
        hasher.update(&self.0);
        hasher.update(&[self.1]);
        hasher.update(&idx.to_le_bytes());
        hasher.finalize()
    }

    pub(crate) fn field_hash_with_idx(&self, idx: usize) -> FieldHash {
        self.hash_with_idx(idx).into()
    }
}

#[derive(Clone)]
pub struct InternalNode<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize>
{
    pub(crate) hash: Option<FieldHash>,
    // INVARIANT: children.len() == keys.len()
    // the ith key is >= than all keys in the ith child but < all keys in the i+1th child
    pub(crate) keys: Vec<KeyWithCounter<MAX_KEY_LEN>>,
    pub(crate) children: Vec<Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>>,
    // witnesses are lazily-computed - none if any particular witness hasn't been computed yet.
    pub(crate) witnesses: Vec<Option<KZGWitness<Bls12>>>,
    pub(crate) batch_witness: Option<KZGBatchWitness<Bls12, Q>>,
    pub(crate) prover: KZGProver<'params, Bls12, Q>,
}

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize>
    InternalNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>
{
    pub(crate) fn new(
        params: &'params KZGParams<Bls12, Q>,
        key: [u8; MAX_KEY_LEN],
        left: Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>,
        right: Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>,
    ) -> Self {
        let left_key = match left {
            Node::Internal(ref node) => node.keys[0].clone(),
            Node::Leaf(ref node) => node.keys[0].clone(),
        };

        InternalNode {
            hash: None,
            children: vec![left, right],
            keys: vec![null_key(), KeyWithCounter(key, 0)],
            witnesses: vec![None, None],
            batch_witness: None,
            prover: KZGProver::new(params),
        }
    }

    pub(crate) fn hash(&self) -> Result<FieldHash, BerkleError> {
        let commitment = self
            .prover
            .commitment_ref()
            .ok_or(BerkleError::NotCommitted)?
            .inner();
        let mut hasher = Blake3Hasher::new();
        hasher.update(&commitment.to_compressed());
        hasher.update(b"internal");
        Ok(hasher.finalize().into())
    }

    fn get_key_idx(&self, key: &[u8; MAX_KEY_LEN]) -> usize {
        self.keys.partition_point(|k| &k.0 <= key)
    }

    fn insert_inner(&mut self, key: &[u8; MAX_KEY_LEN], value: &[u8; MAX_VAL_LEN], hash: Blake3Hash) -> (usize, MembershipProof<MAX_KEY_LEN>, Option<([u8; MAX_KEY_LEN], InternalNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>)>) {
        let idx = self.get_key_idx(key);

        let (proof, new_node) = self.children[idx].insert(key, value, hash);
        
        if let Some((split_key, child)) = new_node {
            let idx = self.get_key_idx(&split_key);
            self.keys.insert(idx, KeyWithCounter(split_key, 0));
            self.children.insert(idx, child);

            if self.keys.len() == Q {
                let mid = self.keys.len() / 2;

                let right_keys = self.keys.split_off(mid);
                let right_children = self.children.split_off(mid);
           
                let right = InternalNode {
                    hash: None,
                    children: right_children,
                    keys: right_keys,
                    witnesses: Vec::new(),
                    batch_witness: None,
                    prover: KZGProver::new(self.prover.parameters()),
                };

                let split_key = self.keys.last().unwrap().clone();

                (idx, proof, Some((split_key.into(), right)))
            } else {
                (idx, proof, None)
            }
        } else {
            (idx, proof, None)
        }
    }

    pub(crate) fn reinterpolate_and_create_witness(
        &mut self,
        idx: usize,
    ) -> (KZGCommitment<Bls12>, KZGWitness<Bls12>) {
        let (commitment, xs, ys) = self.reinterpolate_inner();

        // *should* be guaranteed to be on the polynomial since we just interpolated
        let witness = self.prover.create_witness((xs[idx], ys[idx])).unwrap();
        self.witnesses[idx] = Some(witness);
        (commitment, witness)
    }

    fn reinterpolate_inner(&mut self) -> (KZGCommitment<Bls12>, Vec<Scalar>, Vec<Scalar>) {
        let xs: Vec<Scalar> = self
            .keys
            .iter()
            .chain(std::iter::once(&null_key()))
            .enumerate()
            .map(|(i, k)| k.field_hash_with_idx(i).into())
            .collect();

        let ys: Vec<Scalar> = self.children.iter().map(|child| child.hash().unwrap().into()).collect();

        let polynomial: Polynomial<Bls12, Q> =
            Polynomial::lagrange_interpolation(xs.as_slice(), ys.as_slice());
        let commitment = self.prover.commit(polynomial);
        self.witnesses.iter_mut().for_each(|w| *w = None);
        (commitment, xs, ys)
    }

    pub(crate) fn insert(
        &mut self,
        key: &[u8; MAX_KEY_LEN],
        value: &[u8; MAX_VAL_LEN],
        hash: Blake3Hash,
    ) -> (MembershipProof<MAX_KEY_LEN>, Option<([u8; MAX_KEY_LEN], InternalNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>)>) {
        let (idx, mut proof, new_node) = self.insert_inner(key, value, hash);

        let (commitment, inner_proof) = match new_node {
            Some((_split_key, ref new_node)) => {
                if idx >= self.keys.len() { 
                    let (commitment, witness) = self.reinterpolate_and_create_witness(idx);
                    (
                        commitment,
                        InnerNodeProof {
                            idx: idx - self.keys.len(),
                            key: new_node.keys[idx - self.keys.len()].clone(),
                            child_hash: new_node.children[idx - self.keys.len()].hash().unwrap(),
                            witness
                        },
                    )
                } else {
                    let (commitment, witness) = self.reinterpolate_and_create_witness(idx);
                    (
                        commitment,
                        InnerNodeProof {
                            idx: idx - self.keys.len(),
                            key: self.keys[idx].clone(),
                            child_hash: self.children[idx].hash().unwrap(),
                            witness
                        },
                    )
                }
            }
            None => {
                let (commitment, witness) = self.reinterpolate_and_create_witness(idx);
                (
                    commitment,
                    InnerNodeProof {
                        idx: idx - self.keys.len(),
                        key: self.keys[idx].clone(),
                        child_hash: self.children[idx].hash().unwrap(),
                        witness
                    },
                )
            }
        };

        proof.commitments.push(commitment);
        proof.path.push(inner_proof);
       
        (proof, new_node)
    }

    pub(crate) fn get(&self, key: &[u8; MAX_KEY_LEN]) -> GetResult<MAX_KEY_LEN, MAX_VAL_LEN> {
        unimplemented!()
    }
}

#[derive(Clone)]
pub struct LeafNode<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> {
    pub(crate) hash: Option<FieldHash>,
    // INVARIANT: children.len() == keys.len()

    pub(crate) keys: Vec<KeyWithCounter<MAX_KEY_LEN>>,
    pub(crate) values: Vec<[u8; MAX_VAL_LEN]>,
    pub(crate) hashes: Vec<FieldHash>,
    pub(crate) witnesses: Vec<Option<KZGWitness<Bls12>>>,
    pub(crate) batch_witness: Option<KZGBatchWitness<Bls12, Q>>,
    pub(crate) prover: KZGProver<'params, Bls12, Q>,
    // no sibling pointers yet
}

pub(crate) struct LeafGetFound<const MAX_VAL_LEN: usize>([u8; MAX_VAL_LEN], KVProof);
pub(crate) enum LeafGetNotFound<const MAX_KEY_LEN: usize> {
    Left {
        right: KVProof,
        right_key: KeyWithCounter<MAX_KEY_LEN>,
    },
    Right {
        left: KVProof,
        left_key: KeyWithCounter<MAX_KEY_LEN>,
    },
    Mid {
        idx: usize,
        commitment: KZGCommitment<Bls12>,

        left_witness: KZGWitness<Bls12>,
        left_key: KeyWithCounter<MAX_KEY_LEN>,

        right_witness: KZGWitness<Bls12>,
        right_key: KeyWithCounter<MAX_KEY_LEN>,
    },
}

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize>
    LeafNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>
{
    /// new *does not* immediately commit
    // for the commitment to occur, you must call commit()
    pub(crate) fn new(params: &'params KZGParams<Bls12, Q>) -> Self {
        LeafNode {
            hash: None,
            values: Vec::with_capacity(Q),
            keys: Vec::with_capacity(Q),
            hashes: Vec::with_capacity(Q),
            witnesses: Vec::with_capacity(Q),
            batch_witness: None,
            prover: KZGProver::new(params),
        }
    }

    pub(crate) fn hash(&self) -> Result<FieldHash, BerkleError> {
        let commitment = self
            .prover
            .commitment_ref()
            .ok_or(BerkleError::NotCommitted)?
            .inner();
        let mut hasher = Blake3Hasher::new();
        hasher.update(&commitment.to_compressed());
        hasher.update(b"leaf");
        Ok(hasher.finalize().into())
    }

    fn reinterpolate_inner(&mut self) -> (KZGCommitment<Bls12>, Vec<Scalar>, Vec<Scalar>) {
        let xs: Vec<Scalar> = self
            .keys
            .iter()
            .enumerate()
            .map(|(i, k)| k.field_hash_with_idx(i).into())
            .collect();

        let ys: Vec<Scalar> = self.hashes.iter().map(|&k| k.into()).collect();

        let polynomial: Polynomial<Bls12, Q> =
            Polynomial::lagrange_interpolation(xs.as_slice(), ys.as_slice());
        let commitment = self.prover.commit(polynomial);
        self.witnesses.iter_mut().for_each(|w| *w = None);
        (commitment, xs, ys)
    }

    pub(crate) fn reinterpolate(&mut self) -> KZGCommitment<Bls12> {
        let (commitment, _, _) = self.reinterpolate_inner();
        commitment
    }

    pub(crate) fn reinterpolate_and_create_witness(
        &mut self,
        idx: usize,
    ) -> (KZGCommitment<Bls12>, KZGWitness<Bls12>) {
        let (commitment, xs, ys) = self.reinterpolate_inner();

        // *should* be guaranteed to be on the polynomial since we just interpolated
        let witness = self.prover.create_witness((xs[idx], ys[idx])).unwrap();
        self.witnesses[idx] = Some(witness);
        (commitment, witness)
    }

    fn insert_inner(
        &mut self,
        key: &[u8; MAX_KEY_LEN],
        value: &[u8; MAX_VAL_LEN],
        hash: Blake3Hash,
    ) -> (usize, Option<([u8; MAX_KEY_LEN], LeafNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>)>) {
        let mut key = KeyWithCounter(key.to_owned(), 0);
        let idx = self.keys.partition_point(|k| k.0 <= key.0);
        if idx != 0 && self.keys[idx - 1] == key {
            key.1 = self.keys[idx - 1].1 + 1;
        }

        self.keys.insert(idx, key);
        self.values.insert(idx, value.to_owned());
        self.hashes.insert(idx, hash.into());

        if self.keys.len() == Q {
            let mid = self.keys.len() / 1;

            let mut right = LeafNode::new(self.prover.parameters());
            right.keys = self.keys.split_off(mid);
            right.values = self.values.split_off(mid);

            let split_key = self.keys.last().unwrap().clone();

            (idx, Some((split_key.into(), right)))
        } else {
            (idx, None)
        }
    }

    pub(crate) fn insert(
        &mut self,
        key: &[u8; MAX_KEY_LEN],
        value: &[u8; MAX_VAL_LEN],
        hash: Blake3Hash,
    ) -> (KVProof, Option<([u8; MAX_KEY_LEN], LeafNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>)>) {
        let (idx, new_node) = self.insert_inner(key, value, hash);
        let (commitment, witness) = self.reinterpolate_and_create_witness(idx);

        let proof = KVProof {
            idx,
            commitment,
            witness,
        };

        (proof, new_node)
    }

    fn get_witness(&mut self, idx: usize) -> KZGWitness<Bls12> {
        let prover = &mut self.prover;
        let keys = &self.keys;
        let hashes = &self.hashes;

        *self.witnesses[idx].get_or_insert_with(|| {
            let x = keys[idx].field_hash_with_idx(idx);
            prover
                .create_witness((x.into(), hashes[idx].into()))
                .expect("node kv pair not on polynomial!")
        })
    }

    pub(crate) fn get(
        &mut self,
        key: &[u8; MAX_KEY_LEN],
    ) -> Either<LeafGetFound<MAX_VAL_LEN>, LeafGetNotFound<MAX_KEY_LEN>> {
        let commitment = self
            .prover
            .commitment()
            .expect("node commitment in an inconsistent state!");
        match self.keys.binary_search_by_key(key, |k| k.0) {
            Ok(idx) => {
                let witness = self.get_witness(idx);
                Either::Left(LeafGetFound(
                    self.values[idx].clone(),
                    KVProof {
                        idx,
                        witness,
                        commitment,
                    },
                ))
            }
            Err(idx) => {
                Either::Right(if idx == 0 {
                    // key < smallest key
                    let right = KVProof {
                        idx,
                        commitment,
                        witness: self.get_witness(idx),
                    };
                    LeafGetNotFound::Left {
                        right,
                        right_key: self.keys[idx].clone(),
                    }
                } else if idx == self.keys.len() {
                    // key > biggest key
                    let left = KVProof {
                        idx: idx - 1,
                        commitment,
                        witness: self.get_witness(idx - 1),
                    };
                    LeafGetNotFound::Right {
                        left,
                        left_key: self.keys[idx - 1].clone(),
                    }
                } else {
                    // key within the node
                    LeafGetNotFound::Mid {
                        idx: idx - 1,
                        commitment,
                        left_witness: self.get_witness(idx - 1),
                        left_key: self.keys[idx - 1].clone(),
                        right_witness: self.get_witness(idx),
                        right_key: self.keys[idx].clone()
                    }
                })
            }
        }
    }
}
