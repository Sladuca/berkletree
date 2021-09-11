use kzg::{
    polynomial::Polynomial, KZGBatchWitness, KZGCommitment, KZGParams, KZGProver, KZGWitness,
};
use std::{
    convert::{TryFrom, TryInto},
    fmt,
    fmt::{Debug, Formatter},
};

use blake3::{Hash as Blake3Hash, Hasher as Blake3Hasher};
use bls12_381::{Bls12, Scalar};
use either::Either;

use crate::error::{BerkleError, NodeConvertError};
use crate::proofs::{
    ContainsResult, GetResult, InnerNodeProof, KVProof, MembershipProof, NonMembershipProof,
    RangeIter, RangeResult,
};
use crate::{null_key, FieldHash, KeyWithCounter};

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

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> Debug
    for Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>
{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Node::Internal(node) => f
                .debug_struct("InternalNode")
                .field("entries", node)
                .finish(),
            Node::Leaf(node) => f.debug_struct("LeafNode").field("entries", node).finish(),
        }
    }
}

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize>
    Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>
{
    pub(crate) fn hash(&self) -> Result<FieldHash, BerkleError> {
        match self {
            Node::Internal(node) => node.hash(),
            Node::Leaf(node) => node.hash(),
        }
    }

    pub(crate) fn reinterpolate(&mut self) -> KZGCommitment<Bls12> {
        match self {
            Node::Internal(node) => node.reinterpolate(),
            Node::Leaf(node) => node.reinterpolate(),
        }
    }

    pub(crate) fn insert(
        &mut self,
        key: &[u8; MAX_KEY_LEN],
        value: &[u8; MAX_VAL_LEN],
        hash: Blake3Hash,
    ) -> (
        MembershipProof<MAX_KEY_LEN>,
        Option<(
            [u8; MAX_KEY_LEN],
            Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>,
        )>,
    ) {
        match self {
            Node::Internal(node) => {
                let (proof, new_node) = node.insert(key, value, hash);

                match new_node {
                    Some((key, node)) => (proof, Some((key, node.into()))),
                    None => (proof, None),
                }
            }
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
                        leaf_size,
                        commitment,

                        left_witness,
                        left_key,
                        left_value,
                        right_witness,
                        right_key,
                        right_value,
                    } => NonMembershipProof::IntraNode {
                        path: Vec::new(),
                        commitments: Vec::new(),

                        leaf_commitment: commitment,
                        leaf_size,
                        idx,
                        left_key,
                        left_value,
                        left_witness,
                        right_key,
                        right_value,
                        right_witness,
                    },
                    LeafGetNotFound::Left { right, right_key, right_value} => NonMembershipProof::Edge {
                        is_left: true,
                        path: Vec::new(),
                        commitments: Vec::new(),
                        leaf_proof: right,
                        key: right_key,
                        value: right_value
                    },
                    LeafGetNotFound::Right { left, left_key, left_value } => NonMembershipProof::Edge {
                        is_left: false,
                        path: Vec::new(),
                        commitments: Vec::new(),
                        leaf_proof: left,
                        key: left_key,
                        value: left_value
                    },
                }),
            },
        }
    }

    pub(crate) fn contains_key(&self, key: &[u8; MAX_KEY_LEN]) -> ContainsResult<MAX_KEY_LEN, MAX_VAL_LEN> {
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
    // INVARIANT: children.len() == keys.len()
    // the ith key is >= than all keys in the ith child but < all keys in the i+1th child
    pub(crate) keys: Vec<KeyWithCounter<MAX_KEY_LEN>>,
    pub(crate) children: Vec<Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>>,
    // witnesses are lazily-computed - none if any particular witness hasn't been computed yet.
    pub(crate) witnesses: Vec<Option<KZGWitness<Bls12>>>,
    pub(crate) batch_witness: Option<KZGBatchWitness<Bls12, Q>>,
    pub(crate) prover: KZGProver<'params, Bls12, Q>,
}

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> Debug
    for InternalNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut m = &mut f.debug_map();
        for (key, child) in self.keys.iter().zip(self.children.iter()) {
            m = m.entry(key, child);
        }

        m.finish()
    }
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
        InternalNode {
            children: vec![left, right],
            keys: vec![null_key(), KeyWithCounter(key, 0)],
            witnesses: vec![None; Q],
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
        hasher.update(&self.keys.len().to_le_bytes());

        Ok(hasher.finalize().into())
    }

    pub(crate) fn get_witness(&mut self, idx: usize) -> KZGWitness<Bls12> {
        if let Some(witness) = self.witnesses[idx] {
            witness
        } else {
            // println!("({:?}, {:?})", &self.keys[idx], match self.children[idx] {
            //     Node::Internal(ref node) => &node.keys[0],
            //     Node::Leaf(ref node) => &node.keys[0]
            // });
            let x = self.keys[idx].field_hash_with_idx(idx).into();
            let y = self.children[idx].hash().unwrap().into();
            let witness = self.prover.create_witness((x, y)).unwrap();
            self.witnesses[idx] = Some(witness);
            witness
        }
    }

    pub(crate) fn reinterpolate_and_create_witness(
        &mut self,
        idx: usize,
    ) -> (KZGCommitment<Bls12>, KZGWitness<Bls12>) {
        let (commitment, xs, ys) = self.reinterpolate_inner();

        // should be guaranteed to be on the polynomial since we just interpolated
        let witness = self.prover.create_witness((xs[idx], ys[idx])).unwrap();
        self.witnesses[idx] = Some(witness);
        (commitment, witness)
    }

    fn reinterpolate_inner(&mut self) -> (KZGCommitment<Bls12>, Vec<Scalar>, Vec<Scalar>) {
        let xs: Vec<Scalar> = self
            .keys
            .iter()
            .enumerate()
            .map(|(i, k)| k.field_hash_with_idx(i).into())
            .collect();

        let ys: Vec<Scalar> = self
            .children
            .iter_mut()
            .map(|child| child.hash().unwrap().into())
            .collect();

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

    fn get_key_traversal_idx(&self, key: &[u8; MAX_KEY_LEN]) -> usize {
        // find the last key that it's not less than
        // in the case of dupes, finds the rightmost dupe
        let idx = self.keys.partition_point(|k| key >= &k.0);
        if idx != 0 {
            idx - 1
        } else {
            idx
        }
    }

    fn get_key_insertion_idx(&self, key: &[u8; MAX_KEY_LEN]) -> usize {
        // find the first key it's less than
        self.keys.partition_point(|k| key >= &k.0)
    }

    fn insert_inner(
        &mut self,
        key: &[u8; MAX_KEY_LEN],
        value: &[u8; MAX_VAL_LEN],
        hash: Blake3Hash,
    ) -> (
        usize,
        MembershipProof<MAX_KEY_LEN>,
        Option<(
            [u8; MAX_KEY_LEN],
            InternalNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>,
        )>,
    ) {
        let idx = self.get_key_traversal_idx(key);

        let (proof, new_node) = self.children[idx].insert(key, value, hash);

        if let Some((split_key, child)) = new_node {
            let insertion_idx = self.get_key_insertion_idx(&split_key);

            let split_key = if insertion_idx != 0 && self.keys[insertion_idx - 1].0 == split_key {
                KeyWithCounter(split_key, self.keys[insertion_idx - 1].1 + 1)
            } else {
                KeyWithCounter(split_key, 0)
            };

            self.keys.insert(insertion_idx, split_key);
            self.children.insert(insertion_idx, child);

            // after inserting, key may be in a different place
            // this is a naive way of figuring it out, but this is a
            // 'mvp' tree that will likely be rewritten so it's fine
            let idx = self.get_key_traversal_idx(key);

            if self.keys.len() > Q {
                let mid = self.keys.len() / 2;

                let mut right_keys = self.keys.split_off(mid);
                let split_key = right_keys[0].clone();
                right_keys[0] = null_key();
                let right_children = self.children.split_off(mid);

                let mut right = InternalNode {
                    children: right_children,
                    keys: right_keys,
                    witnesses: vec![None; Q],
                    batch_witness: None,
                    prover: KZGProver::new(self.prover.parameters()),
                };

                right.reinterpolate();
                self.reinterpolate();

                (idx, proof, Some((split_key.into(), right)))
            } else {
                self.reinterpolate();
                (idx, proof, None)
            }
        } else {
            self.reinterpolate();
            (idx, proof, None)
        }
    }

    pub(crate) fn insert(
        &mut self,
        key: &[u8; MAX_KEY_LEN],
        value: &[u8; MAX_VAL_LEN],
        hash: Blake3Hash,
    ) -> (
        MembershipProof<MAX_KEY_LEN>,
        Option<(
            [u8; MAX_KEY_LEN],
            InternalNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>,
        )>,
    ) {
        let (idx, mut proof, mut new_node) = self.insert_inner(key, value, hash);

        let (commitment, inner_proof) = match new_node {
            Some((_split_key, ref mut new_node)) => {
                if idx >= self.keys.len() {
                    let idx = idx - self.keys.len();
                    let commitment = new_node.prover.commitment().unwrap();
                    let witness = new_node.get_witness(idx);
                    (
                        commitment,
                        InnerNodeProof {
                            idx,
                            node_size: new_node.keys.len(),
                            key: new_node.keys[idx].clone(),
                            child_hash: new_node.children[idx].hash().unwrap(),
                            witness,
                        },
                    )
                } else {
                    let commitment = self.prover.commitment().unwrap();
                    let witness = self.get_witness(idx);
                    (
                        commitment,
                        InnerNodeProof {
                            idx,
                            node_size: self.keys.len(),
                            key: self.keys[idx].clone(),
                            child_hash: self.children[idx].hash().unwrap(),
                            witness,
                        },
                    )
                }
            }
            None => {
                let commitment = self.prover.commitment().unwrap();
                let witness = self.get_witness(idx);
                (
                    commitment,
                    InnerNodeProof {
                        idx: idx,
                        node_size: self.keys.len(),
                        key: self.keys[idx].clone(),
                        child_hash: self.children[idx].hash().unwrap(),
                        witness,
                    },
                )
            }
        };

        proof.commitments.push(commitment);
        proof.path.push(inner_proof);

        (proof, new_node)
    }

    pub(crate) fn get_inner(&mut self, idx: usize, key: &[u8; MAX_KEY_LEN]) -> GetResult<MAX_KEY_LEN, MAX_VAL_LEN> {
        match self.children[idx].get(key) {
            GetResult::Found(value, mut proof) => {
                let inner_proof = InnerNodeProof {
                    idx,
                    node_size: self.keys.len(),
                    key: self.keys[idx].clone(),
                    child_hash: self.children[idx].hash().unwrap(),
                    witness: self.get_witness(idx)
                };

                proof.commitments.push(self.prover.commitment().unwrap());
                proof.path.push(inner_proof);

                GetResult::Found(value, proof)
            }
            GetResult::NotFound(proof) => {
                // backtrack through dupes until we find it or can't
                if idx > 0 && &self.keys[idx - 1].0 == key {
                    self.get_inner(idx - 1, key)
                } else {
                    match proof {
                        NonMembershipProof::IntraNode {
                            mut path,
                            mut commitments,

                            leaf_commitment,
                            leaf_size,
                            idx,

                            left_key,
                            left_value,
                            left_witness,

                            right_key,
                            right_value,
                            right_witness
                        } => {
                            let inner_proof = InnerNodeProof {
                                idx,
                                node_size: self.keys.len(),
                                key: self.keys[idx].clone(),
                                child_hash: self.children[idx].hash().unwrap(),
                                witness: self.get_witness(idx)
                            };

                            commitments.push(self.prover.commitment().unwrap());
                            path.push(inner_proof);

                            GetResult::NotFound(NonMembershipProof::IntraNode {
                                path,
                                commitments,

                                leaf_commitment,
                                leaf_size,
                                idx,

                                left_key,
                                left_value,
                                left_witness,
                                right_key,
                                right_value,
                                right_witness
                            })
                        },
                        NonMembershipProof::InterNode {
                            mut common_path,
                            mut common_commitments,
                            
                            left,
                            left_key,
                            left_value,
                            left_path,
                            left_commitments,

                            right,
                            right_key,
                            right_value,
                            right_path,
                            right_commitments,
                        } => {
                            let inner_proof = InnerNodeProof {
                                idx, 
                                node_size: self.keys.len(),
                                key: self.keys[idx].clone(),
                                child_hash: self.children[idx].hash().unwrap(),
                                witness: self.get_witness(idx)
                            };

                            common_path = match common_path {
                                Some(mut common_path) => {
                                    common_path.push(inner_proof);
                                    Some(common_path)
                                },
                                None => Some(vec![inner_proof])
                            };

                            common_commitments = match common_commitments {
                                Some(mut common_commitments) => {
                                    common_commitments.push(self.prover.commitment().unwrap());
                                    Some(common_commitments)
                                },
                                None => Some(vec![self.prover.commitment().unwrap()])
                            };

                            
                            GetResult::NotFound(NonMembershipProof::InterNode {
                                common_path,
                                common_commitments,

                                left,
                                left_key,
                                left_value,
                                left_path,
                                left_commitments,
                                
                                right,
                                right_key,
                                right_value,
                                right_path,
                                right_commitments,
                            })
                        },
                        NonMembershipProof::Edge {
                            is_left,
                            mut path,
                            mut commitments,
                            leaf_proof,
                            key,
                            value
                        } => {
                            let inner_proof = InnerNodeProof {
                                idx,
                                node_size: self.keys.len(),
                                key: self.keys[idx].clone(),
                                child_hash: self.children[idx].hash().unwrap(),
                                witness: self.get_witness(idx)
                            };

                            path.push(inner_proof);
                            commitments.push(self.prover.commitment().unwrap());

                            GetResult::NotFound(NonMembershipProof::Edge {
                                is_left,
                                path,
                                commitments,
                                leaf_proof,
                                key,
                                value
                            })
                        }
                    }
                }
            }
        }
    }

    pub(crate) fn get(&mut self, key: &[u8; MAX_KEY_LEN]) -> GetResult<MAX_KEY_LEN, MAX_VAL_LEN> {
        let idx = self.get_key_traversal_idx(key);
        self.get_inner(idx, key)
    }
}

#[derive(Clone)]
pub struct LeafNode<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> {
    // INVARIANT: children.len() == keys.len()
    pub(crate) keys: Vec<KeyWithCounter<MAX_KEY_LEN>>,
    pub(crate) values: Vec<[u8; MAX_VAL_LEN]>,
    pub(crate) hashes: Vec<FieldHash>,
    pub(crate) witnesses: Vec<Option<KZGWitness<Bls12>>>,
    pub(crate) batch_witness: Option<KZGBatchWitness<Bls12, Q>>,
    pub(crate) prover: KZGProver<'params, Bls12, Q>,
    // no sibling pointers yet
}

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> Debug
    for LeafNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut m = &mut f.debug_map();
        for (key, value) in self.keys.iter().zip(self.values.iter()) {
            m = m.entry(key, value);
        }

        m.finish()
    }
}

pub(crate) struct LeafGetFound<const MAX_VAL_LEN: usize>([u8; MAX_VAL_LEN], KVProof);
pub(crate) enum LeafGetNotFound<const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> {
    Left {
        right: KVProof,
        right_key: KeyWithCounter<MAX_KEY_LEN>,
        right_value: [u8; MAX_VAL_LEN],
    },
    Right {
        left: KVProof,
        left_key: KeyWithCounter<MAX_KEY_LEN>,
        left_value: [u8; MAX_VAL_LEN],
    },
    Mid {
        idx: usize,
        leaf_size: usize,
        commitment: KZGCommitment<Bls12>,

        left_witness: KZGWitness<Bls12>,
        left_key: KeyWithCounter<MAX_KEY_LEN>,
        left_value: [u8; MAX_VAL_LEN],

        right_witness: KZGWitness<Bls12>,
        right_key: KeyWithCounter<MAX_KEY_LEN>,
        right_value: [u8; MAX_VAL_LEN],
    },
}

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize>
    LeafNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>
{
    /// new *does not* immediately commit
    // for the commitment to occur, you must call commit()
    pub(crate) fn new(params: &'params KZGParams<Bls12, Q>) -> Self {
        LeafNode {
            values: Vec::with_capacity(Q),
            keys: Vec::with_capacity(Q),
            hashes: Vec::with_capacity(Q),
            witnesses: vec![None; Q],
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
        hasher.update(&self.keys.len().to_le_bytes());

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

        // should be guaranteed to be on the polynomial since we just interpolated
        let witness = self.prover.create_witness((xs[idx], ys[idx])).unwrap();
        self.witnesses[idx] = Some(witness);
        (commitment, witness)
    }

    fn insert_inner(
        &mut self,
        key: &[u8; MAX_KEY_LEN],
        value: &[u8; MAX_VAL_LEN],
        hash: Blake3Hash,
    ) -> (
        usize,
        Option<(
            [u8; MAX_KEY_LEN],
            LeafNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>,
        )>,
    ) {
        let mut key = KeyWithCounter(key.to_owned(), 0);
        let idx = self.keys.partition_point(|k| key.0 >= k.0);
        if idx != 0 && self.keys[idx - 1] == key {
            key.1 = self.keys[idx - 1].1 + 1;
        }

        self.keys.insert(idx, key);
        self.values.insert(idx, value.to_owned());
        self.hashes.insert(idx, hash.into());

        if self.keys.len() == Q {
            let mid = self.keys.len() / 2;

            let mut right = LeafNode::new(self.prover.parameters());
            right.keys = self.keys.split_off(mid);
            right.values = self.values.split_off(mid);
            right.hashes = self.hashes.split_off(mid);

            let split_key = right.keys[0].clone();

            self.reinterpolate();
            right.reinterpolate();

            (idx, Some((split_key.into(), right)))
        } else {
            self.reinterpolate();
            (idx, None)
        }
    }

    pub(crate) fn insert(
        &mut self,
        key: &[u8; MAX_KEY_LEN],
        value: &[u8; MAX_VAL_LEN],
        hash: Blake3Hash,
    ) -> (
        KVProof,
        Option<(
            [u8; MAX_KEY_LEN],
            LeafNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>,
        )>,
    ) {
        let (idx, new_node) = self.insert_inner(key, value, hash);

        // if value is in new node, proof needs to come from new node
        match new_node {
            Some((split_key, mut new_node)) => {
                if idx >= self.keys.len() {
                    let idx = idx - self.keys.len();
                    let commitment = new_node.prover.commitment().unwrap();
                    let witness = new_node.get_witness(idx);
                    (
                        KVProof {
                            idx,
                            node_size: new_node.keys.len(),
                            retrieved_key_counter: new_node.keys[idx].1,
                            commitment,
                            witness,
                        },
                        Some((split_key, new_node)),
                    )
                } else {
                    let commitment = self.prover.commitment().unwrap();
                    let witness = self.get_witness(idx);
                    (
                        KVProof {
                            idx,
                            node_size: self.keys.len(),
                            retrieved_key_counter: self.keys[idx].1,
                            commitment,
                            witness,
                        },
                        Some((split_key, new_node)),
                    )
                }
            }
            None => {
                let commitment = self.prover.commitment().unwrap();
                let witness = self.get_witness(idx);
                (
                    KVProof {
                        idx,
                        node_size: self.keys.len(),
                        retrieved_key_counter: self.keys[idx].1,
                        commitment,
                        witness,
                    },
                    None,
                )
            }
        }
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
    ) -> Either<LeafGetFound<MAX_VAL_LEN>, LeafGetNotFound<MAX_KEY_LEN, MAX_VAL_LEN>> {
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
                        node_size: self.keys.len(),
                        retrieved_key_counter: self.keys[idx].1,
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
                        node_size: self.keys.len(),
                        retrieved_key_counter: self.keys[idx].1,
                        commitment,
                        witness: self.get_witness(idx),
                    };
                    LeafGetNotFound::Left {
                        right,
                        right_key: self.keys[idx].clone(),
                        right_value: self.values[idx].clone()
                    }
                } else if idx == self.keys.len() {
                    // key > biggest key
                    let left = KVProof {
                        idx: idx - 1,
                        node_size: self.keys.len(),
                        retrieved_key_counter: self.keys[idx - 1].1,
                        commitment,
                        witness: self.get_witness(idx - 1),
                    };
                    LeafGetNotFound::Right {
                        left,
                        left_key: self.keys[idx - 1].clone(),
                        left_value: self.values[idx].clone()
                    }
                } else {
                    // key within the node
                    LeafGetNotFound::Mid {
                        leaf_size: self.keys.len(),
                        idx: idx - 1,
                        commitment,
                        left_witness: self.get_witness(idx - 1),
                        left_key: self.keys[idx - 1].clone(),
                        left_value: self.values[idx - 1].clone(),
                        right_witness: self.get_witness(idx),
                        right_key: self.keys[idx].clone(),
                        right_value: self.values[idx].clone()
                    }
                })
            }
        }
    }
}
