use bitvec::prelude::*;
use kzg::{
    polynomial::Polynomial, KZGBatchWitness, KZGCommitment, KZGParams, KZGProver, KZGWitness,
};
use std::{
    convert::{TryFrom, TryInto},
    fmt,
    fmt::{Debug, Formatter},
    ops::Range,
    process::Child,
};

use blake3::{Hash as Blake3Hash, Hasher as Blake3Hasher};
use bls12_381::{Bls12, Scalar};
use either::Either;

use crate::error::{BerkleError, NodeConvertError};
use crate::proofs::{
    ContainsResult, GetResult, InnerNodeProof, KVProof, MembershipProof, NonMembershipProof,
    RangeResult,
};
use crate::{null_key, FieldHash, KeyWithCounter};

/// enum reprenting the different kinds of nodes for
#[derive(Clone)]
pub enum Node<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> 
{
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

pub(crate) enum ChildOrValue<
    'params,
    const Q: usize,
    const MAX_KEY_LEN: usize,
    const MAX_VAL_LEN: usize,
> 
{
    Value([u8; MAX_VAL_LEN], Blake3Hash),
    Child(Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>),
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

pub(crate) type RangeProofTuple = (
    Vec<BitVec>,
    Vec<Vec<KZGBatchWitness<Bls12>>>,
    Vec<Vec<KZGCommitment<Bls12>>>,
);

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

    pub(crate) fn len(&self) -> usize {
        match self {
            Node::Internal(node) => node.keys.len(),
            Node::Leaf(node) => node.keys.len(),
        }
    }

    pub(crate) fn split_front(
        &mut self,
        at: usize,
    ) -> (
        Vec<KeyWithCounter<MAX_KEY_LEN>>,
        Vec<ChildOrValue<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>>,
    ) {
        match self {
            Node::Internal(node) => {
                let new_keys = node.keys.split_off(at);
                let new_children = node.children.split_off(at);

                (
                    std::mem::replace(&mut node.keys, new_keys),
                    std::mem::replace(&mut node.children, new_children)
                        .into_iter()
                        .map(|c| ChildOrValue::Child(c))
                        .collect(),
                )
            }
            Node::Leaf(node) => {
                let new_keys = node.keys.split_off(at);
                let new_values = node.values.split_off(at);
                let new_hashes = node.hashes.split_off(at);

                (
                    std::mem::replace(&mut node.keys, new_keys),
                    std::mem::replace(&mut node.values, new_values)
                        .into_iter()
                        .zip(std::mem::replace(&mut node.hashes, new_hashes).into_iter())
                        .map(|(val, hash)| ChildOrValue::Value(val, hash))
                        .collect(),
                )
            }
        }
    }

    pub(crate) fn get_batch_witness(&self, idxs: Range<usize>) -> KZGBatchWitness<Bls12> {
        match self {
            Node::Internal(node) => node.get_batch_witness(idxs),
            Node::Leaf(node) => node.get_batch_witness(idxs),
        }
    }

    pub(crate) fn split_back(
        &mut self,
        at: usize,
    ) -> (
        Vec<KeyWithCounter<MAX_KEY_LEN>>,
        Vec<ChildOrValue<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>>,
    ) {
        match self {
            Node::Internal(node) => (
                node.keys.split_off(at),
                node.children
                    .split_off(at)
                    .into_iter()
                    .map(|c| ChildOrValue::Child(c))
                    .collect(),
            ),
            Node::Leaf(node) => (
                node.keys.split_off(at),
                node.values
                    .split_off(at)
                    .into_iter()
                    .zip(node.hashes.split_off(at).into_iter())
                    .map(|(val, hash)| ChildOrValue::Value(val, hash))
                    .collect(),
            ),
        }
    }

    pub(crate) fn merge_from_left(
        &mut self,
        other: Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>,
        split_key: KeyWithCounter<MAX_KEY_LEN>,
    ) {
        match (self, other) {
            (Node::Internal(node), Node::Internal(other)) => {
                let mut old_keys = std::mem::replace(&mut node.keys, other.keys);
                let old_children = std::mem::replace(&mut node.children, other.children);

                old_keys[0] = split_key;

                node.keys.extend(old_keys);
                node.children.extend(old_children);
            }
            (Node::Leaf(node), Node::Leaf(other)) => {
                let old_keys = std::mem::replace(&mut node.keys, other.keys);
                let old_values = std::mem::replace(&mut node.values, other.values);
                let old_hashes = std::mem::replace(&mut node.hashes, other.hashes);

                node.keys.extend(old_keys);
                node.values.extend(old_values);
                node.hashes.extend(old_hashes);
            }
            _ => panic!("should never happen - all leaf nodes must be on the same level!"),
        }
    }

    pub(crate) fn merge_from_right(
        &mut self,
        other: Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>,
        split_key: KeyWithCounter<MAX_KEY_LEN>,
    ) {
        match (self, other) {
            (Node::Internal(node), Node::Internal(other)) => {
                let mut keys = other.keys;
                keys[0] = split_key;
                node.keys.extend(keys);
                node.children.extend(other.children);
            }
            (Node::Leaf(node), Node::Leaf(other)) => {
                node.keys.extend(other.keys);
                node.values.extend(other.values);
                node.hashes.extend(other.hashes);
            }
            _ => panic!("should never happen - all leaf nodes must be on the same level!"),
        }
    }

    pub(crate) fn append(
        &mut self,
        front: bool,
        keys: Vec<KeyWithCounter<MAX_KEY_LEN>>,
        values: Vec<ChildOrValue<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>>,
    ) -> KeyWithCounter<MAX_KEY_LEN> {
        match self {
            Node::Internal(node) => {
                let children = values
                    .into_iter()
                    .map(|c| match c {
                        ChildOrValue::Child(c) => c,
                        _ => panic!("should never happen!"),
                    })
                    .collect();
                if front {
                    let old_keys = std::mem::replace(&mut node.keys, keys);
                    let old_children = std::mem::replace(&mut node.children, children);

                    node.keys.extend(old_keys);
                    node.children.extend(old_children);
                } else {
                    node.keys.extend(keys);
                    node.children.extend(children);
                }

                node.keys[0].clone()
            }
            Node::Leaf(node) => {
                let mut values_vec = Vec::with_capacity(values.len());
                let mut hashes_vec = Vec::with_capacity(values.len());
                values
                    .into_iter()
                    .map(|v| match v {
                        ChildOrValue::Value(value, hash) => (value, hash),
                        _ => panic!("should never happen!"),
                    })
                    .for_each(|(value, hash)| {
                        values_vec.push(value);
                        hashes_vec.push(hash);
                    });

                let values = values_vec;
                let hashes = hashes_vec;

                if front {
                    let old_keys = std::mem::replace(&mut node.keys, keys);
                    let old_values = std::mem::replace(&mut node.values, values);
                    let old_hashes = std::mem::replace(&mut node.hashes, hashes);

                    node.keys.extend(old_keys);
                    node.values.extend(old_values);
                    node.hashes.extend(old_hashes);
                } else {
                    node.keys.extend(keys);
                    node.values.extend(values);
                    node.hashes.extend(hashes);
                }

                node.keys[0].clone()
            }
        }
    }

    pub(crate) fn insert(
        &mut self,
        key: &KeyWithCounter<MAX_KEY_LEN>,
        value: &[u8; MAX_VAL_LEN],
        hash: Blake3Hash,
    ) -> (
        MembershipProof<MAX_KEY_LEN>,
        Option<(
            KeyWithCounter<MAX_KEY_LEN>,
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
                    LeafGetNotFound::Left {
                        right,
                        right_key,
                        right_value,
                    } => NonMembershipProof::Edge {
                        is_left: true,
                        path: Vec::new(),
                        commitments: Vec::new(),
                        leaf_proof: right,
                        key: right_key,
                        value: right_value,
                    },
                    LeafGetNotFound::Right {
                        left,
                        left_key,
                        left_value,
                    } => NonMembershipProof::Edge {
                        is_left: false,
                        path: Vec::new(),
                        commitments: Vec::new(),
                        leaf_proof: left,
                        key: left_key,
                        value: left_value,
                    },
                }),
            },
        }
    }

    pub(crate) fn delete(
        &mut self,
        key: &[u8; MAX_KEY_LEN],
        idxs: &[usize],
    ) -> (([u8; MAX_VAL_LEN], Blake3Hash), usize, bool) {
        match self {
            Node::Internal(node) => {
                let idx = idxs[0];

                let mut res = node.children[idx].delete(key, &idxs[1..]);
                res.1 = idx;

                match res {
                    ((value, hash), idx, false) => ((value, hash), idx, false),
                    // handle merge
                    ((value, hash), idx, true) => ((value, hash), idx, node.merge_child(idx)),
                }
            }
            Node::Leaf(node) => node.delete(key),
        }
    }

    fn compute_subtree_range_proof(&self, level: usize) -> RangeProofTuple {
        match self {
            Node::Internal(ref node) => node.children.iter().fold(
                (vec![BitVec::new()], vec![Vec::new()], vec![Vec::new()]),
                |(mut bvs, mut witnesses, mut commitments), child| {
                    let (next_bvs, next_witnesses, next_commitments) =
                        child.compute_subtree_range_proof(level + 1);

                    if bvs.len() < next_bvs.len() {
                        bvs.extend(vec![BitVec::new(); next_bvs.len() - bvs.len()]);
                        witnesses.extend(vec![Vec::new(); next_witnesses.len() - witnesses.len()]);
                        commitments.extend(vec![Vec::new(); next_commitments.len() - commitments.len()]);
                    }

                    bvs.iter_mut()
                        .zip(next_bvs.iter())
                        .for_each(|(dst, src)| dst.extend(src));
                    witnesses
                        .iter_mut()
                        .zip(next_witnesses.iter())
                        .for_each(|(dst, src)| dst.extend_from_slice(src.as_slice()));
                    commitments
                        .iter_mut()
                        .zip(next_commitments.iter())
                        .for_each(|(dst, src)| dst.extend(src));

                    let mut bv = bitvec![0; node.keys.len()];
                    *(bv.as_mut_bitslice().get_mut(0).unwrap()) = true;
                    *(bv.as_mut_bitslice().get_mut(node.keys.len() - 1).unwrap()) = true;

                    witnesses[level].push(node.get_batch_witness(0..node.keys.len()));
                    commitments[level].push(node.prover.commitment().unwrap());
                    bvs[level].extend(bv);

                    (bvs, witnesses, commitments)
                },
            ),
            Node::Leaf(ref node) => {
                let mut bvs = vec![BitVec::new(); level + 1];
                let mut bv = bitvec![0; node.keys.len()];
                let mut witnesses = vec![Vec::new(); level + 1];
                let mut commitments = vec![Vec::new(); level + 1];

                *(bv.as_mut_bitslice().get_mut(0).unwrap()) = true;
                *(bv.as_mut_bitslice().get_mut(node.keys.len() - 1).unwrap()) = true;
                bvs[level] = bv;

                witnesses[level].push(node.get_batch_witness(0..node.keys.len()));
                commitments[level].push(node.prover.commitment().unwrap());

                (bvs, witnesses, commitments)
            }
        }
    }

    fn compute_range_edge_proof(
        &self,
        is_left: bool,
        path: &[usize],
        level: usize,
    ) -> RangeProofTuple {
        let idx = path[0];
        println!("edge({}, {})", idx, is_left);
        match self {
            Node::Internal(ref node) => {
                let (left_idx, right_idx, (mut bvs, mut witnesses, mut commitments)) = match is_left
                {
                    true => (
                        idx + 1,
                        node.keys.len(),
                        node.children[idx].compute_range_edge_proof(is_left, &path[1..], level + 1),
                    ),
                    false => (
                        0,
                        idx + 1,
                        node.children[idx].compute_range_edge_proof(is_left, &path[1..], level + 1),
                    ),
                };

                for i in left_idx..right_idx {
                    let (subtree_bvs, subtree_witnesses, subtree_commitments) =
                        node.children[i].compute_subtree_range_proof(level + 1);

                    bvs.iter_mut()
                        .zip(subtree_bvs.iter())
                        .for_each(|(dst, src)| dst.extend(src));
                    witnesses
                        .iter_mut()
                        .zip(subtree_witnesses.iter())
                        .for_each(|(dst, src)| dst.extend_from_slice(src.as_slice()));
                    commitments
                        .iter_mut()
                        .zip(subtree_commitments.iter())
                        .for_each(|(dst, src)| dst.extend(src));
                }

                let mut bv = bitvec![0; right_idx - left_idx];
                *(bv.as_mut_bitslice().get_mut(0).unwrap()) = true;
                *(bv.as_mut_bitslice().get_mut(right_idx - left_idx - 1).unwrap()) = true;

                bvs[level].extend(bv);

                witnesses[level].push(node.get_batch_witness(left_idx..right_idx));
                commitments[level].push(node.prover.commitment().unwrap());

                (bvs, witnesses, commitments)
            }
            Node::Leaf(ref node) => {
                let mut bvs = vec![BitVec::new(); level + 1];
                let mut witnesses = vec![Vec::new(); level + 1];
                let mut commitments = vec![Vec::new(); level + 1];

                if is_left {
                    witnesses[level].push(node.get_batch_witness(idx..node.keys.len()));
                } else {
                    witnesses[level].push(node.get_batch_witness(0..idx));
                }

                commitments[level].push(node.prover.commitment().unwrap());

                let mut bv = bitvec![0; node.keys.len()];
                *(bv.as_mut_bitslice().get_mut(0).unwrap()) = true;
                *(bv.as_mut_bitslice().get_mut(node.keys.len() - 1).unwrap()) = true;
                bvs[level] = bv;

                match is_left {
                    true => (bvs, witnesses, commitments),
                    false => (bvs, witnesses, commitments),
                }
            }
        }
    }

    pub(crate) fn compute_range_proof(
        &self,
        left_path: &[usize],
        right_path: &[usize],
        level: usize,
    ) -> RangeProofTuple {
        let left = left_path[0];
        let right = right_path[0];
        println!("outer({}, {})", left, right);

        match self {
            Node::Internal(ref node) => {
                if left == right {
                    node.children[left].compute_range_proof(
                        &left_path[1..],
                        &right_path[1..],
                        level + 1,
                    )
                } else {
                    let (mut bvs, mut witnesses, mut commitments) = node.children[left]
                        .compute_range_edge_proof(true, &left_path[1..], level + 1);
                    let (right_bvs, right_witnesses, right_commitments) = node.children[right]
                        .compute_range_edge_proof(false, &right_path[1..], level + 1);

                    for i in left..right {
                        let (subtree_bvs, subtree_witnesses, subtree_commitments) =
                            node.children[i].compute_subtree_range_proof(level + 1);

                        bvs.iter_mut()
                            .zip(subtree_bvs.iter())
                            .for_each(|(dst, src)| dst.extend(src));
                        witnesses
                            .iter_mut()
                            .zip(subtree_witnesses.iter())
                            .for_each(|(dst, src)| dst.extend_from_slice(src.as_slice()));
                        commitments
                            .iter_mut()
                            .zip(subtree_commitments)
                            .for_each(|(dst, src)| dst.extend(src));
                    }

                    bvs.iter_mut()
                        .zip(right_bvs.iter())
                        .for_each(|(dst, src)| dst.extend(src));
                    witnesses
                        .iter_mut()
                        .zip(right_witnesses.iter())
                        .for_each(|(dst, src)| dst.extend_from_slice(src.as_slice()));
                    commitments
                        .iter_mut()
                        .zip(right_commitments)
                        .for_each(|(dst, src)| dst.extend(src));

                    let mut bv = bitvec![0; node.keys.len()];
                    *(bv.as_mut_bitslice().get_mut(0).unwrap()) = true;
                    *(bv.as_mut_bitslice().get_mut(node.keys.len() - 1).unwrap()) = true;

                    bvs[level].extend(bv);
                    witnesses[level].push(node.get_batch_witness(left..(right + 1)));
                    commitments[level].push(node.prover.commitment().unwrap());

                    (bvs, witnesses, commitments)
                }
            }
            Node::Leaf(ref node) => {
                let mut bvs = vec![BitVec::new(); level + 1];
                let mut commitments = vec![Vec::new(); level + 1];
                let mut witnesses = vec![Vec::new(); level + 1];

                let mut bv = bitvec![0; node.keys.len()];
                *(bv.as_mut_bitslice().get_mut(0).unwrap()) = true;
                *(bv.as_mut_bitslice().get_mut(node.keys.len() - 1).unwrap()) = true;

                witnesses[level].push(node.get_batch_witness(left..(right + 1)));
                commitments[level].push(node.prover.commitment().unwrap());
                bvs[level] = bv;

                (bvs, witnesses, commitments)
            }
        }
    }

    pub(crate) fn get_by_path(
        &self,
        path: &[usize],
    ) -> (KeyWithCounter<MAX_KEY_LEN>, [u8; MAX_VAL_LEN]) {
        let idx = path[0];
        match self {
            Node::Internal(node) => node.children[idx].get_by_path(&path[1..]),
            Node::Leaf(node) => (node.keys[idx].clone(), node.values[idx].clone()),
        }
    }

    pub(crate) fn advance_path_by_one(
        &self,
        path: &mut [usize],
    ) -> Option<(KeyWithCounter<MAX_KEY_LEN>, [u8; MAX_VAL_LEN])> {
        let mut idx = path[0];
        match self {
            Node::Internal(node) => loop {
                if idx == node.keys.len() {
                    idx = 0;
                    path[0] = idx;
                    break None;
                }

                let res = node.children[idx].advance_path_by_one(&mut path[1..]);
                if res.is_some() {
                    path[0] = idx;
                    break res;
                } else {
                    idx += 1;
                }
            },
            Node::Leaf(node) => {
                if idx == node.keys.len() {
                    idx = 0;
                    path[0] = idx;
                    None
                } else {
                    let res = Some((node.keys[idx].clone(), node.values[idx].clone()));
                    idx += 1;
                    path[0] = idx;
                    res
                }
            }
        }
    }
}

impl<const MAX_KEY_LEN: usize> KeyWithCounter<MAX_KEY_LEN> {
    pub(crate) fn hash(&self) -> Blake3Hash {
        let mut hasher = Blake3Hasher::new();
        hasher.update(&self.0);
        hasher.update(&self.1.to_le_bytes());
        hasher.finalize()
    }

    pub(crate) fn hash_with_idx(&self, idx: usize) -> Blake3Hash {
        let mut hasher = Blake3Hasher::new();
        hasher.update(&self.0);
        hasher.update(&self.1.to_le_bytes());
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
    pub(crate) batch_witness: Option<KZGBatchWitness<Bls12>>,
    pub(crate) prover: KZGProver<'params, Bls12>,
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
        params: &'params KZGParams<Bls12>,
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

    pub(crate) fn get_batch_witness(&self, idxs: Range<usize>) -> KZGBatchWitness<Bls12> {
        let points: Vec<(Scalar, Scalar)> = idxs
            .map(|idx| {
                (
                    self.keys[idx].field_hash_with_idx(idx).into(),
                    self.children[idx].hash().unwrap().into(),
                )
            })
            .collect();
        self.prover.create_witness_batched(points.as_slice()).unwrap()
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

        let polynomial: Polynomial<Bls12> =
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

    fn get_key_insertion_idx(&self, key: &KeyWithCounter<MAX_KEY_LEN>) -> usize {
        // find the first key it's less than
        self.keys.partition_point(|k| key >= k)
    }

    fn insert_inner(
        &mut self,
        key: &KeyWithCounter<MAX_KEY_LEN>,
        value: &[u8; MAX_VAL_LEN],
        hash: Blake3Hash,
    ) -> (
        usize,
        MembershipProof<MAX_KEY_LEN>,
        Option<(
            KeyWithCounter<MAX_KEY_LEN>,
            InternalNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>,
        )>,
    ) {
        let idx = self.get_key_traversal_idx(&key.0);

        let (proof, new_node) = self.children[idx].insert(key, value, hash);

        if let Some((split_key, child)) = new_node {
            let insertion_idx = self.get_key_insertion_idx(&split_key);

            self.keys.insert(insertion_idx, split_key);
            self.children.insert(insertion_idx, child);

            // after inserting, key may be in a different place
            // this is a naive way of figuring it out, but this is a
            // 'mvp' tree that will likely be rewritten so it's fine
            let idx = self.get_key_traversal_idx(&key.0);

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
        key: &KeyWithCounter<MAX_KEY_LEN>,
        value: &[u8; MAX_VAL_LEN],
        hash: Blake3Hash,
    ) -> (
        MembershipProof<MAX_KEY_LEN>,
        Option<(
            KeyWithCounter<MAX_KEY_LEN>,
            InternalNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>,
        )>,
    ) {
        let (idx, mut proof, mut new_node) = self.insert_inner(key, value, hash);

        let (commitment, inner_proof) = match new_node {
            Some((ref _split_key, ref mut new_node)) => {
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

    pub(crate) fn get_inner(
        &mut self,
        idx: usize,
        key: &[u8; MAX_KEY_LEN],
    ) -> GetResult<MAX_KEY_LEN, MAX_VAL_LEN> {
        match self.children[idx].get(key) {
            GetResult::Found(value, mut proof) => {
                let inner_proof = InnerNodeProof {
                    idx,
                    node_size: self.keys.len(),
                    key: self.keys[idx].clone(),
                    child_hash: self.children[idx].hash().unwrap(),
                    witness: self.get_witness(idx),
                };

                proof.commitments.push(self.prover.commitment().unwrap());
                proof.path.push(inner_proof);

                GetResult::Found(value, proof)
            }
            GetResult::NotFound(proof) => {
                match proof {
                    NonMembershipProof::IntraNode {
                        mut path,
                        mut commitments,

                        leaf_commitment,
                        leaf_size,
                        idx: leaf_idx,

                        left_key,
                        left_value,
                        left_witness,

                        right_key,
                        right_value,
                        right_witness,
                    } => {
                        let inner_proof = InnerNodeProof {
                            idx,
                            node_size: self.keys.len(),
                            key: self.keys[idx].clone(),
                            child_hash: self.children[idx].hash().unwrap(),
                            witness: self.get_witness(idx),
                        };

                        commitments.push(self.prover.commitment().unwrap());
                        path.push(inner_proof);

                        GetResult::NotFound(NonMembershipProof::IntraNode {
                            path,
                            commitments,

                            leaf_commitment,
                            leaf_size,
                            idx: leaf_idx,

                            left_key,
                            left_value,
                            left_witness,

                            right_key,
                            right_value,
                            right_witness,
                        })
                    }
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
                            witness: self.get_witness(idx),
                        };

                        common_path = match common_path {
                            Some(mut common_path) => {
                                common_path.push(inner_proof);
                                Some(common_path)
                            }
                            None => Some(vec![inner_proof]),
                        };

                        common_commitments = match common_commitments {
                            Some(mut common_commitments) => {
                                common_commitments.push(self.prover.commitment().unwrap());
                                Some(common_commitments)
                            }
                            None => Some(vec![self.prover.commitment().unwrap()]),
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
                    }
                    NonMembershipProof::Edge {
                        is_left,
                        mut path,
                        mut commitments,
                        leaf_proof,
                        key: leaf_key,
                        value,
                    } => {
                        println!("(edge) is_left: {}, idx: {}", is_left, idx);
                        if is_left && idx > 0 {
                            // if we didn't find it, but we get a left edge and it's not the first key, backtrack

                            // if result of backtrack is NotFound::Edge on the right,
                            // then the key is between child[idx - 1] and child[idx],
                            // in which case we return an InterNodeProof

                            // if result of backtrack is NotFound::Edge on the left,
                            // continue backtracking (recursive case)

                            // otherwise, simply return the result

                            let res = self.get_inner(idx - 1, key);
                            if let GetResult::NotFound(NonMembershipProof::Edge {
                                is_left: false,
                                path: mut left_path,
                                commitments: mut left_commitments,
                                leaf_proof: left_leaf_proof,
                                key: left_key,
                                value: left_value,
                            }) = res
                            {
                                let left_inner_proof = InnerNodeProof {
                                    idx: idx - 1,
                                    node_size: self.keys.len(),
                                    key: self.keys[idx - 1].clone(),
                                    child_hash: self.children[idx - 1].hash().unwrap(),
                                    witness: self.get_witness(idx - 1),
                                };
                                let inner_proof = InnerNodeProof {
                                    idx,
                                    node_size: self.keys.len(),
                                    key: self.keys[idx].clone(),
                                    child_hash: self.children[idx].hash().unwrap(),
                                    witness: self.get_witness(idx),
                                };

                                left_path.push(left_inner_proof);
                                path.push(inner_proof);

                                left_commitments.push(self.prover.commitment().unwrap());
                                commitments.push(self.prover.commitment().unwrap());

                                GetResult::NotFound(NonMembershipProof::InterNode {
                                    common_commitments: None,
                                    common_path: None,

                                    left: left_leaf_proof,
                                    left_key,
                                    left_value,
                                    left_path,
                                    left_commitments,

                                    right: leaf_proof,
                                    right_key: leaf_key,
                                    right_value: value,
                                    right_path: path,
                                    right_commitments: commitments,
                                })
                            } else {
                                // otherwise, just return the result up
                                res
                            }
                        } else if !is_left && idx < self.keys.len() - 1 {
                            // if it's not the last key but it's a right edge and we're not backtracking, then it's an InterNode proof
                            match self.children[idx + 1].get(key) {
                                GetResult::NotFound(NonMembershipProof::Edge {
                                    is_left: true,
                                    path: mut right_path,
                                    commitments: mut right_commitments,
                                    leaf_proof: right_leaf_proof,
                                    key: right_key,
                                    value: right_value,
                                }) => {
                                    let right_inner_proof = InnerNodeProof {
                                        idx: idx + 1,
                                        node_size: self.keys.len(),
                                        key: self.keys[idx + 1].clone(),
                                        child_hash: self.children[idx + 1].hash().unwrap(),
                                        witness: self.get_witness(idx + 1),
                                    };
                                    let inner_proof = InnerNodeProof {
                                        idx,
                                        node_size: self.keys.len(),
                                        key: self.keys[idx].clone(),
                                        child_hash: self.children[idx].hash().unwrap(),
                                        witness: self.get_witness(idx),
                                    };

                                    right_path.push(right_inner_proof);
                                    path.push(inner_proof);

                                    right_commitments.push(self.prover.commitment().unwrap());
                                    commitments.push(self.prover.commitment().unwrap());

                                    GetResult::NotFound(NonMembershipProof::InterNode {
                                        common_commitments: None,
                                        common_path: None,

                                        left: leaf_proof,
                                        left_key: leaf_key,
                                        left_value: value,
                                        left_path: path,
                                        left_commitments: commitments,

                                        right: right_leaf_proof,
                                        right_key,
                                        right_value,
                                        right_path: right_path,
                                        right_commitments,
                                    })
                                }
                                // no other case should occur if the B+ tree is properly sorted
                                _ => panic!("should never happen!"),
                            }
                        } else {
                            let inner_proof = InnerNodeProof {
                                idx,
                                node_size: self.keys.len(),
                                key: self.keys[idx].clone(),
                                child_hash: self.children[idx].hash().unwrap(),
                                witness: self.get_witness(idx),
                            };

                            path.push(inner_proof);
                            commitments.push(self.prover.commitment().unwrap());

                            GetResult::NotFound(NonMembershipProof::Edge {
                                is_left,
                                path,
                                commitments,
                                leaf_proof,
                                key: leaf_key,
                                value,
                            })
                        }
                    }
                }
            }
        }
    }

    pub(crate) fn get(&mut self, key: &[u8; MAX_KEY_LEN]) -> GetResult<MAX_KEY_LEN, MAX_VAL_LEN> {
        let idx = self.get_key_traversal_idx(key);
        // println!(
        //     "(internal) get({:?}), keys: {:?}, node_size: {}, idx: {}",
        //     key,
        //     &self.keys,
        //     self.keys.len(),
        //     idx
        // );
        self.get_inner(idx, key)
    }

    // merges child i with adjacent nodes to maintain invariant
    // returns (true, true) if self needs to be merged after merging its child
    pub(crate) fn merge_child(&mut self, idx: usize) -> bool {
        // println!("{}", self.children[idx].len());
        // number of keys children[idx] needs to satisfy invariant
        let deficit = Q / 2 - self.children[idx].len();

        println!(
            "(merge_child, before) self.keys: {:?}, idx: {}",
            &self.keys, idx
        );

        if idx > 0 && self.children[idx - 1].len() - deficit >= Q / 2 {
            println!("0");
            // if left child has enough keys to spare, move them and update split key

            let split_idx = self.children[idx - 1].len() - deficit;
            let (keys, values) = self.children[idx - 1].split_back(split_idx);
            let split_key = keys[0].clone();

            self.children[idx].append(true, keys, values);
            self.children[idx - 1].reinterpolate();
            self.children[idx].reinterpolate();

            self.keys[idx] = split_key;
        } else if idx < self.children.len() - 1 && self.children[idx + 1].len() - deficit >= Q / 2 {
            println!("1");
            // else if right child has enough keys to spare, move them and update split key

            let split_idx = deficit;

            let (mut keys, values) = self.children[idx + 1].split_front(split_idx);

            keys[0] = self.keys[idx + 1].clone();
            let split_key = match self.children[idx + 1] {
                Node::Internal(ref mut node) => std::mem::replace(&mut node.keys[0], null_key()),
                Node::Leaf(ref node) => node.keys[0].clone(),
            };

            self.children[idx].append(false, keys, values);
            self.children[idx + 1].reinterpolate();
            self.children[idx].reinterpolate();

            self.keys[idx + 1] = split_key;
        } else {
            // else pick the smallest adjacent sibling and merge

            let (removal_idx, is_left) = {
                if idx == 0 {
                    (idx + 1, false)
                } else if idx == self.children.len() - 1 {
                    (idx - 1, true)
                } else if self.children[idx - 1].len() < self.children[idx + 1].len() {
                    (idx - 1, true)
                } else {
                    (idx + 1, false)
                }
            };

            // split key is the right of the two keys of the target node and node were merging from resp.
            if is_left {
                println!("2");
                // since we're merging from the left, split key is the target's keye
                let split_key = self.keys[idx].clone();
                let key = self.keys.remove(removal_idx);
                let child = self.children.remove(removal_idx);

                // previous line moves everything to the left, so target node is at idx-1
                self.children[idx - 1].merge_from_left(child, split_key);
                self.keys[idx - 1] = key;

                self.children[idx - 1].reinterpolate();
            } else {
                println!("3");
                // removed key is the split key since we're merging from the right
                let key = self.keys.remove(removal_idx);
                let child = self.children.remove(removal_idx);

                // previous line does not change idx of target node because it comes after it in the vec
                // so we use children[idx] not children[idx - 1]
                self.children[idx].merge_from_right(child, key);

                self.children[idx].reinterpolate();
            }
        }
        
        self.reinterpolate();

        self.keys.len() < Q / 2
    }
}

#[derive(Clone)]
pub struct LeafNode<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize>
{
    // INVARIANT: children.len() == keys.len()
    pub(crate) keys: Vec<KeyWithCounter<MAX_KEY_LEN>>,
    pub(crate) values: Vec<[u8; MAX_VAL_LEN]>,
    pub(crate) hashes: Vec<Blake3Hash>,
    pub(crate) witnesses: Vec<Option<KZGWitness<Bls12>>>,
    pub(crate) batch_witness: Option<KZGBatchWitness<Bls12>>,
    pub(crate) prover: KZGProver<'params, Bls12>,
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
    pub(crate) fn new(params: &'params KZGParams<Bls12>) -> Self {
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

        let ys: Vec<Scalar> = self
            .hashes
            .iter()
            .map(|&h| FieldHash::from(h).into())
            .collect();

        let polynomial: Polynomial<Bls12> =
            Polynomial::lagrange_interpolation(xs.as_slice(), ys.as_slice());
        let commitment = self.prover.commit(polynomial);
        self.witnesses.iter_mut().for_each(|w| *w = None);
        (commitment, xs, ys)
    }

    pub(crate) fn reinterpolate(&mut self) -> KZGCommitment<Bls12> {
        let (commitment, _, _) = self.reinterpolate_inner();
        commitment
    }

    fn insert_inner(
        &mut self,
        key: &KeyWithCounter<MAX_KEY_LEN>,
        value: &[u8; MAX_VAL_LEN],
        hash: Blake3Hash,
    ) -> (
        usize,
        Option<(
            KeyWithCounter<MAX_KEY_LEN>,
            LeafNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>,
        )>,
    ) {
        let idx = self.keys.partition_point(|k| key >= k);

        self.keys.insert(idx, key.to_owned());
        self.values.insert(idx, value.to_owned());
        self.hashes.insert(idx, hash);

        if self.keys.len() > Q {
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
        key: &KeyWithCounter<MAX_KEY_LEN>,
        value: &[u8; MAX_VAL_LEN],
        hash: Blake3Hash,
    ) -> (
        KVProof,
        Option<(
            KeyWithCounter<MAX_KEY_LEN>,
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
                .create_witness((x.into(), FieldHash::from(hashes[idx]).into()))
                .expect("node kv pair not on polynomial!")
        })
    }

    fn get_batch_witness(&self, idxs: Range<usize>) -> KZGBatchWitness<Bls12> {
        println!("(leaf) idxs: {:?}, node_size: {:?}", &idxs, self.keys.len());
        let points: Vec<(Scalar, Scalar)> = idxs
            .map(|idx| {
                (
                    self.keys[idx].field_hash_with_idx(idx).into(),
                    FieldHash::from(self.hashes[idx]).into(),
                )
            })
            .collect();
        self.prover.create_witness_batched(points.as_slice()).unwrap()
    }

    pub(crate) fn get(
        &mut self,
        key: &[u8; MAX_KEY_LEN],
    ) -> Either<LeafGetFound<MAX_VAL_LEN>, LeafGetNotFound<MAX_KEY_LEN, MAX_VAL_LEN>> {
        // println!(
        //     "(leaf) get({:?}) keys: {:?}, node_size: {}",
        //     key,
        //     &self.keys,
        //     self.keys.len()
        // );
        let commitment = self
            .prover
            .commitment()
            .expect("node commitment in an inconsistent state!");
        match self.keys.binary_search_by_key(key, |k| k.0) {
            Ok(idx) => {
                // println!("hi");
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
                    // println!("howdy 0");
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
                        right_value: self.values[idx].clone(),
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
                        left_value: self.values[idx - 1].clone(),
                    }
                } else {
                    // println!(
                    //     "left: {:?}, right: {:?}",
                    //     &self.keys[idx - 1],
                    //     &self.keys[idx]
                    // );
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
                        right_value: self.values[idx].clone(),
                    }
                })
            }
        }
    }

    pub(crate) fn delete(
        &mut self,
        key: &[u8; MAX_KEY_LEN],
    ) -> (([u8; MAX_VAL_LEN], Blake3Hash), usize, bool) {
        let idx = self
            .keys
            .binary_search_by_key(key, |k| k.0)
            .expect("key not found!");

        let _key = self.keys.remove(idx);
        let value = self.values.remove(idx);
        let hash = self.hashes.remove(idx);

        // tell parent we need to merge
        if self.keys.len() < Q / 2 {
            ((value, hash), idx, true)
        } else {
            ((value, hash), idx, false)
        }
    }
}
