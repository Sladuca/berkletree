use kzg::{KZGBatchWitness, KZGCommitment, KZGParams, KZGProver, KZGWitness};
use std::convert::{TryFrom};
use bytes::Bytes;
use blake3::{Hash as Blake3Hash};
use bls12_381::{Bls12, Scalar};
use either::Either;

use crate::{FieldHash, GetResult, KVProof, MembershipProof, Offset, RangeResult, ContainsResult, NonMembershipProof, RangeIter};
use crate::error::{NodeConvertError, BerkleError};

/// enum reprenting the different kinds of nodes for
#[derive(Clone)]
pub enum Node<'params, const Q: usize> {
    Internal(InternalNode<'params, Q>),
    Leaf(LeafNode<'params, Q>),
}

impl<'params, const Q: usize> From<InternalNode<'params, Q>> for Node<'params, Q> {
    fn from(node: InternalNode<'params, Q>) -> Self {
        Node::Internal(node)
    }
}

impl<'params, const Q: usize> From<LeafNode<'params, Q>> for Node<'params, Q> {
    fn from(node: LeafNode<'params, Q>) -> Self {
        Node::Leaf(node)
    }
}

impl<'params, const Q: usize> TryFrom<Node<'params, Q>> for LeafNode<'params, Q> {
    type Error = NodeConvertError;
    fn try_from(node: Node<'params, Q>) -> Result<Self, NodeConvertError> {
        match node {
            Node::Leaf(node) => Ok(node),
            _ => Err(NodeConvertError::NotLeafNode),
        }
    }
}

impl<'params, const Q: usize> TryFrom<Node<'params, Q>> for InternalNode<'params, Q> {
    type Error = NodeConvertError;
    fn try_from(node: Node<'params, Q>) -> Result<Self, NodeConvertError> {
        match node {
            Node::Internal(node) => Ok(node),
            _ => Err(NodeConvertError::NotInternalNode),
        }
    }
}

impl<'params, const Q: usize> Node<'params, Q> {
	pub fn insert<K>(&mut self, key: K, value: Offset, hash: Blake3Hash) -> MembershipProof
    where
        K: AsRef<[u8]>,
    {
		match self {
			Node::Internal(node) => node.insert(key.as_ref(), value, hash),
			Node::Leaf(node) => {
				let leaf = node.insert(key.as_ref(), value, hash);
				MembershipProof {
					commitments: Vec::new(),
                    path: Vec::new(),
                    leaf
				}
			}
		}
    }

    pub fn insert_no_proof<K>(&mut self, key: K, value: Offset, hash: Blake3Hash)
    where
        K: AsRef<[u8]>,
    {
        match self {
            Node::Internal(node) => node.insert_no_proof(key.as_ref(), value, hash),
            Node::Leaf(node) => node.insert_no_proof(key.as_ref(), value, hash)
        }
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
        match self {
            Node::Internal(node) => node.get(key.as_ref()),
            Node::Leaf(node) => {
                match node.get(key.as_ref()) {
                    Either::Left(LeafGetFound(offset, leaf)) => GetResult::Found(
                        offset,
                        MembershipProof {
                            commitments: Vec::new(),
                            path: Vec::new(),
                            leaf
                        }
                    ),
                    Either::Right(LeafGetNotFound { left, left_key, right, right_key}) => GetResult::NotFound(
                        NonMembershipProof::IntraNode {
                            commitments: Vec::new(),
                            path_to_leaf: Vec::new(),

                            left_key,
                            left,

                            right_key,
                            right
                        }
                    )
                }
            }
        }
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

#[derive(Clone)]
pub struct InternalNode<'params, const Q: usize> {
    pub(crate) hash: Option<FieldHash>,
	// INVARIANT: children.len() == keys.len()
	// INVARIANT: keys has no duplicates
	// the ith key is >= than all keys in the ith child but < all keys in the i+1th child
    pub(crate) children: Vec<Node<'params, Q>>,
    pub(crate) keys: Vec<Bytes>,
    // witnesses are lazily-computed - none if any particular witness hasn't been computed yet.
    pub(crate) witnesses: Vec<Option<KZGWitness<Bls12>>>,
    pub(crate) batch_witness: Option<KZGBatchWitness<Bls12, Q>>,
    pub(crate) prover: KZGProver<'params, Bls12, Q>,
}

impl<'params, const Q: usize> InternalNode<'params, Q> {
    pub(crate) fn new(
        params: &'params KZGParams<Bls12, Q>,
        key: Bytes,
        left: Node<'params, Q>,
        right: Node<'params, Q>,
    ) -> Self {
        let left_key = match left {
            Node::Internal(ref node) => node.keys[0].clone(),
            Node::Leaf(ref node) => node.keys[0].clone(),
        };

        InternalNode {
            hash: None,
            children: vec![left, right],
            keys: vec![key],
            witnesses: Vec::new(),
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
        Ok(blake3::hash(&commitment.to_uncompressed()).into())
    }
	
	pub(crate) fn insert(&self, key: &[u8], value: Offset, hash: Blake3Hash) -> MembershipProof {
		unimplemented!()	
	}

	pub(crate) fn insert_no_proof(&self, key: &[u8], value: Offset, hash: Blake3Hash) {
		unimplemented!()	
	}

	pub(crate) fn get(&self, key: &[u8]) -> GetResult
	{
		unimplemented!()
	}

	pub(crate) fn get_no_proof(&self, key: &[u8]) -> Option<Offset>
	{
		unimplemented!()
	}
}


#[derive(Clone)]
pub struct LeafNode<'params, const Q: usize> {
    pub(crate) hash: Option<FieldHash>,
	// INVARIANT: children.len() == keys.len()
	// INVARIANT: keys has no duplicates
    pub(crate) keys: Vec<Bytes>,
    pub(crate) offsets: Vec<Offset>,
    pub(crate) hashes: Vec<FieldHash>,
    pub(crate) witnesses: Vec<Option<KZGWitness<Bls12>>>,
    pub(crate) batch_witness: Option<KZGBatchWitness<Bls12, Q>>,
    pub(crate) prover: KZGProver<'params, Bls12, Q>, 
    // no sibling pointers yet
}

pub(crate) struct LeafGetFound(Offset, KVProof);
pub(crate) struct LeafGetNotFound {
    left: KVProof,
    left_key: Bytes,

    right: KVProof,
    right_key: Bytes,
}

impl<'params, const Q: usize> LeafNode<'params, Q> {
    /// new *does not* immediately commit
    // for the commitment to occur, you must call commit()
    pub(crate) fn new(params: &'params KZGParams<Bls12, Q>) -> Self {
        LeafNode {
            hash: None,
            offsets: Vec::with_capacity(Q),
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
        Ok(blake3::hash(&commitment.to_uncompressed()).into())
    }

	pub(crate) fn insert(&self, key: &[u8], value: Offset, hash: Blake3Hash) -> KVProof {
		unimplemented!()	
	}

	pub(crate) fn insert_no_proof(&self, key: &[u8], value: Offset, hash: Blake3Hash) {
		unimplemented!()	
	}

	pub(crate) fn get(&self, key: &[u8]) -> Either<LeafGetFound, LeafGetNotFound>
	{
		unimplemented!()
	}

	pub(crate) fn get_no_proof(&self, key: &[u8]) -> Offset
	{
		unimplemented!()
	}
}