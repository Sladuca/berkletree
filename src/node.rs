use kzg::{KZGBatchWitness, KZGCommitment, KZGParams, KZGProver, KZGWitness};
use std::convert::{TryFrom, TryInto};
use std::cmp::{PartialEq, PartialOrd, Ord, Ordering};

use blake3::{Hash as Blake3Hash};
use bls12_381::{Bls12, Scalar};
use either::Either;

use crate::{FieldHash, GetResult, KVProof, MembershipProof, Offset, RangeResult, ContainsResult, NonMembershipProof, RangeIter};
use crate::error::{NodeConvertError, BerkleError};

/// enum reprenting the different kinds of nodes for
#[derive(Clone)]
pub enum Node<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> {
    Internal(InternalNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>),
    Leaf(LeafNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>),
}

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> From<InternalNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>> for Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN> {
    fn from(node: InternalNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>) -> Self {
        Node::Internal(node)
    }
}

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> From<LeafNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>> for Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN> {
    fn from(node: LeafNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>) -> Self {
        Node::Leaf(node)
    }
}

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> TryFrom<Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>> for LeafNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN> {
    type Error = NodeConvertError;
    fn try_from(node: Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>) -> Result<Self, NodeConvertError> {
        match node {
            Node::Leaf(node) => Ok(node),
            _ => Err(NodeConvertError::NotLeafNode),
        }
    }
}

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> TryFrom<Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>> for InternalNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN> {
    type Error = NodeConvertError;
    fn try_from(node: Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>) -> Result<Self, NodeConvertError> {
        match node {
            Node::Internal(node) => Ok(node),
            _ => Err(NodeConvertError::NotInternalNode),
        }
    }
}

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN> {
	pub(crate) fn insert(&mut self, key: &[u8; MAX_KEY_LEN], value: &[u8; MAX_VAL_LEN], hash: Blake3Hash) -> MembershipProof<MAX_KEY_LEN>
    {
		match self {
			Node::Internal(node) => node.insert(key, value, hash),
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

    pub(crate) fn insert_no_proof(&mut self, key: &[u8; MAX_KEY_LEN], value: &[u8; MAX_VAL_LEN], hash: Blake3Hash)
    {
        match self {
            Node::Internal(node) => node.insert_no_proof(key, value, hash),
            Node::Leaf(node) => node.insert_no_proof(key, value, hash)
        }
    }

    pub(crate) fn bulk_insert(&mut self, entries: Vec<(&[u8; MAX_KEY_LEN], &[u8; MAX_VAL_LEN], Blake3Hash)>) -> Vec<MembershipProof<MAX_KEY_LEN>>
    {
        unimplemented!()
    }

    pub(crate) fn bulk_insert_no_proof(&mut self, entries: Vec<(&[u8; MAX_KEY_LEN], &[u8; MAX_VAL_LEN], Blake3Hash)>)
    {
        unimplemented!()
    }

    pub(crate) fn get(&self, key: &[u8; MAX_KEY_LEN]) -> GetResult<MAX_KEY_LEN, MAX_VAL_LEN>
    {
        match self {
            Node::Internal(node) => node.get(key),
            Node::Leaf(node) => {
                match node.get(key) {
                    Either::Left(LeafGetFound(val, leaf)) => GetResult::Found(
                        val,
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

    pub(crate) fn get_no_proof(&self, key: &[u8; MAX_KEY_LEN]) -> Option<Offset>
    {
        unimplemented!()
    }

    pub(crate) fn contains_key(&self, key: &[u8; MAX_KEY_LEN]) -> ContainsResult<MAX_KEY_LEN>
    {
        unimplemented!()
    }

    pub(crate) fn contains_key_no_proof(&self, key: &[u8; MAX_KEY_LEN]) -> bool
    {
        unimplemented!()
    }

    pub(crate) fn range(&self, left: &[u8; MAX_KEY_LEN], right: &[u8; MAX_KEY_LEN]) -> RangeResult<Q, MAX_KEY_LEN, MAX_VAL_LEN>
    {
        unimplemented!()
    }

    pub(crate) fn range_no_proof(&self, left: &[u8; MAX_KEY_LEN], right: &[u8; MAX_KEY_LEN]) -> RangeIter<Q, MAX_KEY_LEN, MAX_VAL_LEN>
    {
        unimplemented!()
    }
}

// assumes there will be no more than 255 duplicate keys in a single node
#[derive(Debug, Clone)]
struct KeyWithCounter<const MAX_KEY_LEN: usize>([u8; MAX_KEY_LEN], u8);

impl<const MAX_KEY_LEN: usize> PartialEq for KeyWithCounter<MAX_KEY_LEN> {
    fn eq(&self, other: &KeyWithCounter<MAX_KEY_LEN>) -> bool {
        self.0 == other.0
    }
}

impl<const MAX_KEY_LEN: usize> Eq for KeyWithCounter<MAX_KEY_LEN> {}

impl<const MAX_KEY_LEN: usize> PartialOrd for KeyWithCounter<MAX_KEY_LEN> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        PartialOrd::partial_cmp(&self.0, &other.0)
    }
}

impl<const MAX_KEY_LEN: usize> Ord for KeyWithCounter<MAX_KEY_LEN> {
    fn cmp(&self, other: &Self) -> Ordering {
        Ord::cmp(&self.0, &other.0)
    }
}


#[derive(Clone)]
pub struct InternalNode<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> {
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

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> InternalNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN> {
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
            keys: vec![KeyWithCounter(key, 0)],
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
	
	pub(crate) fn insert(&self, key: &[u8; MAX_KEY_LEN], value: &[u8; MAX_VAL_LEN], hash: Blake3Hash) -> MembershipProof<MAX_KEY_LEN> {
		unimplemented!()	
	}

	pub(crate) fn insert_no_proof(&self, key: &[u8; MAX_KEY_LEN], value: &[u8; MAX_VAL_LEN], hash: Blake3Hash) {
		unimplemented!()	
	}

	pub(crate) fn get(&self, key: &[u8; MAX_KEY_LEN]) -> GetResult<MAX_KEY_LEN, MAX_VAL_LEN>
	{
		unimplemented!()
	}

	pub(crate) fn get_no_proof(&self, key: &[u8; MAX_KEY_LEN]) -> Option<Offset>
	{
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
pub(crate) struct LeafGetNotFound<const MAX_KEY_LEN: usize> {
    left: KVProof,
    left_key: [u8; MAX_KEY_LEN],

    right: KVProof,
    right_key: [u8; MAX_KEY_LEN],
}

impl<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> LeafNode<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN> {
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
        Ok(blake3::hash(&commitment.to_uncompressed()).into())
    }

    fn insert_inner(&mut self, key: &[u8; MAX_KEY_LEN], value: &[u8; MAX_VAL_LEN], hash: Blake3Hash) -> usize {
        let mut key = KeyWithCounter(key.to_owned(), 0);
        let idx = self.keys.partition_point(|k| k.0 <= key.0);
        if idx != 0 && self.keys[idx - 1] == key {
            key.1 = self.keys[idx - 1].1 + 1;
        }
        
        self.keys.insert(idx, key);
        self.values.insert(idx, value.to_owned());
        idx
    }

	pub(crate) fn insert(&mut self, key: &[u8; MAX_KEY_LEN], value: &[u8; MAX_VAL_LEN], hash: Blake3Hash) -> KVProof {
       let idx = self.insert_inner(key, value, hash);
       
       unimplemented!()
	}  

	pub(crate) fn insert_no_proof(&self, key: &[u8], value: &[u8], hash: Blake3Hash) {
		unimplemented!()	
	}

	pub(crate) fn get(&self, key: &[u8]) -> Either<LeafGetFound<MAX_VAL_LEN>, LeafGetNotFound<MAX_KEY_LEN>>
	{
		unimplemented!()
	}

	pub(crate) fn get_no_proof(&self, key: &[u8]) -> Offset
	{
		unimplemented!()
	}
}