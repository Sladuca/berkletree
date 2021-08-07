use std::cmp::Ord;
use std::cell::RefCell;
use std::rc::Rc;

use ark_poly_commit::kzg10::{
	UniversalParams,
	KZG10,
	Commitment,
	Proof
};
use ark_ec::bls12::Bls12;
use ark_bls12_381::{
	Parameters as ECParams,
	Fr as ECScalarField
};
use ark_poly::univariate::DensePolynomial;
use blake3::{
	Hasher as Blake3Hasher,
	Hash as Blake3Hash
};
use bitvec::vec::BitVec;

pub(crate) type ECEngine = Bls12<ECParams>;

#[derive(Debug, Clone, PartialEq)]
pub struct Polynomial(DensePolynomial<ECScalarField>);

#[derive(Debug, Clone, PartialEq)]
pub struct PolynomialCommitment(Commitment<ECEngine>);

#[derive(Debug, Clone, PartialEq)]
pub struct Witness(Proof<ECEngine>);

mod serialize;

/// High level struct that user interacts with
pub struct BerkleTree<K, V, const Q: usize>
where
	K: Ord + Clone,
{
	parameters: UniversalParams<ECEngine>,
	scheme: KZG10<ECEngine, DensePolynomial<ECScalarField>>,
	root: Rc<RefCell<Node<K, V, Q>>>
}

/// enum reprenting the different kinds of nodes for
#[derive(Debug, Clone, PartialEq)]
enum Node<K, V, const Q: usize> 
where
	K: Ord + Clone
{
    Internal {
		hash: Blake3Hash,
		node: InternalNode<K, V, Q>,
	},
	Leaf {
		hash: Blake3Hash,
		node: LeafNode<K, V, Q>,
	}
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct InternalNode<K, V, const Q: usize>
where
	K: Ord + Clone,
{
	children: Vec<Node<K, V, Q>>,
	keys: Vec<K>,
	// witnesses are lazily-computed - none if any particular witness hasn't been computed yet.
	witnesses: Vec<Option<Witness>>,
	polynomial: Polynomial,
	commitment: PolynomialCommitment
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LeafNode<K, V, const Q: usize>
where
	K: Ord + Clone,
{
	values: Vec<V>,
	keys: Vec<K>,
	hashes: Vec<Blake3Hash>,
	witnesses: Vec<Option<Witness>>,
	polynomial: Polynomial,
	commitment: PolynomialCommitment
    
    // no next / prev pointers here since we need to traverse the tree up/down
    // anyways to get a range proof
}

pub struct KVProof<K, V> {
	idx: usize,
	key: K,
	value: V,
	witness: Witness,
}

// TODO
pub struct MembershipProof<K, V> {
	commitments: Vec<PolynomialCommitment>,
	path: Vec<KVProof<K, V>>
}

// TODO
pub enum NonMembershipProof<K, V> {
	IntraNode {
		commitments: Vec<PolynomialCommitment>,
		path_to_left: Vec<KVProof<K, V>>,
		right: KVProof<K,V>
	},
	InterNode {
		common_path: Option<Vec<KVProof<K, V>>>,
		common_commitments: Option<Vec<PolynomialCommitment>>,

		left_path: Vec<KVProof<K, V>>,
		left_commitments: Vec<PolynomialCommitment>,

		right_path: Vec<KVProof<K, V>>,
		right_commitments: Vec<PolynomialCommitment>,
	}
}

pub enum RangePath<K, V> {
	KeyExists(MembershipProof<K, V>),
	KeyDNE(NonMembershipProof<K, V>)
}

// TODO
pub struct RangeProof<K, V> {
	left_path: RangePath<K, V>,
	right_path: RangePath<K, V>,
	bitvecs: Vec<BitVec>,
}

pub enum GetResult<K, V> {
	Found(V, MembershipProof<K, V>),
	NotFound(V, NonMembershipProof<K, V>)
}

pub enum ContainsResult<K, V> {
	Found(MembershipProof<K, V>),
	NotFound(NonMembershipProof<K, V>),
}

pub struct RangeResult<'a, K, V, const Q: usize>
where
	K: Ord + Clone
{
	proof: RangeProof<K, V>,
	iter: RangeIter<'a, K, V, Q>
}

pub struct RangeIter<'a, K, V, const Q: usize>
where
	K: Ord + Clone
{
	left_path: Vec<K>,
	right_path: Vec<K>,
	root: &'a Node<K, V, Q>
}


impl<K, V, const Q: usize> BerkleTree<K, V, Q>
where
	K: Ord + Clone,
{
	/// 
	pub fn new() -> Self {
		unimplemented!()
	}

	pub fn new_with_params(params: UniversalParams<ECEngine>) -> Self {
		unimplemented!()
	}

	pub fn insert(&mut self, key: K, value: V, hash: Blake3Hash) -> MembershipProof<K, V> {
		unimplemented!()
	}

	pub fn insert_no_proof(&mut self, key: K, value: V, hash: Blake3Hash) {
		unimplemented!()
	}

	pub fn bulk_insert(&mut self, entries: Vec<(K, V, Blake3Hash)>) -> Vec<MembershipProof<K, V>> {
		unimplemented!()
	}

	pub fn bulk_insert_no_proof(&mut self, entries: Vec<(K, V, Blake3Hash)>) {
		unimplemented!()
	}

	pub fn get(&self, key: K) -> GetResult<K, V> {
		unimplemented!()
	} 

	pub fn get_no_proof(&self, key: K) -> Option<V> {
		unimplemented!()
	}

	pub fn contains_key(&self, key: K) -> ContainsResult<K, V> {
		unimplemented!()
	}

	pub fn contains_key_no_proof(&self, key: K) -> bool {
		unimplemented!()
	}

	pub fn range(&self, left: K, right: K) -> RangeResult<K, V, Q> {
		unimplemented!()
	}

	pub fn range_no_proof(&self, key: K) -> RangeIter<K, V, Q> {
		unimplemented!()
	}
}