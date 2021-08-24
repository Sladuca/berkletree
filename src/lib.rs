use std::{
	cell::RefCell,
	rc::Rc,
};
use kzg::{
	KZGParams,
	KZGProver,
	KZGWitness,
	KZGBatchWitness,
	KZGCommitment,
	polynomial::Polynomial
};
use bls12_381::{
	Bls12,
	Scalar
};
use blake3::{
	Hash as Blake3Hash,
};
use bitvec::vec::BitVec;

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
pub struct BerkleTree<const Q: usize>
{
	params: KZGParams<Bls12, Q>,
	root: Rc<RefCell<Node<Q>>>
}

/// enum reprenting the different kinds of nodes for
#[derive(Clone)]
enum Node<const Q: usize>
{
    Internal {
		hash: FieldHash,
		node: InternalNode<Q>,
	},
	Leaf {
		hash: FieldHash,
		node: LeafNode<Q>,
	}
}

#[derive(Clone)]
pub(crate) struct InternalNode<const Q: usize>
{
	children: Vec<Node<Q>>,
	keys: Vec<Box<[u8]>>,
	// witnesses are lazily-computed - none if any particular witness hasn't been computed yet.
	witnesses: Vec<Option<KZGWitness<Bls12>>>,
	batch_witness: KZGBatchWitness<Bls12, Q>,
	prover: KZGProver<Bls12, Q>
}

#[derive(Clone)]
pub(crate) struct LeafNode<const Q: usize>
{
	keys: Vec<Box<[u8]>>,
	offsets: Vec<Offset>,
	hashes: Vec<FieldHash>,
	witnesses: Vec<Option<KZGWitness<Bls12>>>,
	prover: KZGProver<Bls12, Q>
    // no next / prev pointers here since we need to traverse the tree up/down
    // anyways to get a range proof
}

impl<const Q: usize> LeafNode<Q> {
	fn new_from_prover(mut prover: KZGProver<Bls12, Q>) -> Self {
		let polynomial = Polynomial::new_zero();
		prover.commit(polynomial);
		LeafNode {
			offsets: Vec::with_capacity(Q),
			keys: Vec::with_capacity(Q),
			hashes: Vec::with_capacity(Q),
			witnesses: Vec::with_capacity(Q),
			prover: prover
		}
	}
}

pub struct KVProof {
	idx: usize,
	witness: KZGWitness<Bls12>,
}

pub struct InnerNodeProof<'a> {
	idx: usize,
	key: &'a [u8],
	child_hash: FieldHash,
	witness: KZGWitness<Bls12>,
}


pub struct MembershipProof<'a> {
	commitments: Vec<KZGCommitment<Bls12>>,
	path: Vec<InnerNodeProof<'a>>,
	leaf: KVProof
}

pub enum NonMembershipProof<'a> {
	/// path_to_leaf.len() == commitments.len() - 1. The last commitment is for the leaf node
	IntraNode {
		commitments: Vec<KZGCommitment<Bls12>>,
		path_to_leaf: Vec<InnerNodeProof<'a>>,

		left: KVProof,
		right: KVProof
	},
	InterNode {
		common_path: Option<Vec<InnerNodeProof<'a>>>,
		common_commitments: Option<Vec<KZGCommitment<Bls12>>>,

		left: KVProof,
		left_commitment: KZGCommitment<Bls12>,

		right: KVProof,
		right_commitment: KZGCommitment<Bls12>
	}
}

pub enum RangePath<'a> {
	KeyExists(MembershipProof<'a>),
	KeyDNE(NonMembershipProof<'a>)
}

// TODO
pub struct RangeProof<'a> {
	left_path: RangePath<'a>,
	right_path: RangePath<'a>,
	bitvecs: Vec<BitVec>,
}

pub enum GetResult<'a> {
	Found(Offset, MembershipProof<'a>),
	NotFound(NonMembershipProof<'a>)
}

pub enum ContainsResult<'a> {
	Found(MembershipProof<'a>),
	NotFound(NonMembershipProof<'a>),
}

pub struct RangeResult<'a, const Q: usize>
where
{
	proof: RangeProof<'a>,
	iter: RangeIter<'a, Q>
}

pub struct RangeIter<'a, const Q: usize>
{
	left_path: Vec<&'a [u8]>,
	right_path: Vec<&'a [u8]>,
	root: Rc<RefCell<Node<Q>>>,
	current_key: &'a [u8]
}

impl<const Q: usize> BerkleTree<Q>
{
	pub fn new_with_params(params: KZGParams<Bls12, Q>) -> Self {
		let prover = KZGProver::new(params);
		let root_leaf = LeafNode::new_from_prover(prover);
		unimplemented!()
	}

	pub fn insert<'a, K>(&mut self, key: K, value: Offset, hash: Blake3Hash) -> MembershipProof<'a> 
	where
		K: AsRef<[u8]>
	{
		unimplemented!()
	}

	pub fn insert_no_proof<K>(&mut self, key: K, value: Offset, hash: Blake3Hash) 
	where
		K: AsRef<[u8]>
	{
		unimplemented!()
	}

	pub fn bulk_insert<'a, K>(&mut self, entries: Vec<(K, Offset, Blake3Hash)>) -> Vec<MembershipProof<'a>> 
	where
		K: AsRef<[u8]>
	{
		unimplemented!()
	}

	pub fn bulk_insert_no_proof<K>(&mut self, entries: Vec<(K, Offset, Blake3Hash)>) 
	where
		K: AsRef<[u8]>
	{
		unimplemented!()
	}

	pub fn get<'a, K>(&self, key: &K) -> GetResult<'a> 
	where
		K: AsRef<[u8]>
	{
		unimplemented!()
	} 

	pub fn get_no_proof<K>(&self, key: &K) -> Option<Offset>
	where
		K: AsRef<[u8]>
	{
		unimplemented!()
	}

	pub fn contains_key<'a, K>(&self, key: &K) -> ContainsResult<'a> 
	where
		K: AsRef<[u8]>
	{
		unimplemented!()
	}

	pub fn contains_key_no_proof<K>(&self, key: &K) -> bool 
	where
		K: AsRef<[u8]>
	{
		unimplemented!()
	}

	pub fn range<'a, K>(&self, left: &K, right: &K) -> RangeResult<'a, Q>
	where
		K: AsRef<[u8]>
	{
		unimplemented!()
	}

	pub fn range_no_proof<'a, K>(&self, key: &K) -> RangeIter<'a, Q>
	where
		K: AsRef<[u8]>
	{
		unimplemented!()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use test_utils::*;
	use std::fmt::Debug;
	use fastrand::Rng;

	const RAND_SEED: u64 = 42;

	fn test_setup<const Q: usize>() -> KZGParams<Bls12, Q> {
		let rng = Rng::with_seed(420);
		let s: Scalar = rng.u64(0..u64::MAX).into();
		kzg::setup(s)
	}

	fn make_tree<K, const Q: usize>(items: Vec<(K, Offset, Blake3Hash)>) -> BerkleTree<Q>
	where
		K: AsRef<[u8]> + Debug
	{
		let params = test_setup();
		let mut tree: BerkleTree<Q> = BerkleTree::new_with_params(params);
		tree.bulk_insert_no_proof(items);
		tree
	}

	#[test]
	fn test_non_bulk_only_root_no_proof() {
		let params = test_setup();
		let mut tree: BerkleTree<11> = BerkleTree::new_with_params(params.clone());

		let keys: Vec<usize> = (0..1000).step_by(10).collect();

		// ordered insert, oredered get
		for &i in keys.iter() {
			let b = &i.to_le_bytes();
			let hash = blake3::hash(b);
			tree.insert_no_proof(b, i, hash);
		}

		for &i in keys.iter() {
			let b = &i.to_le_bytes();
			let v = tree.get_no_proof(b).expect(&format!("could not find key {} in the tree", i));
			assert_eq!(v, i);
		}

		let mut tree: BerkleTree<11> = BerkleTree::new_with_params(params.clone());
		let rng = Rng::with_seed(RAND_SEED);
		let mut keys_shuffled = keys.clone();
		
		// ordered insert, unordered get
		for &i in keys.iter() {
			let b = &i.to_le_bytes();
			let hash = blake3::hash(b);
			tree.insert_no_proof(b, i, hash);
		}

		rng.shuffle(&mut keys_shuffled);

		for &i in keys_shuffled.iter() {
			let b = &i.to_le_bytes();
			let v = tree.get_no_proof(b).expect(&format!("could not find key {} in the tree", i));
			assert_eq!(v, i);
		}

		let mut tree: BerkleTree<11> = BerkleTree::new_with_params(params.clone());
		// unordered insert, ordered get
		rng.shuffle(&mut keys_shuffled);
		for &i in keys_shuffled.iter() {
			let b = &i.to_le_bytes();
			let hash = blake3::hash(b);
			tree.insert_no_proof(b, i, hash);
		}


		for &i in keys.iter() {
			let b = &i.to_le_bytes();
			let v = tree.get_no_proof(b).expect(&format!("could not find key {} in the tree", i));
			assert_eq!(v, i);
		}

		let mut tree: BerkleTree<11> = BerkleTree::new_with_params(params.clone());
		// unordered insert, unordered get
		rng.shuffle(&mut keys_shuffled);
		for &i in keys_shuffled.iter() {
			let b = &i.to_le_bytes();
			let hash = blake3::hash(b);
			tree.insert_no_proof(b, i, hash);
		}

		rng.shuffle(&mut keys_shuffled);
		for &i in keys.iter() {
			let b = &i.to_le_bytes();
			let v = tree.get_no_proof(b).expect(&format!("could not find key {} in the tree", i));
			assert_eq!(v, i);
		}
		
	}
}