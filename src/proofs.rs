use kzg::{KZGCommitment, KZGVerifier, KZGWitness};
use bls12_381::{Bls12};
use bitvec::vec::BitVec;
use std::{cell::RefCell, rc::Rc};
use blake3::{Hash as Blake3Hash, Hasher as Blake3Hasher};

use crate::{FieldHash, KeyWithCounter};
use crate::node::Node;

/// Struct that comprises all information needed to verify a Leaf Node, minus the key and value hash.
/// it is assumed the the key and value hash will be known to the user, since they asked for the key
/// when get() or insert() and they have the value.
pub struct KVProof {
    pub(crate) idx: usize,
	pub(crate) retrieved_key_counter: u8,
    pub(crate) commitment: KZGCommitment<Bls12>,
    pub(crate) witness: KZGWitness<Bls12>,
}

impl KVProof {
	pub fn verify<'params, K: AsRef<[u8]>, const Q: usize, const MAX_KEY_LEN: usize>(&self, key: K, value_hash: Blake3Hash, verifier: &KZGVerifier<'params, Bls12, Q>) -> bool {
		let KVProof { idx, retrieved_key_counter, commitment, witness } = self;

		let mut key_padded = [0; MAX_KEY_LEN];
		key_padded[0..key.as_ref().len()].copy_from_slice(key.as_ref());
		let key = KeyWithCounter(key_padded, *retrieved_key_counter);

		verifier.verify_eval((key.field_hash_with_idx(*idx).into(), FieldHash::from(value_hash).into()), commitment, witness)
	}
}

/// Struct that comprises all information needed to verify an Internal Node, minus the commitment
pub struct InnerNodeProof<const MAX_KEY_LEN: usize> {
    pub(crate) idx: usize,
    pub(crate) key: KeyWithCounter<MAX_KEY_LEN>,
    pub(crate) child_hash: FieldHash,
    pub(crate) witness: KZGWitness<Bls12>,
}

impl<const MAX_KEY_LEN: usize> InnerNodeProof<MAX_KEY_LEN> {
	pub fn verify<'params, const Q: usize>(&self, commitment: &KZGCommitment<Bls12>, verifier: &KZGVerifier<'params, Bls12, Q>) -> bool {
		let InnerNodeProof { idx, key, child_hash, witness } = self;
		verifier.verify_eval((key.field_hash_with_idx(*idx).into(), (*child_hash).into()), commitment, witness)
	}
}

pub struct MembershipProof<const MAX_KEY_LEN: usize> {
	/// KZG commitments for internal nodes of the audit path ordered in reverse.
	/// The root node comes last, its child comes second to last, ...
	/// 0th entry is the internal node above the leaf
    pub(crate) commitments: Vec<KZGCommitment<Bls12>>,

	/// InnerNodeProofs for internal nodes of the audit path ordered in reverse just like `commitments`
    pub(crate) path: Vec<InnerNodeProof<MAX_KEY_LEN>>,

	/// Proof for the leaf node
    pub(crate) leaf: KVProof,
}

impl<const MAX_KEY_LEN: usize> MembershipProof<MAX_KEY_LEN> {
	pub fn verify<'params, K: AsRef<[u8]>, const Q: usize>(&self, key: K, value_hash: Blake3Hash, verifier: &KZGVerifier<'params, Bls12, Q>) -> bool {
		let mut prev_child_hash = None;

		// verify the audit path
		for i in (0..self.path.len()).rev() {
			let commitment = &self.commitments[i];

			// check to make sure the hash given by the previous proof and current node matches
			match prev_child_hash {
				Some(prev_child_hash) => {
					let mut hasher = Blake3Hasher::new();
					hasher.update(&commitment.inner().to_compressed());
					hasher.update(b"internal");
					
					if prev_child_hash != hasher.finalize().into() {
						println!("child hash check failure at level {:?}", self.path.len() - 1 - i);
						return false
					}
				},
				None => {}
			};

			// verify the polynomal eval
			if !self.path[i].verify(commitment, verifier) {
				println!("polynomial eval check failure at level {:?}", self.path.len() - 1 - i);
				return false;
			}

			prev_child_hash = Some(self.path[i].child_hash);
		}

		// check the last hash
		match prev_child_hash {
			Some(prev_child_hash) => {
				let mut hasher = Blake3Hasher::new();
				hasher.update(&self.leaf.commitment.inner().to_compressed());
				hasher.update(b"leaf");

				if prev_child_hash != hasher.finalize().into() {
					println!("leaf hash check failure");
					return false
				}
			},
			None => {}
		}

		// verify the leaf
		self.leaf.verify::<'_, K, Q, MAX_KEY_LEN>(key, value_hash, verifier)
	}
}

pub enum NonMembershipProof<const MAX_KEY_LEN: usize> {
    /// path.len() == commitments.len() - 1. The last commitment is for the leaf node
    IntraNode {
        path: Vec<InnerNodeProof<MAX_KEY_LEN>>,
        leaf_commitment: KZGCommitment<Bls12>,
        // idx of left key
        idx: usize,

        left_key: KeyWithCounter<MAX_KEY_LEN>,
        left_witness: KZGWitness<Bls12>,

        right_key: KeyWithCounter<MAX_KEY_LEN>,
        right_witness: KZGWitness<Bls12>,
    },
    InterNode {
        common_path: Option<Vec<InnerNodeProof<MAX_KEY_LEN>>>,
        common_commitments: Option<Vec<KZGCommitment<Bls12>>>,

        left: KVProof,
        left_key: KeyWithCounter<MAX_KEY_LEN>,

        right: KVProof,
        right_key: KeyWithCounter<MAX_KEY_LEN>,
    },
    Edge {
        is_left: bool,
        path: Vec<InnerNodeProof<MAX_KEY_LEN>>,
        leaf_proof: KVProof,
        key: KeyWithCounter<MAX_KEY_LEN>,
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

pub struct RangeResult<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize>
{
    proof: RangeProof<MAX_KEY_LEN>,
    iter: RangeIter<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>,
}

pub struct RangeIter<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> {
    left_path: Vec<KeyWithCounter<MAX_KEY_LEN>>,
    right_path: Vec<KeyWithCounter<MAX_KEY_LEN>>,
    root: Rc<RefCell<Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>>>,
    current_key: [u8; MAX_KEY_LEN],
}