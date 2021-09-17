use bitvec::vec::BitVec;
use blake3::{Hash as Blake3Hash, Hasher as Blake3Hasher};
use bls12_381::Bls12;
use kzg::{KZGCommitment, KZGVerifier, KZGWitness};
use std::{cell::RefCell, rc::Rc};

use crate::node::Node;
use crate::{null_key, FieldHash, KeyWithCounter};

fn verify_path<'params, const Q: usize, const MAX_KEY_LEN: usize>(
    mut prev_child_hash: Option<FieldHash>,
    path: &Vec<InnerNodeProof<MAX_KEY_LEN>>,
    commitments: &Vec<KZGCommitment<Bls12>>,
    verifier: &KZGVerifier<'params, Bls12, Q>,
) -> (bool, Option<FieldHash>) {
    // verify the audit path
    for i in (0..path.len()).rev() {
        let commitment = &commitments[i];

        // println!("{:#?}", &path[i]);
        // check child hash
        if let Some(prev_child_hash) = prev_child_hash {
            let mut hasher = Blake3Hasher::new();
            hasher.update(&commitment.inner().to_compressed());
            hasher.update(b"internal");
            hasher.update(&path[i].node_size.to_le_bytes());

            if prev_child_hash != hasher.finalize().into() {
                println!("child hash check failure at level {:?}", path.len() - 1 - i);
                return (false, Some(prev_child_hash));
            }
        };

        // verify the polynomial eval
        if !path[i].verify(commitment, verifier) {
            println!(
                "polynomial eval check failure at level {:?}",
                path.len() - 1 - i
            );
            return (false, prev_child_hash);
        }

        prev_child_hash = Some(path[i].child_hash);
    }

    (true, prev_child_hash)
}

/// Struct that comprises all information needed to verify a Leaf Node, minus the key and value hash.
/// it is assumed the the key and value hash will be known to the user, since they asked for the key
/// when get() or insert() and they have the value.
#[derive(Debug)]
pub struct KVProof {
    pub(crate) idx: usize,
    pub(crate) node_size: usize,
    pub(crate) retrieved_key_counter: usize,
    pub(crate) commitment: KZGCommitment<Bls12>,
    pub(crate) witness: KZGWitness<Bls12>,
}

impl KVProof {
    pub fn verify<'params, K: AsRef<[u8]>, const Q: usize, const MAX_KEY_LEN: usize>(
        &self,
        key: &K,
        value_hash: Blake3Hash,
        verifier: &KZGVerifier<'params, Bls12, Q>,
    ) -> bool {
        let KVProof {
            idx,
            retrieved_key_counter,
            node_size: _,
            commitment,
            witness,
        } = self;

        let mut key_padded = [0; MAX_KEY_LEN];
        key_padded[0..key.as_ref().len()].copy_from_slice(key.as_ref());
        let key = KeyWithCounter(key_padded, *retrieved_key_counter);

        verifier.verify_eval(
            (
                key.field_hash_with_idx(*idx).into(),
                FieldHash::from(value_hash).into(),
            ),
            commitment,
            witness,
        )
    }
}

/// Struct that comprises all information needed to verify an Internal Node, minus the commitment
#[derive(Debug)]
pub struct InnerNodeProof<const MAX_KEY_LEN: usize> {
    pub(crate) idx: usize,
    pub(crate) node_size: usize,
    pub(crate) key: KeyWithCounter<MAX_KEY_LEN>,
    pub(crate) child_hash: FieldHash,
    pub(crate) witness: KZGWitness<Bls12>,
}

impl<const MAX_KEY_LEN: usize> InnerNodeProof<MAX_KEY_LEN> {
    pub fn verify<'params, const Q: usize>(
        &self,
        commitment: &KZGCommitment<Bls12>,
        verifier: &KZGVerifier<'params, Bls12, Q>,
    ) -> bool {
        let InnerNodeProof {
            idx,
            node_size: _,
            key,
            child_hash,
            witness,
        } = self;
        verifier.verify_eval(
            (key.field_hash_with_idx(*idx).into(), (*child_hash).into()),
            commitment,
            witness,
        )
    }
}

#[derive(Debug)]
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
    pub fn verify<'params, K: AsRef<[u8]>, const Q: usize>(
        &self,
        key: &K,
        value_hash: Blake3Hash,
        verifier: &KZGVerifier<'params, Bls12, Q>,
    ) -> bool {
        let (path_ok, prev_child_hash) = verify_path(None, &self.path, &self.commitments, verifier);

        // check the last hash
        if let Some(prev_child_hash) = prev_child_hash {
            let mut hasher = Blake3Hasher::new();
            hasher.update(&self.leaf.commitment.inner().to_compressed());
            hasher.update(b"leaf");
            hasher.update(&self.leaf.node_size.to_le_bytes());

            if prev_child_hash != hasher.finalize().into() {
                println!("leaf hash check failure");
                return false;
            }
        }

        // verify the leaf
        self.leaf
            .verify::<'_, K, Q, MAX_KEY_LEN>(key, value_hash, verifier)
    }
}

#[derive(Debug)]
pub enum NonMembershipProof<const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> {
    /// path.len() == commitments.len() - 1. The last commitment is for the leaf node
    IntraNode {
        path: Vec<InnerNodeProof<MAX_KEY_LEN>>,
        commitments: Vec<KZGCommitment<Bls12>>,
        leaf_commitment: KZGCommitment<Bls12>,
        leaf_size: usize,
        // idx of left key
        idx: usize,

        left_key: KeyWithCounter<MAX_KEY_LEN>,
        left_value: [u8; MAX_VAL_LEN],
        left_witness: KZGWitness<Bls12>,

        right_key: KeyWithCounter<MAX_KEY_LEN>,
        right_value: [u8; MAX_VAL_LEN],
        right_witness: KZGWitness<Bls12>,
    },
    InterNode {
        common_path: Option<Vec<InnerNodeProof<MAX_KEY_LEN>>>,
        // does not contain the commitment for the inner node at which they split
        common_commitments: Option<Vec<KZGCommitment<Bls12>>>,

        left: KVProof,
        left_key: KeyWithCounter<MAX_KEY_LEN>,
        left_value: [u8; MAX_VAL_LEN],
        left_path: Vec<InnerNodeProof<MAX_KEY_LEN>>,
        left_commitments: Vec<KZGCommitment<Bls12>>,

        right: KVProof,
        right_key: KeyWithCounter<MAX_KEY_LEN>,
        right_value: [u8; MAX_VAL_LEN],
        right_path: Vec<InnerNodeProof<MAX_KEY_LEN>>,
        right_commitments: Vec<KZGCommitment<Bls12>>,
    },
    Edge {
        is_left: bool,
        path: Vec<InnerNodeProof<MAX_KEY_LEN>>,
        commitments: Vec<KZGCommitment<Bls12>>,
        leaf_proof: KVProof,
        key: KeyWithCounter<MAX_KEY_LEN>,
        value: [u8; MAX_VAL_LEN],
    },
}

impl<const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize>
    NonMembershipProof<MAX_KEY_LEN, MAX_VAL_LEN>
{
    pub fn verify<'params, K, const Q: usize>(
        &self,
        key: &K,
        verifier: &KZGVerifier<'params, Bls12, Q>,
    ) -> bool
    where
        K: AsRef<[u8]>,
    {
        let key = key.as_ref();
        match self {
            NonMembershipProof::IntraNode {
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
                right_witness,
            } => {
                println!("IntraNode");
                if key <= &left_key.0 || key >= &right_key.0 {
                    false
                } else {
                    let (path_ok, prev_child_hash) = verify_path(None, path, commitments, verifier);
                    if !path_ok {
                        return false;
                    }

                    // check the last hash
                    if let Some(prev_child_hash) = prev_child_hash {
                        let mut hasher = Blake3Hasher::new();
                        hasher.update(&leaf_commitment.inner().to_compressed());
                        hasher.update(b"leaf");
                        hasher.update(&leaf_size.to_le_bytes());

                        if prev_child_hash != hasher.finalize().into() {
                            println!("leaf hash check failure");
                            return false;
                        }
                    }

                    // verify the keys to the left and right
                    let left_idx = *idx;
                    let right_idx = idx + 1;

                    verifier.verify_eval(
                        (
                            left_key.field_hash_with_idx(left_idx).into(),
                            FieldHash::from(blake3::hash(left_value)).into(),
                        ),
                        leaf_commitment,
                        left_witness,
                    ) && verifier.verify_eval(
                        (
                            right_key.field_hash_with_idx(right_idx).into(),
                            FieldHash::from(blake3::hash(right_value)).into(),
                        ),
                        leaf_commitment,
                        right_witness,
                    )
                }
            }
            NonMembershipProof::InterNode {
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
            } => {
                println!("InterNode");
                if key <= &left_key.0 || key >= &right_key.0 {
                    false
                } else {
                    let mut common_path_child_hash: Option<FieldHash> = None;

                    if let (Some(ref common_path), Some(common_commitments)) =
                        (common_path, common_commitments)
                    {
                        let (path_ok, prev_child_hash) =
                            verify_path(None, common_path, common_commitments, verifier);
                        if !path_ok {
                            return false;
                        }

                        common_path_child_hash = prev_child_hash;
                    }

                    // verify the left and right paths & leaf hashes
                    if let Some(common_path_child_hash) = common_path_child_hash {
                        // left
                        let (path_ok, prev_child_hash) = verify_path(
                            Some(common_path_child_hash.clone()),
                            &left_path,
                            &left_commitments,
                            verifier,
                        );
                        if !path_ok {
                            return false;
                        }

                        if let Some(prev_child_hash) = prev_child_hash {
                            let mut hasher = Blake3Hasher::new();
                            hasher.update(&left.commitment.inner().to_compressed());
                            hasher.update(b"leaf");
                            hasher.update(&left.node_size.to_le_bytes());

                            if prev_child_hash != hasher.finalize().into() {
                                println!("left leaf hash check failure");
                                return false;
                            }
                        }

                        // right
                        let (path_ok, prev_child_hash) = verify_path(
                            Some(common_path_child_hash),
                            &right_path,
                            &right_commitments,
                            verifier,
                        );
                        if !path_ok {
                            return false;
                        }

                        if let Some(prev_child_hash) = prev_child_hash {
                            let mut hasher = Blake3Hasher::new();
                            hasher.update(&right.commitment.inner().to_compressed());
                            hasher.update(b"leaf");
                            hasher.update(&right.node_size.to_le_bytes());

                            if prev_child_hash != hasher.finalize().into() {
                                println!("right leaf hash check failure");
                                return false;
                            }
                        }
                    }

                    // verify leaf proofs
                    left.verify::<'params, [u8; MAX_KEY_LEN], Q, MAX_KEY_LEN>(
                        &left_key.0,
                        blake3::hash(left_value),
                        verifier,
                    ) && right.verify::<'params, [u8; MAX_KEY_LEN], Q, MAX_KEY_LEN>(
                        &right_key.0,
                        blake3::hash(right_value),
                        verifier,
                    )
                }
            }
            NonMembershipProof::Edge {
                is_left,
                path,
                commitments,
                leaf_proof,
                key,
                value,
            } => {
                // TODO is this mathematically correct?

                println!("Edge(is_left: {})", is_left);
                let mut prev_child_hash: Option<FieldHash> = None;

                if *is_left {
                    for i in (0..path.len()).rev() {
                        // check to make sure idx of this node is 0 and node.keys[idx] == null key
                        if path[i].idx != 0 || path[i].key != null_key() {
                            return false;
                        }

                        let commitment = &commitments[i];

                        // check child hash
                        if let Some(prev_child_hash) = prev_child_hash {
                            let mut hasher = Blake3Hasher::new();
                            hasher.update(&commitment.inner().to_compressed());
                            hasher.update(b"internal");
                            hasher.update(&path[i].node_size.to_le_bytes());

                            if prev_child_hash != hasher.finalize().into() {
                                println!(
                                    "child hash check failure at level {:?}",
                                    path.len() - 1 - i
                                );
                                return false;
                            }
                        }

                        // verify the polynomial eval
                        if !path[i].verify(commitment, verifier) {
                            println!(
                                "polynomial eval check failure at level {:?}",
                                path.len() - 1 - i
                            );
                            return false;
                        }

                        prev_child_hash = Some(path[i].child_hash);
                    }

                    true
                } else {
                    for i in (0..path.len()).rev() {
                        // check to make sure idx of this node == the node size
                        // if the prover lied about the node_size, the hash check will fail
                        // if the prover lied about the idx, path[i].verify() will fail
                        // therefore if this check, the hash check, and path[i].verify() succeeds,
                        // the given key is the largest key in the node
                        if path[i].idx != path[i].node_size - 1 {
                            println!(
                                "wrong idx: expected {}, got {}",
                                path[i].node_size - 1,
                                path[i].idx
                            );
                            return false;
                        }

                        let commitment = &commitments[i];

                        // check child hash
                        if let Some(prev_child_hash) = prev_child_hash {
                            let mut hasher = Blake3Hasher::new();
                            hasher.update(&commitment.inner().to_compressed());
                            hasher.update(b"internal");
                            hasher.update(&path[i].node_size.to_le_bytes());

                            if prev_child_hash != hasher.finalize().into() {
                                println!(
                                    "child hash check failure at level {:?}",
                                    path.len() - 1 - i
                                );
                                return false;
                            }
                        }

                        // verify the polynomial eval
                        if !path[i].verify(commitment, verifier) {
                            println!(
                                "polynomial eval check failure at level {:?}",
                                path.len() - 1 - i
                            );
                            return false;
                        }

                        prev_child_hash = Some(path[i].child_hash);
                    }

                    true
                }
            }
        }
    }
}

pub enum RangePath<const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> {
    KeyExists(MembershipProof<MAX_KEY_LEN>),
    KeyDNE(NonMembershipProof<MAX_KEY_LEN, MAX_VAL_LEN>),
}

// TODO
pub struct RangeProof<const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> {
    left_path: RangePath<MAX_KEY_LEN, MAX_VAL_LEN>,
    right_path: RangePath<MAX_KEY_LEN, MAX_VAL_LEN>,
    bitvecs: Vec<BitVec>,
}

pub enum GetResult<const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> {
    Found([u8; MAX_VAL_LEN], MembershipProof<MAX_KEY_LEN>),
    NotFound(NonMembershipProof<MAX_KEY_LEN, MAX_VAL_LEN>),
}

pub enum ContainsResult<const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> {
    Found(MembershipProof<MAX_KEY_LEN>),
    NotFound(NonMembershipProof<MAX_KEY_LEN, MAX_VAL_LEN>),
}

pub enum DeleteResult<const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> {
    Deleted([u8; MAX_VAL_LEN], Blake3Hash),
    NotFound(NonMembershipProof<MAX_KEY_LEN, MAX_VAL_LEN>),
}

pub struct RangeResult<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize>
{
    proof: RangeProof<MAX_KEY_LEN, MAX_VAL_LEN>,
    iter: RangeIter<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>,
}

pub struct RangeIter<'params, const Q: usize, const MAX_KEY_LEN: usize, const MAX_VAL_LEN: usize> {
    left_path: Vec<KeyWithCounter<MAX_KEY_LEN>>,
    right_path: Vec<KeyWithCounter<MAX_KEY_LEN>>,
    root: Rc<RefCell<Node<'params, Q, MAX_KEY_LEN, MAX_VAL_LEN>>>,
    current_key: [u8; MAX_KEY_LEN],
}
