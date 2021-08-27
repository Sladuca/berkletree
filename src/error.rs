use thiserror::Error;

#[derive(Debug, Error)]
pub enum BerkleError {
    #[error("attempted to get the hash of a node that has no commitment")]
    NotCommitted,
}

#[derive(Debug, Error)]
pub enum NodeConvertError {
    #[error("tried to convert non-leaf node into leaf node")]
    NotLeafNode,
    #[error("tried to convert non-internal node into internal node")]
    NotInternalNode,
}
