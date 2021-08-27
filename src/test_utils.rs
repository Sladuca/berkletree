use crate::*;
use std::fmt::Debug;

pub(crate) fn assert_is_b_tree<const Q: usize>(tree: &BerkleTree<Q>) {
    assert_is_b_tree_inner(&tree.root.borrow(), (None, None), 0)
}

pub(crate) fn assert_is_b_tree_inner<const Q: usize>(
    node: &Node<Q>,
    parent_keys: (Option<&[u8]>, Option<&[u8]>),
    level: usize,
) {
    let (left_parent_key, right_parent_key) = parent_keys;

    match node {
        Node::Internal { hash, node } => {
            assert_at_node(
                is_sorted(&node.keys),
                left_parent_key,
                level,
                "keys are not sorted".to_string(),
            );

            // ensure every key in node is >= left parent key but < right parent key
            // ignore the corresponding check of each parent key that is None
            node.keys
                .iter()
                .for_each(|key| match (left_parent_key, right_parent_key) {
                    (Some(left), Some(right)) => assert_at_node(
                        key.as_ref() >= left && key.as_ref() < right,
                        left_parent_key,
                        level,
                        format!(
                            "key {:#?} < left parent key {:#?} or >= right parent key {:#?}",
                            key, left, right
                        ),
                    ),
                    (Some(left), None) => assert_at_node(
                        key.as_ref() >= left,
                        left_parent_key,
                        level,
                        format!("key {:#?} < left parent key {:#?}", key, left),
                    ),
                    (None, Some(right)) => assert_at_node(
                        key.as_ref() < right,
                        left_parent_key,
                        level,
                        format!("key {:#?} >= right parent key {:#?}", key, right),
                    ),
                    (None, None) => assert_at_node(
                        level == 0,
                        left_parent_key,
                        level,
                        "(None, None) case of parent keys for non-root node encountered!"
                            .to_string(),
                    ),
                });

            node.children.iter().enumerate().for_each(|(i, child)| {
                // recurse - parent keys have 4 possible cases
                if i == 0 && i == node.keys.len() - 1 {
                    // case where there's only 1 child - should never happen
                    assert_at_node(false, left_parent_key, level, "only 1 child!".to_string());
                } else if i == 0 {
                    // case where it's the 0th but not the last child
                    let right = node.keys[i].as_ref();
                    assert_is_b_tree_inner(child, (None, Some(right)), level + 1);
                } else if i == node.keys.len() {
                    // case where it's the last child
                    let left = node.keys[i - 1].as_ref();
                    assert_is_b_tree_inner(child, (Some(left), None), level + 1);
                } else {
                    // case where it's neither the first nor the last child
                    let left = node.keys[i - 1].as_ref();
                    let right = node.keys[i].as_ref();
                    assert_is_b_tree_inner(child, (Some(left), Some(right)), level + 1);
                }
            });
        }
        Node::Leaf { node, hash } => {
            assert_at_node(
                node.keys.len() >= Q / 2,
                left_parent_key,
                level,
                format!("leaf node has {} < Q / 2 keys", node.keys.len()),
            );

            assert_at_node(
                is_sorted(&node.keys),
                left_parent_key,
                level,
                "keys are not sorted".to_string(),
            );
        }
    }
}

pub(crate) fn is_sorted<T: Ord>(items: &Vec<T>) -> bool {
    let (is_sorted, _) = items.iter().fold((true, None), |(is_sorted, prev), curr| {
        if let Some(prev) = prev {
            (is_sorted && prev <= curr, Some(curr))
        } else {
            (is_sorted, Some(curr))
        }
    });

    is_sorted
}

pub(crate) fn assert_at_node(
    cond: bool,
    left_parent_key: Option<&[u8]>,
    level: usize,
    msg: String,
) {
    assert!(
        cond,
        "In node with parent key {:#?} at level {}: {}",
        left_parent_key, level, msg
    );
}
