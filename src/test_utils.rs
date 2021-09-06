use crate::*;
use std::fmt::Debug;

pub(crate) fn assert_is_b_tree<
    const Q: usize,
    const MAX_KEY_LEN: usize,
    const MAX_VAL_LEN: usize,
>(
    tree: &BerkleTree<Q, MAX_KEY_LEN, MAX_VAL_LEN>,
) {
    println!("-----------");
    let res = assert_is_b_tree_inner(&tree.root.borrow(), (None, None), 0);
    println!("-----------\n");
    res
}

pub(crate) fn assert_is_b_tree_inner<
    const Q: usize,
    const MAX_KEY_LEN: usize,
    const MAX_VAL_LEN: usize,
>(
    node: &Node<Q, MAX_KEY_LEN, MAX_VAL_LEN>,
    parent_keys: (Option<KeyWithCounter<MAX_KEY_LEN>>, Option<KeyWithCounter<MAX_KEY_LEN>>),
    level: usize,
) {
    let (left_parent_key, right_parent_key) = parent_keys;

    match node {
        Node::Internal(node) => {
            println!("(internal) parent key: {:?}, keys: {:?}", &left_parent_key, node.keys);
            assert_at_node(
                node.keys.len() == node.children.len(),
                &left_parent_key,
                level,
                "children.len() != keys.len()".to_string()
            );

            assert_at_node(
                node.keys[0] == null_key(),
                &left_parent_key,
                level,
                "0th key in node is not null key!".to_string()
            );

            assert_at_node(
                is_sorted(&node.keys),
                &left_parent_key,
                level,
                "keys are not sorted".to_string(),
            );

            // ensure every key in node *except for 0th key, which is the null key*
            // is >= left parent key but < right parent key
            // ignore the corresponding check of each parent key that is None
            node.keys
                .iter()
                .skip(1)
                .for_each(|key| match (left_parent_key.as_ref(), right_parent_key.as_ref()) {
                    (Some(left), Some(right)) => assert_at_node(
                        key >= &left && key < &right,
                        &left_parent_key,
                        level,
                        format!(
                            "key {:?} < left parent key {:?} or >= right parent key {:?}",
                            key, left, right
                        ),
                    ),
                    (Some(left), None) => assert_at_node(
                        key >= &left,
                        &left_parent_key,
                        level,
                        format!("key {:?} < left parent key {:?}", key, left),
                    ),
                    (None, _) => assert_at_node(
                        level == 0,
                        &left_parent_key,
                        level,
                        "(None, _) case of parent keys for non-root node encountered! All nodes should have null key!"
                            .to_string(),
                    ),
                });

            node.children.iter().enumerate().for_each(|(i, child)| {
                // recurse - parent keys have 4 possible cases
                if i == 0 && i == node.keys.len() - 1 {
                    // case where there's only 1 child - should never happen
                    assert_at_node(false, &left_parent_key, level, "only 1 child!".to_string());
                } else if i == node.keys.len() - 1 {
                    // case where it's the last child
                    let left = node.keys[i].clone();
                    assert_is_b_tree_inner(child, (Some(left), None), level + 1);
                } else {
                    // case where it's not the last child
                    let left = node.keys[i].clone();
                    let right = node.keys[i + 1].clone();
                    assert_is_b_tree_inner(child, (Some(left), Some(right)), level + 1);
                }
            });
        }
        Node::Leaf(node) => {
            println!("(leaf) parent_key: {:?} keys: {:?}", &left_parent_key, node.keys);
            assert_at_node(
                node.keys.len() >= Q / 2,
                &left_parent_key,
                level,
                format!("leaf node has {} < Q / 2 keys", node.keys.len()),
            );

            assert_at_node(
                is_sorted(&node.keys),
                &left_parent_key,
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

pub(crate) fn assert_at_node<const MAX_KEY_LEN: usize>(
    cond: bool,
    left_parent_key: &Option<KeyWithCounter<MAX_KEY_LEN>>,
    level: usize,
    msg: String,
) {
    assert!(
        cond,
        "In node with parent key {:?} at level {}: {}",
        left_parent_key, level, msg
    );
}
