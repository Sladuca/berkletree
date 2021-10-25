## Berkletree

This repo contains a qucik-and-dirty toy prototype implementation of the "Merkle B-Tree" described in ["Dynamic Merkle B-Tree With Efficient Proofs"](https://arxiv.org/pdf/2006.01994.pdf). It is absolutely not suited for any 'real' usage whatsoever, nor is it meant to be representative of what Berkle trees are capable of.

The purpose of this project was to...
1. Write the first implementation of "Berkle" trees
2. Scope out the extra complexity involved in a practical implementation

The tree implemented in this crate is totally in-memory, and has the following features implemented, with proofs and support for duplicate keys:
- `get`
- `contains`
- `insert`
- `delete`
- `range` (proofs incomplete because it turns out the range proof scheme doesn't support duplicate keys)
