from __future__ import annotations
from typing import List, Tuple
from .hashing import h_leaf, h_node

def merkle_proof(index: int, leaves: List[str]) -> List[Tuple[str, str]]:
    """
    Generate Merkle inclusion proof for leaf at index.
    Returns list of (hash, side) tuples where side is 'L' or 'R'.
    """
    if not leaves or index >= len(leaves):
        raise ValueError(f"Invalid index {index} for {len(leaves)} leaves")
    
    proof = []
    level = leaves[:]
    idx = index
    
    while len(level) > 1:
        nxt = []
        it = iter(level)
        level_idx = 0
        
        for a in it:
            b = next(it, a)  # duplicate last if odd
            if level_idx == idx:
                # Current node is a, sibling is b
                if a != b:  # not duplicated
                    proof.append((b, 'R'))
                idx = level_idx // 2
            elif level_idx == idx - 1:
                # Current node is b, sibling is a
                proof.append((a, 'L'))
                idx = level_idx // 2
            else:
                idx = idx // 2
            
            nxt.append(h_node(a, b))
            level_idx += 2
        
        level = nxt
    
    return proof

def verify_merkle_proof(leaf_hash: str, index: int, proof: List[Tuple[str, str]], root: str) -> bool:
    """
    Verify Merkle inclusion proof.
    Returns True if leaf_hash at index matches root given proof.
    """
    current = leaf_hash
    
    for sibling_hash, side in proof:
        if side == 'L':
            current = h_node(sibling_hash, current)
        elif side == 'R':
            current = h_node(current, sibling_hash)
        else:
            raise ValueError(f"Invalid proof side: {side}")
    
    return current == root
