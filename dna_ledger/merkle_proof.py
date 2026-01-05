from __future__ import annotations

from typing import List, Tuple

from .hashing import h_node


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
        pairs = []
        
        # Build pairs for this level
        it = iter(level)
        for a in it:
            b = next(it, a)  # duplicate last if odd
            pairs.append((a, b))
        
        # Find which pair contains our target index
        pair_idx = idx // 2
        pos_in_pair = idx % 2
        
        # Add sibling to proof
        if pair_idx < len(pairs):
            a, b = pairs[pair_idx]
            if pos_in_pair == 0:
                # Target is 'a', sibling is 'b' on the right
                if a != b:  # not a duplicated node
                    proof.append((b, 'R'))
            else:
                # Target is 'b', sibling is 'a' on the left
                proof.append((a, 'L'))
        
        # Build next level
        for a, b in pairs:
            nxt.append(h_node(a, b))
        
        # Move up to next level
        level = nxt
        idx = pair_idx
    
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
