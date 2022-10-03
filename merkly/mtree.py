"""
# Merkle Tree model
"""
from typing import List, Optional
from pydantic import BaseModel


class Node(BaseModel):
    """
    # 🍃 Leaf of Tree
    """
    left: Optional[str]
    right: Optional[str]

    def __repr__(self) -> str:
        if self.left is None:
            return f"{self.right[:3]}"
        elif self.right is None:
            return f"{self.left[:3]}"

class MerkleTree():
    """
    # 🌳 Merkle Tree
    - You can passa raw data
    - They will hashed by `keccak-256`
    """
    def __init__(self, leafs: List[str]) -> None:
        """
        # Constructor
        - Needs a `list` of `str`
        """
        if not is_power_2(leafs.__len__()):
            raise Exception("size of leafs should be power of 2")

        self.leafs: List[str] = self.__hash_leafs(leafs)

    def __hash_leafs(self, leafs: List[str]) -> List[str]:
        return list(map(keccak, leafs))

    @property
    def root(self) -> str:
        """
        # Get a root of merkle tree
        """
        return merkle_root(self.leafs)[0]

    def proof(self, leaf: str) -> List[str]:
        """
        # Get a proof of merkle tree
        """
        return merkle_proof(self.leafs, keccak(leaf), [])

    def verify(self, proof: List[str]) -> bool:
        """
        # Verify the Merkle Proof
        """
        return self.root == reduce(lambda x, y: keccak(x + y), proof)
