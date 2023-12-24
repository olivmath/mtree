"""
Merkle Tree Model
"""

from typing import Callable, List
from functools import reduce

from merkly.node import Node, Side
from merkly.utils import (
    validate_hash_function,
    is_power_2,
    slice_in_pairs,
    keccak,
    half,
    validate_leafs,
)


class MerkleTree:
    """
    # 🌳 Merkle Tree implementation

    ## Args:
        - leafs: List of raw data
        - hash_function (Callable[[str], str], optional): Function that hashes the data.
            * Defaults to `keccak` if not provided. It must have the signature (data: str) -> str.

    """

    def __init__(
        self,
        leafs: List[str],
        hash_function: Callable[[bytes, bytes], bytes] = lambda x, y: keccak(x + y),
    ) -> None:
        validate_leafs(leafs)
        validate_hash_function(hash_function)
        self.hash_function: Callable[[bytes, bytes], bytes] = hash_function
        self.raw_leafs: List[str] = leafs
        self.leafs: List[str] = self.__hash_leafs(leafs)
        self.short_leafs: List[str] = self.short(self.leafs)

    def __hash_leafs(self, leafs: List[str]) -> List[str]:
        return list(map(lambda x: self.hash_function(x.encode(), bytes()), leafs))

    def __repr__(self) -> str:
        return f"""MerkleTree(\nraw_leafs: {self.raw_leafs}\nleafs: {self.leafs}\nshort_leafs: {self.short(self.leafs)})"""

    def short(self, data: List[str]) -> List[str]:
        return [x[:2] for x in data]

    @property
    def root(self) -> bytes:
        return self.make_root(self.leafs)

    def proof(self, raw_leaf: str) -> List[Node]:
        return self.make_proof(
            self.leafs, [], self.hash_function(raw_leaf.encode(), bytes())
        )

    def verify(self, proof: List[bytes], raw_leaf: str) -> bool:
        full_proof = [self.hash_function(raw_leaf.encode(), bytes())]
        full_proof.extend(proof)

        def concat_nodes(left: Node, right: Node) -> Node:
            if isinstance(left, Node) is not True:
                start_node = left
                if right.side == Side.RIGHT:
                    data = self.hash_function(start_node, right.data)
                    return Node(data=data, side=Side.LEFT)
                else:
                    data = self.hash_function(right.data, start_node)
                    return Node(data=data, side=Side.RIGHT)
            else:
                if right.side == Side.RIGHT:
                    data = self.hash_function(left.data, right.data)
                    return Node(data=data, side=Side.LEFT)
                else:
                    data = self.hash_function(right.data, left.data)
                    return Node(data=data, side=Side.RIGHT)

        return reduce(concat_nodes, full_proof).data == self.root

    def make_root(self, leafs: List[bytes]) -> List[str]:
        while len(leafs) > 1:
            next_level = []
            for i in range(0, len(leafs) - 1, 2):
                next_level.append(self.hash_function(leafs[i], leafs[i + 1]))

            if len(leafs) % 2 == 1:
                next_level.append(leafs[-1])

            leafs = next_level

        return leafs[0]

    def make_proof(
        self, leafs: List[bytes], proof: List[Node], leaf: bytes
    ) -> List[Node]:
        """
        # Make a proof

        ## Dev:
            - if the `leaf` index is less than half the size of the `leafs`
        list then the right side must reach root and vice versa

        ## Args:
            - leafs: List of leafs
            - proof: Accumulated proof
            - leaf: Leaf for which to create the proof

        ## Returns:
            - List of Nodes representing the proof
        """

        try:
            index = leafs.index(leaf)
        except ValueError as err:
            msg = f"Leaf: {leaf} does not exist in the tree: {leafs}"
            raise ValueError(msg) from err

        if is_power_2(len(leafs)) is False:
            return self.mix_tree(leafs, [], index)

        if len(leafs) == 2:
            if index == 1:
                proof.append(Node(data=leafs[0], side=Side.LEFT))
            else:
                proof.append(Node(data=leafs[1], side=Side.RIGHT))
            proof.reverse()
            return proof

        left, right = half(leafs)

        if index < len(leafs) / 2:
            proof.append(Node(data=self.make_root(right), side=Side.RIGHT))
            return self.make_proof(left, proof, leaf)
        else:
            proof.append(Node(data=self.make_root(left), side=Side.LEFT))
            return self.make_proof(right, proof, leaf)

    def mix_tree(
        self, leaves: List[bytes], proof: List[Node], leaf_index: int
    ) -> List[Node]:
        if len(leaves) == 1:
            return proof

        if leaf_index % 2 == 0:
            if leaf_index + 1 < len(leaves):
                node = Node(data=leaves[leaf_index + 1], side=Side.RIGHT)
                proof.append(node)
        else:
            node = Node(data=leaves[leaf_index - 1], side=Side.LEFT)
            proof.append(node)

        return self.mix_tree(self.up_layer(leaves), proof, leaf_index // 2)

    def up_layer(self, leaves: List[bytes]) -> List[bytes]:
        new_layer = []
        for pair in slice_in_pairs(leaves):
            if len(pair) == 1:
                new_layer.append(pair[0])
            else:
                data = self.hash_function(pair[0], pair[1])
                new_layer.append(data)
        return new_layer