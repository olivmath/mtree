from merkly.mtree import MerkleTree
from typing import List
from pytest import mark
import hashlib


def test_simple_merkle_tree_constructor():
    leaves = ["a", "b", "c", "d"]
    leaves = list(map(lambda x: x.encode(),leaves))

    tree = MerkleTree(leaves)

    assert tree.raw_leaves == leaves
    for i, j in zip(
        tree.short_leaves,
        [
            bytes.fromhex("3ac2"),
            bytes.fromhex("b555"),
            bytes.fromhex("0b42"),
            bytes.fromhex("f191"),
        ],
    ):
        assert i == j
    assert tree.leaves == [
        bytes.fromhex(
            "3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb"
        ),
        bytes.fromhex(
            "b5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510"
        ),
        bytes.fromhex(
            "0b42b6393c1f53060fe3ddbfcd7aadcca894465a5a438f69c87d790b2299b9b2"
        ),
        bytes.fromhex(
            "f1918e8562236eb17adc8502332f4c9c82bc14e19bfc0aa10ab674ff75b3d2f3"
        ),
    ]

    assert (
        tree.root.hex()
        == "68203f90e9d07dc5859259d7536e87a6ba9d345f2552b5b9de2999ddce9ce1bf"
    )

    assert tree.human_leaves == [
        "3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb",
        "b5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510",
        "0b42b6393c1f53060fe3ddbfcd7aadcca894465a5a438f69c87d790b2299b9b2",
        "f1918e8562236eb17adc8502332f4c9c82bc14e19bfc0aa10ab674ff75b3d2f3",
    ]

    assert tree.human_short_leaves == ["3ac2", "b555", "0b42", "f191"]


@mark.parametrize(
    "leaves, root",
    [
        (
            ["a", "b", "c", "d", "e", "f", "g", "h", "1"],
            "85d75312120b9d7cc325fef61d5c3b5de921a77f11049b187ddc5b90a3172c6d",
        ),
        (
            ["a", "b", "c", "d", "e", "f", "g", "h"],
            "cd07272f4955ddcfdac38ff36dff9d3e4353498923679ab548ba87e34648e4a3",
        ),
        (
            ["a", "b", "c", "d", "e"],
            "1dd0d2a6ae466d665cb26e1a31f07c57ae5df7d2bc559cd5826d417be9141a5d",
        ),
        (
            ["a", "b", "c", "d"],
            "68203f90e9d07dc5859259d7536e87a6ba9d345f2552b5b9de2999ddce9ce1bf",
        ),
        (
            ["a", "b"],
            "805b21d846b189efaeb0377d6bb0d201b3872a363e607c25088f025b0c6ae1f8",
        ),
    ],
)
def test_simple_merkle_root_with_keccak256(leaves: List[str], root: str):
    tree = MerkleTree(leaves)
    result = tree.root.hex()
    assert result == root


@mark.parametrize(
    "leaves, root",
    [
        (
            ["a", "b", "c", "d", "e", "f", "g", "h", "1"],
            "44611cac12a28960fa9f8d8bf93d9d73944b1425f3ba41d9cffe45c3aa3403d6",
        ),
        (
            ["a", "b", "c", "d", "e", "f", "g", "h"],
            "bd7c8a900be9b67ba7df5c78a652a8474aedd78adb5083e80e49d9479138a23f",
        ),
        (
            ["a", "b", "c", "d", "e"],
            "d71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba",
        ),
        (
            ["a", "b", "c", "d"],
            "14ede5e8e97ad9372327728f5099b95604a39593cac3bd38a343ad76205213e7",
        ),
        (
            ["a", "b"],
            "e5a01fee14e0ed5c48714f22180f25ad8365b53f9779f79dc4a3d7e93963f94a",
        ),
    ],
)
def test_simple_merkle_root_with_sha_256(leaves: List[str], root: str):
    def sha_256(x: bytes, y: bytes) -> bytes:
        data = x + y
        h = hashlib.sha256()
        h.update(data)
        return h.digest()

    tree = MerkleTree(leaves, hash_function=sha_256)
    result = tree.root.hex()
    assert result == root


@mark.parametrize(
    "leaves, root",
    [
        (
            ["a", "b", "c", "d", "e", "f", "g", "h", "1"],
            "bf4835202b9091df8d6e44c0e36094fc5dee200ef2aeb385299e0e73d289947a",
        ),
        (
            ["a", "b", "c", "d", "e", "f", "g", "h"],
            "c82d4fe15c85db42ec73121b5c482d86b95b78e05db8f707cde754e2bde30195",
        ),
        (
            ["a", "b", "c", "d", "e"],
            "c79cb7cae8eeca849c11c804ccfde50216bbe143cd557cc0a8bb877c66496e4e",
        ),
        (
            ["a", "b", "c", "d"],
            "565a2fdea5772b9dffdbb0081beeee36b2e9b952a8ef34fc5a58653fe4f9bd3d",
        ),
        (
            ["a", "b"],
            "fb53027dcbe9bb65748239cf200d4512367aafe81c683d0584491bfe7b644279",
        ),
    ],
)
def test_simple_merkle_root_with_shake256(leaves: List[str], root: str):
    def shake_256(x: bytes, y: bytes) -> bytes:
        data = x + y
        h = hashlib.shake_256()
        h.update(data)
        return h.digest(32)

    tree = MerkleTree(leaves, hash_function=shake_256)
    result = tree.root.hex()
    assert result == root


@mark.parametrize(
    "leaves, root",
    [
        (
            ["a", "b", "c", "d", "e", "f", "g", "h", "1"],
            "8e106437be21dfca61170ed413a185a73cd081a4a5760a95df4ccc5488874260",
        ),
        (
            ["a", "b", "c", "d", "e", "f", "g", "h"],
            "463baccb1666a42a1156e67f5961be418728a5bd80a97fda6d5054496d7646dc",
        ),
        (
            ["a", "b", "c", "d", "e"],
            "b8efa384f64647583db7ea069c46ec746d4d8c0c1815040431db4134bc0b41fd",
        ),
        (
            ["a", "b", "c", "d"],
            "5267fec4a5327f9d287233f95213afa39d3aad2fee1fa1384b032b79fb3441e8",
        ),
        (
            ["a", "b"],
            "29df505440ebe180c00857e92b0694c56a33762b08944472492b0cbf6ec607e3",
        ),
    ],
)
def test_simple_merkle_root_with_sha3_256(leaves: List[str], root: str):
    def sha3_256(x: bytes, y: bytes) -> bytes:
        data = x + y
        h = hashlib.sha3_256()
        h.update(data)
        return h.digest()

    tree = MerkleTree(leaves, hash_function=sha3_256)
    result = tree.root.hex()
    assert result == root
