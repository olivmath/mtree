from merkly.mtree import MerkleTree
import hashlib
import json


def sha256(x, y):
    data = x + y
    return hashlib.sha256(data).digest()


leaves = ["a", "b", "c", "d"]
leaves = list(map(lambda x: x.encode(),leaves))
tree = MerkleTree(leaves, sha256)
root = tree.root.hex()

print(json.dumps({"root": root}))
