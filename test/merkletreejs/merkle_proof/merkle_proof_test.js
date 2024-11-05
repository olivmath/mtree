const { MerkleTree } = require('merkletreejs');
const SHA256 = require('crypto-js/sha256');

const leaves = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'].map(x => Buffer.from(x, 'utf-8')).map(SHA256);
const tree = new MerkleTree(leaves, SHA256);
const leaf = SHA256(Buffer.from('a', 'utf-8'));
const proof = tree.getProof(leaf).map(node => ({ data: node.data.toString('hex'), position: node.position }));

console.log(JSON.stringify({ proof, isValid: tree.verify(proof, leaf, tree.getRoot()) }))
