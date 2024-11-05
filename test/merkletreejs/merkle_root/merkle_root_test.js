const { MerkleTree } = require('merkletreejs');
const SHA256 = require('crypto-js/sha256');


const leaves = ['a', 'b', 'c', 'd'].map(x => Buffer.from(x, 'utf-8')).map(SHA256);
const tree = new MerkleTree(leaves, SHA256, {});
const root = tree.getRoot().toString('hex');

console.log(JSON.stringify({ root }));
