const express = require('express');
const bodyParser = require('body-parser');
const { MerkleTree } = require('merkletreejs');
const CryptoJS = require('crypto-js');

// Example voter IDs (replace with your real list)
const voterIDs = [
  'VOTER001',
  'VOTER002',
  'VOTER003',
  'VOTER004'
];

// Hash voter IDs
const leaves = voterIDs.map(id => CryptoJS.SHA256(id).toString(CryptoJS.enc.Hex));
const tree = new MerkleTree(leaves, CryptoJS.SHA256, { sortPairs: true });
const merkleRoot = tree.getHexRoot();

const app = express();
app.use(bodyParser.json());

// Endpoint to get Merkle root
app.get('/merkleRoot', (req, res) => {
  res.json({ merkleRoot });
});

// Endpoint to get Merkle proof for a voter ID
app.post('/getMerkleProof', (req, res) => {
  const { voterID } = req.body;
  if (!voterID) return res.status(400).json({ error: 'Missing voterID' });
  const leaf = CryptoJS.SHA256(voterID).toString(CryptoJS.enc.Hex);
  const proof = tree.getProof(leaf);
  if (proof.length === 0) {
    return res.status(404).json({ error: 'Voter ID not found' });
  }
  res.json({ leaf, merkleRoot, proof });
});

app.listen(4000, () => {
  console.log('Authority node running on port 4000');
});