const express = require('express');
const bodyParser = require('body-parser');
const { MerkleTree } = require('merkletreejs');
const crypto = require('crypto'); // Use Node's crypto instead of CryptoJS

// Voter IDs
const voterIDs = [
  'VOTER001',
  'VOTER002',
  'VOTER003',
  'VOTER004'
];

// Hash function using Node's crypto (same as blockchain)
function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

// Create leaves using Node's crypto
const leaves = voterIDs.map(id => sha256(id));

// Build tree WITHOUT sortPairs (blockchain doesn't sort)
const tree = new MerkleTree(leaves, sha256, { sortPairs: false });
const merkleRoot = tree.getHexRoot();

const app = express();
app.use(bodyParser.json());

// Endpoint to get Merkle root
app.get('/merkleRoot', (req, res) => {
  res.json({ 
    merkleRoot: merkleRoot,
    voters: voterIDs.length,
    timestamp: new Date().toISOString()
  });
});

// Endpoint to get Merkle proof for a voter ID
app.post('/getMerkleProof', (req, res) => {
  const { voterID } = req.body;
  if (!voterID) return res.status(400).json({ error: 'Missing voterID' });
  
  // Find index
  const index = voterIDs.indexOf(voterID);
  if (index === -1) {
    return res.status(404).json({ error: 'Voter ID not found' });
  }
  
  // Get leaf hash (same as blockchain expects)
  const leaf = sha256(voterID).toString('hex');
  
  // Get proof
  const proof = tree.getProof(leaves[index]);
  
  if (proof.length === 0) {
    return res.status(404).json({ error: 'Voter ID not found' });
  }
  
  res.json({ leaf, merkleRoot, proof });
});

app.listen(4000, () => {
  console.log('Authority node running on port 4000');
  console.log(`Merkle Root: ${merkleRoot}`);
  console.log(`Registered ${voterIDs.length} voters`);
});
