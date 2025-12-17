const express = require('express');
const bodyParser = require('body-parser');
const { MerkleTree } = require('merkletreejs');
const crypto = require('crypto');
const axios = require('axios');
const { generateRandomKeys } = require('paillier-bigint');

// Voter IDs
const voterIDs = [
  'VOTER001',
  'VOTER002',
  'VOTER003',
  'VOTER004',
  'VOTER005',
];

// Hash function using Node's crypto
function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

// Build Merkle tree
const leaves = voterIDs.map(id => sha256(id));
const tree = new MerkleTree(leaves, sha256, { sortPairs: false });
const merkleRoot = tree.getHexRoot();

let HE = null; // will hold { publicKey, privateKey }

async function init() {
  // 1) Generate Paillier keys BEFORE starting the server
  console.log('🔑 Generating fresh Paillier 2048-bit keys...');
  const { publicKey, privateKey } = await generateRandomKeys(2048, true); // simpleVariant = true
  HE = { publicKey, privateKey };
  console.log('✅ HE keys ready:');
  const c1 = HE.publicKey.encrypt(1n);

  // 2) Now set up Express app and routes
  const app = express();
  app.use(bodyParser.json());

  // Merkle endpoints
  app.get('/merkleRoot', (req, res) => {
    res.json({
      merkleRoot,
      voters: voterIDs.length,
      timestamp: new Date().toISOString(),
    });
  });

  app.post('/getMerkleProof', (req, res) => {
    const { voterID } = req.body;
    if (!voterID) return res.status(400).json({ error: 'Missing voterID' });

    const index = voterIDs.indexOf(voterID);
    if (index === -1) {
      return res.status(404).json({ error: 'Voter ID not found' });
    }

    const leaf = sha256(voterID).toString('hex');
    const proof = tree.getProof(leaves[index]);
    if (proof.length === 0) {
      return res.status(404).json({ error: 'Voter ID not found' });
    }

    res.json({ leaf, merkleRoot, proof });
  });

  // HE public key
  app.get('/hePublicKey', (req, res) => {
    // HE is guaranteed to be ready here
    res.json({
      n: HE.publicKey.n.toString(16),
      g: HE.publicKey.g.toString(16),
      scheme: 'paillier-2048',
    });
  });

  // HE decrypt totals
  app.post('/heDecryptTotals', async (req, res) => {
    try {
      const { totals } = req.body;
      // Use _p and _q here
      if (!HE || !HE.privateKey || !HE.privateKey._p || !HE.privateKey._q) {
        console.error('HE private key not ready', HE && HE.privateKey);
        return res.status(503).json({ error: 'HE private key not ready' });
      }

      console.log(`🔓 Decrypting ${totals.length} totals via Rust zk-service...`);

      const plaintext = await Promise.all(
        totals.map(async (hex, i) => {
          try {
            const rustRes = await axios.post(
              'http://zk-service:5000/decrypt_with_key',
              {
                ciphertext: hex,
                decryption_key: {
                  p: '0x' + HE.privateKey._p.toString(16),
                  q: '0x' + HE.privateKey._q.toString(16),
                },
              },
              { timeout: 5000 }
            );

            console.log('Rust plaintext raw:', rustRes.data.plaintext);
            const count = Number(rustRes.data.plaintext);
            console.log(`Candidate ${i}: ${hex.slice(0, 16)}... → ${count}`);
            return count.toString();
          } catch (e) {
            console.error(`Decrypt ${i} failed:`, e.message);
            return '0';
          }
        })
      );

      res.json({
        plaintext,
        maxVotes: voterIDs.length,
        debug: totals.map(h => h.slice(0, 16)),
      });
    } catch (e) {
      console.error('heDecryptTotals failed:', e);
      res.status(500).json({ error: e.message });
    }
  });

  // 3) Start server only after everything above is ready
  app.listen(4000, () => {
    console.log('Authority node running on port 4000');
    console.log(`Merkle Root: ${merkleRoot}`);
    console.log(`Registered ${voterIDs.length} voters`);
  });
}

// Run init and fail fast if anything goes wrong
init().catch(err => {
  console.error('Authority init failed:', err);
  process.exit(1);
});
