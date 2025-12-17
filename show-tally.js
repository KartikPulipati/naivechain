require('dotenv').config({ path: './election.env', quiet: true });

const axios = require('axios');
const NODE_URL = process.argv[2] || 'http://localhost:3001';
const AUTH_URL = 'http://localhost:4000';
const ELECTION_CANDIDATES = process.env.ELECTION_CANDIDATES
  ? process.env.ELECTION_CANDIDATES.split(',').map(s => s.trim())
  : ['candidateA', 'candidateB', 'candidateC', 'candidateD'];

(async () => {
  const encRes = await axios.get(`${NODE_URL}/tallyEncrypted`);
  const { totals } = encRes.data;
  
  if (!totals || totals.length === 0) {
    console.log('No votes tallied yet.');
    return;
  }
  
  const decRes = await axios.post(`${AUTH_URL}/heDecryptTotals`, { totals });
  const { plaintext } = decRes.data;
  
  console.log('Final tally:');
  plaintext.forEach((s, i) => {
    const count = Number(s);  // Authority already returns "1" or "0" strings
    console.log(`- ${ELECTION_CANDIDATES[i]}: ${count}`);
  });
})();
