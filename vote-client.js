#!/usr/bin/env node
'use strict';

const axios = require('axios');
const { PublicKey } = require('paillier-bigint');

if (process.argv.length < 4) {
    console.error('Usage: node vote-client.js <node_url> <voter_id> <vote_index>');
    console.error('Example: node vote-client.js http://localhost:3001 VOTER001 0');
    process.exit(1);
}

const NODE_URL = process.argv[2];
const VOTER_ID = process.argv[3];
const VOTE_INDEX = parseInt(process.argv[4]) || 0;
const ZK_URL = 'http://zk-service:5000';

async function main() {
    console.log(`🗳️  Voting on ${NODE_URL} for ${VOTER_ID}`);

    // 1. Fetch candidates from node config
    const configRes = await axios.get(`${NODE_URL}/config`);
    const candidates = configRes.data.candidates || ["candidateA", "candidateB", "candidateC", "candidateD"];
    
    if (VOTE_INDEX < 0 || VOTE_INDEX >= candidates.length) {
        throw new Error(`Invalid vote index: ${VOTE_INDEX}, valid: 0-${candidates.length-1}`);
    }
    
    console.log(`Voting for: ${candidates[VOTE_INDEX]}`);

    // 2. Get Merkle proof from authority
    const AUTHORITY_URL = 'http://localhost:4000';
    const proofRes = await axios.post(`${AUTHORITY_URL}/getMerkleProof`, { voterID: VOTER_ID });
    const { leaf: voterHash, proof: merkleProof } = proofRes.data;
    console.log(`✅ Voter hash: ${voterHash.slice(0,16)}...`);

    // 3. Get HE public key
    const heRes = await axios.get(`${AUTHORITY_URL}/hePublicKey`);
    const HE_PUB = new PublicKey(
        BigInt(heRes.data.n.startsWith('0x') ? heRes.data.n : '0x' + heRes.data.n),
        BigInt(heRes.data.g.startsWith('0x') ? heRes.data.g : '0x' + heRes.data.g)
    );
    if (!HE_PUB.n2) HE_PUB.n2 = HE_PUB.n * HE_PUB.n;
    console.log(`✅ HE public key loaded`);

    // 4. Create one-hot vote vector
    const numCandidates = candidates.length;
    const voteVector = new Array(numCandidates).fill(0);
    voteVector[VOTE_INDEX] = 1;
    console.log(`📊 Vote vector: [${voteVector.join(', ')}]`);

    // 5. Generate REAL n+1 proofs + encrypted vector from zk-service
    console.log('🔨 Generating REAL n+1 ZK proofs...');
    const proofsRes = await axios.post(`${ZK_URL}/generateVoteProofs`, {
        n: '0x' + HE_PUB.n.toString(16),
        vote_vector: voteVector
    }, { timeout: 10000 });
    
    const { encrypted_vote_vector: encryptedVoteVector, bit_proofs: bitProofs, sum_proof: sumProof } = proofsRes.data;
    
    console.log(`✅ Generated REAL proofs:`);
    console.log(`   - ${encryptedVoteVector.length} ciphertexts (n+1)`);
    console.log(`   - ${bitProofs.length} bit proofs`);
    console.log(`   - 1 sum consistency proof`);

    console.log(`🔒 Encrypted: [${encryptedVoteVector.map(c => c.slice(0,16)+'...').join(', ')}]`);

    // 6. Submit vote with REAL proofs
    const submitRes = await axios.post(`${NODE_URL}/mineBlock`, {
        voterHash,
        merkleProof,
        encryptedVoteVector,
        bitProofs,
        sumProof
    });

    console.log(`✅ Vote proposed! Block hash: ${submitRes.data.blockHash}`);
    console.log(`🔗 View blocks: ${NODE_URL}/blocks`);
}

main().catch(err => {
    console.error('❌ Vote failed:', err.message);
    process.exit(1);
});
