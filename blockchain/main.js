'use strict';
var CryptoJS = require("crypto-js");
var express = require("express");
var bodyParser = require('body-parser');
var WebSocket = require("ws");
const axios = require('axios');
const crypto = require('crypto');

// Config and identity
var http_port = process.env.HTTP_PORT || 3001;
var p2p_port = process.env.P2P_PORT || 6001;
var initialPeers = process.env.PEERS ? process.env.PEERS.split(',') : [];
const NODE_ID = process.env.NODE_ID || process.env.HTTP_PORT || 'unknown';
const AUTHORITY_URL = process.env.AUTHORITY_URL || 'http://authority:4000';

const ELECTION_ID = process.env.ELECTION_ID || 'POC-DEFAULT';
const ELECTION_CANDIDATES = process.env.ELECTION_CANDIDATES ? JSON.parse(process.env.ELECTION_CANDIDATES) : ["candidateA","candidateB","candidateC"];
const ELECTION_START = process.env.ELECTION_START ? parseInt(process.env.ELECTION_START, 10) : null;
const ELECTION_END = process.env.ELECTION_END ? parseInt(process.env.ELECTION_END, 10) : null;

const { PublicKey } = require('paillier-bigint');
let TOTAL_VOTES = 0;
let HE_PUB = null;
let N2 = null;
let ENC_TOTALS = null;

// Dynamic merkle root (fetched from authority at startup)
let MERKLE_ROOT = null;

// Message types
var MessageType = {
    QUERY_LATEST: 0,
    QUERY_ALL: 1,
    RESPONSE_BLOCKCHAIN: 2,
    PROPOSE_BLOCK: 3,
    NETWORK_VOTE: 4
};

// Block structure with dummy proof fields
class Block {
    constructor(index, previousHash, timestamp, voterHash, merkleProof, voteVector, hash, blockType = 'VOTE', config = null, encryptedVoteVector = null, encOne = null, binaryProofs = null) {
        this.index = index;
        this.previousHash = previousHash.toString();
        this.timestamp = timestamp;
        this.voterHash = voterHash;
        this.merkleProof = merkleProof;
        this.voteVector = voteVector;
        this.encryptedVoteVector = encryptedVoteVector;
        this.encOne = encOne;                    // encrypted 1 (dummy proof field)
        this.binaryProofs = binaryProofs;        // array of dummy proof objects
        this.blockType = blockType;
        this.config = config;
        this.hash = hash.toString();
    }
}

// Chain state
var sockets = [];
var blockchain = [getGenesisBlock()];

function getGenesisBlock() {
    return new Block(
        0,
        "0",
        1465154705,
        "genesisVoterHash",
        [],
        [],
        "816534932c2b7154836da6afc367695e6337db8a921823784c14378abed4f7d7",
        "VOTE",
        null,
        null,
        null,
        null
    );
}

// Fetch merkle root from authority
async function fetchMerkleRoot() {
    try {
        const response = await axios.get(`${AUTHORITY_URL}/merkleRoot`);
        MERKLE_ROOT = response.data.merkleRoot;
        console.log(`Fetched Merkle Root from authority: ${MERKLE_ROOT}`);
        console.log(`Registered voters: ${response.data.voters}`);
        return true;
    } catch (err) {
        console.error('Failed to fetch Merkle Root from authority:', err.message);
        return false;
    }
}

async function fetchHePublicKey() {
    try {
        const r = await axios.get(`${AUTHORITY_URL}/hePublicKey`, { timeout: 8000 });
        const n = BigInt(r.data.n.startsWith('0x') ? r.data.n : '0x' + r.data.n);
        const g = BigInt(r.data.g.startsWith('0x') ? r.data.g : '0x' + r.data.g);
        HE_PUB = new PublicKey(n, g);
        if (!HE_PUB.n2 && HE_PUB._n2) HE_PUB.n2 = HE_PUB._n2;
        if (!HE_PUB.n2) HE_PUB.n2 = n * n;
        N2 = HE_PUB.n2;
        console.log('Loaded HE public key and computed n^2');
        return true;
    } catch (e) {
        console.error('Failed to load HE public key:', e.message);
        return false;
    }
}

/**
 * Verify a Merkle inclusion proof
 */
function verifyMerkleProof(leaf, proof, expectedRoot) {
    try {
        const cleanRoot = expectedRoot.startsWith('0x') ? expectedRoot.slice(2) : expectedRoot;
        let currentHash = Buffer.from(leaf, 'hex');
        
        for (let i = 0; i < proof.length; i++) {
            const sibling = proof[i];
            const siblingData = Buffer.from(sibling.data.data);
            
            let combined;
            if (sibling.position === 'left') {
                combined = Buffer.concat([siblingData, currentHash]);
            } else {
                combined = Buffer.concat([currentHash, siblingData]);
            }
            
            currentHash = crypto.createHash('sha256').update(combined).digest();
        }
        
        const computedRoot = currentHash.toString('hex');
        return computedRoot === cleanRoot;
    } catch (err) {
        console.error('Merkle proof verification error:', err);
        return false;
    }
}

// One-hot vector check
function isOneHot(vec) {
    if (!Array.isArray(vec) || vec.length < 1) return false;
    let sum = 0;
    for (const v of vec) {
        const x = Number(v);
        if (!(x === 0 || x === 1)) return false;
        sum += x;
    }
    return sum === 1;
}

// Paillier helpers
function modPow(base, exp, mod) {
    let result = 1n, b = base % mod, e = exp;
    while (e > 0n) {
        if (e & 1n) result = (result * b) % mod;
        b = (b * b) % mod;
        e >>= 1n;
    }
    return result;
}

function cryptoRand(n) {
    let bits = n.toString(2).length;
    let bytes = Math.ceil(bits / 8);
    while (true) {
        let buf = crypto.randomBytes(bytes);
        let val = BigInt('0x' + buf.toString('hex'));
        if (val < n && val > 1n) return val;
    }
}

function paillierEncrypt(pub, plaintext) {
    const n = pub.n, n2 = pub.n2 || (pub.n * pub.n), g = pub.g;
    const r = cryptoRand(n);
    const c = (modPow(g, plaintext, n2) * modPow(r, n, n2)) % n2;
    return c;
}

// Encrypt vote vector using Paillier HE
function encryptVectorPaillier(vec) {
    if (!HE_PUB) throw new Error('HE public key not loaded');
    return vec.map(v => {
        const m = BigInt(Number(v));
        const c = paillierEncrypt(HE_PUB, m);
        return '0x' + c.toString(16);
    });
}

// Generate dummy proofs (all zeros, always pass)
function generateDummyProofs(length) {
    const proofs = [];
    for (let i = 0; i < length; i++) {
        proofs.push({
            A0: '0x0',
            A1: '0x0',
            e0: '0',
            e1: '0',
            z0: '0',
            z1: '0'
        });
    }
    return proofs;
}

// Hashing over vector contents (updated to include encOne and binaryProofs)
var calculateHash = (index, previousHash, timestamp, voterHash, merkleProof, voteVector, blockType = 'VOTE', config = null, encryptedVoteVector = null, encOne = null, binaryProofs = null) => {
    const votePart = Array.isArray(voteVector) ? JSON.stringify(voteVector) : "";
    const encPart = Array.isArray(encryptedVoteVector) ? JSON.stringify(encryptedVoteVector) : "";
    const encOnePart = encOne || "";
    const proofsPart = Array.isArray(binaryProofs) ? JSON.stringify(binaryProofs) : "";
    const typePart = blockType || 'VOTE';
    const configPart = config ? JSON.stringify(config) : "";
    return CryptoJS.SHA256(
        index + previousHash + timestamp + voterHash + JSON.stringify(merkleProof) + votePart + encPart + encOnePart + proofsPart + typePart + configPart
    ).toString();
};

var calculateHashForBlock = (block) => {
    return calculateHash(
        block.index,
        block.previousHash,
        block.timestamp,
        block.voterHash || "",
        block.merkleProof || [],
        block.voteVector || null,
        block.blockType || 'VOTE',
        block.config || null,
        block.encryptedVoteVector || null,
        block.encOne || null,
        block.binaryProofs || null
    );
};

// Block creation
var generateNextBlock = (voterHash, merkleProof, voteVector, encryptedVoteVector, encOne, binaryProofs) => {
    var previousBlock = getLatestBlock();
    var nextIndex = previousBlock.index + 1;
    var nextTimestamp = Math.floor(Date.now() / 1000);
    var nextHash = calculateHash(
        nextIndex,
        previousBlock.hash,
        nextTimestamp,
        voterHash,
        merkleProof,
        voteVector,
        'VOTE',
        null,
        encryptedVoteVector,
        encOne,
        binaryProofs
    );
    return new Block(
        nextIndex,
        previousBlock.hash,
        nextTimestamp,
        voterHash,
        merkleProof,
        voteVector,
        nextHash,
        'VOTE',
        null,
        encryptedVoteVector,
        encOne,
        binaryProofs
    );
};

// Block validation with DUMMY proof verification (always passes)
var isValidNewBlock = (newBlock, previousBlock) => {
    if (previousBlock.index + 1 !== newBlock.index) { 
        console.log('invalid index'); 
        return false; 
    }
    if (previousBlock.hash !== newBlock.previousHash) { 
        console.log('invalid previoushash'); 
        return false; 
    }
    if (calculateHashForBlock(newBlock) !== newBlock.hash) { 
        console.log('invalid hash'); 
        return false; 
    }

    if (newBlock.blockType && newBlock.blockType !== 'VOTE') {
        return true;
    }

    // VOTE block rules
    if (!MERKLE_ROOT) { 
        console.log('no merkle root'); 
        return false; 
    }
    if (!Array.isArray(newBlock.encryptedVoteVector) || newBlock.encryptedVoteVector.length < 1) {
        console.log('missing encryptedVoteVector'); 
        return false;
    }
    if (newBlock.voteVector && newBlock.voteVector.length) {
        console.log('plaintext voteVector should not be present in proposed block'); 
        return false;
    }
    if (!verifyMerkleProof(newBlock.voterHash, newBlock.merkleProof, MERKLE_ROOT)) {
        console.log('invalid merkle proof'); 
        return false;
    }
    if (hasVoterAlreadyVoted(newBlock.voterHash)) {
        console.log('double vote detected'); 
        return false;
    }
    for (const [h, b] of Object.entries(global.pendingProposals || {})) {
        if (b && b !== newBlock && b.voterHash === newBlock.voterHash) {
            console.log('conflict with pending proposal'); 
            return false;
        }
    }

    // DUMMY PROOF VERIFICATION - commented out so it always passes
    /*
    if (!ensureN2()) {
        console.log('HE not ready for proof verification');
        return false;
    }
    if (!Array.isArray(newBlock.binaryProofs) || newBlock.binaryProofs.length !== newBlock.encryptedVoteVector.length) {
        console.log('binaryProofs length mismatch');
        return false;
    }
    for (let i = 0; i < newBlock.encryptedVoteVector.length; i++) {
        // Real proof verification would go here
        // if (!paillierBitSigmaVerify(newBlock.encryptedVoteVector[i], newBlock.binaryProofs[i], HE_PUB.n, HE_PUB.g, N2)) {
        //     console.log('bit proof failed', i);
        //     return false;
        // }
    }
    */

    return true;
};

var addBlock = (newBlock) => {
    if (isValidNewBlock(newBlock, getLatestBlock())) {
        blockchain.push(newBlock);
    }
};

var getLatestBlock = () => blockchain[blockchain.length - 1];

// HTTP server
var initHttpServer = () => {
    var app = express();
    app.use(bodyParser.json());

    app.get('/blocks', (req, res) => {
        res.json(blockchain);
    });

    app.get('/config', (req, res) => {
        res.json({
            electionId: ELECTION_ID,
            merkleRoot: MERKLE_ROOT,
            candidates: ELECTION_CANDIDATES,
            startTime: ELECTION_START,
            endTime: ELECTION_END
        });
    });

    app.get('/hasVoted/:voterHash', (req, res) => {
        const voterHash = req.params.voterHash;
        const voted = hasVoterAlreadyVoted(voterHash);
        let blockIndex = null;
        if (voted) {
            for (let i = 1; i < blockchain.length; i++) {
                if (blockchain[i].voterHash === voterHash) { 
                    blockIndex = i; 
                    break; 
                }
            }
        }
        res.json({ voterHash, voted, blockIndex });
    });

    // Mine/propose a block with DUMMY proofs
    app.post('/mineBlock', async (req, res) => {
        try {
            const { voterHash, merkleProof, voteVector } = req.body;

            if (!voterHash || !Array.isArray(merkleProof) || !Array.isArray(voteVector)) {
                return res.status(400).json({ error: 'voterHash, merkleProof, and voteVector are required' });
            }
            if (!MERKLE_ROOT) {
                return res.status(503).json({ error: 'Merkle root not yet loaded from authority' });
            }
            if (!verifyMerkleProof(voterHash, merkleProof, MERKLE_ROOT)) {
                return res.status(403).json({ error: 'Invalid Merkle proof: voter not eligible' });
            }
            if (!isOneHot(voteVector)) {
                return res.status(400).json({ error: 'Invalid vote: not one-hot' });
            }
            if (hasVoterAlreadyVoted(voterHash)) {
                return res.status(409).json({ error: 'Double vote rejected: voter has already voted' });
            }
            if (isVoterInPendingProposals(voterHash)) {
                return res.status(409).json({ error: 'Conflicting pending proposal exists for this voter' });
            }
            if (!HE_PUB) {
                return res.status(503).json({ error: 'HE public key not loaded' });
            }

            // Encrypt vector
            const encryptedVoteVector = encryptVectorPaillier(voteVector);

            // Encrypt 1 for encOne (dummy proof field)
            const encOne = '0x' + paillierEncrypt(HE_PUB, 1n).toString(16);

            // Generate DUMMY proofs (all zeros)
            const binaryProofs = generateDummyProofs(voteVector.length);

            // Build proposed block
            const newBlock = generateNextBlock(
                voterHash,
                merkleProof,
                null,  // no plaintext in proposed block
                encryptedVoteVector,
                encOne,
                binaryProofs
            );

            // Consensus proposal
            const blockHash = newBlock.hash;
            if (!global.pendingProposals) global.pendingProposals = {};
            global.pendingProposals[blockHash] = newBlock;

            if (!global.voteTally) global.voteTally = {};
            global.voteTally[blockHash] = {
                totalVoters: sockets.length,
                proposer: NODE_ID,
                votes: {}
            };

            broadcast({
                type: MessageType.PROPOSE_BLOCK,
                data: JSON.stringify({ block: newBlock, proposer: NODE_ID })
            });

            return res.json({ status: 'proposed', blockHash });
        } catch (err) {
            console.error('Error in /mineBlock:', err);
            return res.status(500).json({ error: 'Vote submission failed' });
        }
    });

    app.get('/tallyEncrypted', (req, res) => {
        try {
            if (!HE_PUB || !N2) return res.status(503).json({ error: 'HE public key not loaded' });
            if (!ENC_TOTALS) return res.json({ totals: [], n2: '0x' + N2.toString(16) });
            const hexTotals = ENC_TOTALS.map(bigIntToHex);
            return res.json({ totals: hexTotals, n2: '0x' + N2.toString(16) });
        } catch (e) {
            console.error('Error in /tallyEncrypted:', e);
            return res.status(500).json({ error: 'Encrypted tally failed' });
        }
    });

    app.listen(http_port, '0.0.0.0', () => console.log('Listening http on port: ' + http_port));
};

// P2P
var initP2PServer = () => {
    var server = new WebSocket.Server({ port: p2p_port });
    server.on('connection', ws => initConnection(ws));
    console.log('listening websocket p2p port on: ' + p2p_port);
};

var initConnection = (ws) => {
    sockets.push(ws);
    initMessageHandler(ws);
    initErrorHandler(ws);
    write(ws, queryChainLengthMsg());
};

var initMessageHandler = (ws) => {
    ws.on('message', (data) => {
        var message = JSON.parse(data);
        console.log('Received message' + JSON.stringify(message));
        switch (message.type) {
            case MessageType.QUERY_LATEST:
                write(ws, responseLatestMsg());
                break;
            case MessageType.QUERY_ALL:
                write(ws, responseChainMsg());
                break;
            case MessageType.RESPONSE_BLOCKCHAIN:
                handleBlockchainResponse(message);
                break;
            case MessageType.PROPOSE_BLOCK: {
                const proposalData = JSON.parse(message.data);
                const proposedBlock = proposalData.block;
                const proposer = proposalData.proposer;
                const nodeId = NODE_ID;
                const blockHash = proposedBlock.hash;

                console.log(`Node ${nodeId} received proposal from Node ${proposer}, validating...`);

                if (!global.pendingProposals) global.pendingProposals = {};
                global.pendingProposals[blockHash] = proposedBlock;

                if (!global.voteTally) global.voteTally = {};
                if (!global.voteTally[blockHash]) {
                    global.voteTally[blockHash] = {
                        totalVoters: sockets.length,
                        proposer: proposer,
                        votes: {}
                    };
                }

                const valid = isValidNewBlock(proposedBlock, getLatestBlock());
                const voteResult = valid ? 'yes' : 'no';

                console.log(`Node ${nodeId} voted ${voteResult} for block ${proposedBlock.index}`);

                global.voteTally[blockHash].votes[nodeId] = voteResult;

                broadcast({
                    type: MessageType.NETWORK_VOTE,
                    data: JSON.stringify({ blockHash, nodeId, vote: voteResult })
                });

                checkConsensus(blockHash);
                break;
            }
            case MessageType.NETWORK_VOTE: {
                const voteData = JSON.parse(message.data);
                const { blockHash, nodeId, vote } = voteData;

                if (!global.voteTally || !global.voteTally[blockHash]) {
                    console.log(`Received vote for unknown block, ignoring`);
                    break;
                }

                global.voteTally[blockHash].votes[nodeId] = vote;
                const currentNodeId = NODE_ID;
                console.log(`Node ${currentNodeId} received: Node ${nodeId} voted ${vote}`);

                checkConsensus(blockHash);
                break;
            }
        }
    });
};

function hasVoterAlreadyVoted(voterHash) {
    for (let i = 1; i < blockchain.length; i++) {
        if (blockchain[i].voterHash === voterHash) return true;
    }
    return false;
}

function isVoterInPendingProposals(voterHash) {
    if (!global.pendingProposals) return false;
    for (const [hash, block] of Object.entries(global.pendingProposals)) {
        if (block && block.voterHash === voterHash) return true;
    }
    return false;
}

function hexToBigInt(h) { 
    return BigInt('0x' + h.replace(/^0x/, '')); 
}

function bigIntToHex(x) { 
    return '0x' + x.toString(16); 
}

function ensureTotalsLength(len) {
    if (!ENC_TOTALS || ENC_TOTALS.length !== len) {
        ENC_TOTALS = new Array(len).fill(1n);
    }
}

function ensureN2() {
    if (N2) return true;
    if (HE_PUB && HE_PUB.n) {
        N2 = HE_PUB.n * HE_PUB.n;
        console.log('Computed n^2 lazily for encrypted totals');
        return true;
    }
    return false;
}

function applyEncryptedVectorToTotals(encVecHex) {
    if (!ensureN2()) { throw new Error('N2 not initialized'); }
    const len = encVecHex.length;
    ensureTotalsLength(len);
    for (let i = 0; i < len; i++) {
        const c = hexToBigInt(encVecHex[i]);
        ENC_TOTALS[i] = (ENC_TOTALS[i] * c) % N2;
    }
}

function recomputeEncryptedTotalsFromChain() {
    if (!ensureN2()) { throw new Error('N2 not initialized'); }
    ENC_TOTALS = null;
    for (const b of blockchain) {
        if (b.index === 0) continue;
        if (b.blockType && b.blockType !== 'VOTE') continue;
        if (Array.isArray(b.encryptedVoteVector)) {
            applyEncryptedVectorToTotals(b.encryptedVoteVector);
        }
    }
    console.log('Recomputed ENC_TOTALS from chain');
}

function checkConsensus(blockHash) {
    if (!global.voteTally || !global.voteTally[blockHash]) return;

    const tally = global.voteTally[blockHash];
    const votes = tally.votes;
    const receivedVotes = Object.keys(votes).length;
    const totalVoters = tally.totalVoters;
    const proposer = tally.proposer;
    const nodeId = NODE_ID;

    console.log(`Node ${nodeId}: Received ${receivedVotes}/${totalVoters} votes`);

    if (receivedVotes < totalVoters) return;

    const yesVotes = Object.values(votes).filter(v => v === 'yes').length;
    const noVotes = totalVoters - yesVotes;
    const decision = yesVotes > noVotes ? 'accept' : 'reject';

    const isProposer = nodeId === proposer;
    console.log(`Node ${nodeId} ${isProposer ? '(proposer)' : ''} — Consensus: ${yesVotes} yes, ${noVotes} no → ${decision}`);

    const block = global.pendingProposals[blockHash];
    if (decision === 'accept' && block) {
        addBlock(block);
        console.log(`Node ${nodeId} added block ${block.index}`);
        if (!block.blockType || block.blockType === 'VOTE') {
            if (Array.isArray(block.encryptedVoteVector)) {
                try { 
                    applyEncryptedVectorToTotals(block.encryptedVoteVector); 
                } catch (e) { 
                    console.error('Encrypted totals update skipped:', e.message); 
                }
            }
            TOTAL_VOTES += 1;
        }
        broadcast(responseLatestMsg());
    } else {
        console.log(`Node ${nodeId} rejected block`);
    }

    delete global.pendingProposals[blockHash];
    delete global.voteTally[blockHash];
}

var initErrorHandler = (ws) => {
    var closeConnection = (ws) => {
        console.log('connection failed to peer: ' + ws.url);
        sockets.splice(sockets.indexOf(ws), 1);
    };
    ws.on('close', () => closeConnection(ws));
    ws.on('error', () => closeConnection(ws));
};

var connectToPeers = (newPeers) => {
    newPeers.forEach((peer) => {
        var ws = new WebSocket(peer);
        ws.on('open', () => initConnection(ws));
        ws.on('error', () => {
            console.log('connection failed')
        });
    });
};

var handleBlockchainResponse = (message) => {
    var receivedBlocks = JSON.parse(message.data).sort((b1, b2) => (b1.index - b2.index));
    var latestBlockReceived = receivedBlocks[receivedBlocks.length - 1];
    var latestBlockHeld = getLatestBlock();
    if (latestBlockReceived.index > latestBlockHeld.index) {
        console.log('blockchain possibly behind. We got: ' + latestBlockHeld.index + ' Peer got: ' + latestBlockReceived.index);
        if (latestBlockHeld.hash === latestBlockReceived.previousHash) {
            console.log("We can append the received block to our chain");
            blockchain.push(latestBlockReceived);
            broadcast(responseLatestMsg());
        } else if (receivedBlocks.length === 1) {
            console.log("We have to query the chain from our peer");
            broadcast(queryAllMsg());
        } else {
            console.log("Received blockchain is longer than current blockchain");
            replaceChain(receivedBlocks);
        }
    } else {
        console.log('received blockchain is not longer than current blockchain. Do nothing');
    }
};

var replaceChain = (newBlocks) => {
    if (isValidChain(newBlocks) && newBlocks.length > blockchain.length) {
        blockchain = newBlocks;
        try { 
            recomputeEncryptedTotalsFromChain(); 
        } catch (e) { 
            console.error('Failed to recompute encrypted totals:', e); 
        }
        broadcast(responseLatestMsg());
    } else {
        console.log('Received blockchain invalid');
    }
};

var isValidChain = (blockchainToValidate) => {
    if (JSON.stringify(blockchainToValidate[0]) !== JSON.stringify(getGenesisBlock())) {
        return false;
    }
    var tempBlocks = [blockchainToValidate[0]];
    for (var i = 1; i < blockchainToValidate.length; i++) {
        if (isValidNewBlock(blockchainToValidate[i], tempBlocks[i - 1])) {
            tempBlocks.push(blockchainToValidate[i]);
        } else {
            return false;
        }
    }
    return true;
};

var queryChainLengthMsg = () => ({ 'type': MessageType.QUERY_LATEST });
var queryAllMsg = () => ({ 'type': MessageType.QUERY_ALL });
var responseChainMsg = () => ({
    'type': MessageType.RESPONSE_BLOCKCHAIN, 
    'data': JSON.stringify(blockchain)
});
var responseLatestMsg = () => ({
    'type': MessageType.RESPONSE_BLOCKCHAIN,
    'data': JSON.stringify([getLatestBlock()])
});

var write = (ws, message) => ws.send(JSON.stringify(message));
var broadcast = (message) => sockets.forEach(socket => write(socket, message));

// Boot sequence
(async () => {
    const rootOk = await fetchMerkleRoot();
    const heOk = await fetchHePublicKey();
    if (!rootOk || !heOk) {
        console.error('Cannot start without Merkle Root and HE key. Exiting.');
        process.exit(1);
    }

    try { 
        recomputeEncryptedTotalsFromChain(); 
    } catch (e) { 
        console.error('Recompute ENC totals failed:', e); 
    }

    connectToPeers(initialPeers);
    initHttpServer();
    initP2PServer();
    console.log(`Node ${NODE_ID} ready with Merkle Root: ${MERKLE_ROOT}`);
})();
