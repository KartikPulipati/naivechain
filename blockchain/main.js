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
const ELECTION_START = process.env.ELECTION_START ? parseInt(process.env.ELECTION_START, 10) : null; // epoch seconds or null
const ELECTION_END = process.env.ELECTION_END ? parseInt(process.env.ELECTION_END, 10) : null;       // epoch seconds or null

// Candidate ordering for tally display (no validation enforced here)
const CANDIDATES = ["candidateA", "candidateB", "candidateC"];

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

// Block structure: vector-only voting
class Block {
    constructor(index, previousHash, timestamp, voterHash, merkleProof, voteVector, hash) {
        this.index = index;
        this.previousHash = previousHash.toString();
        this.timestamp = timestamp;
        this.voterHash = voterHash;
        this.merkleProof = merkleProof;
        this.voteVector = voteVector;
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
        "816534932c2b7154836da6afc367695e6337db8a921823784c14378abed4f7d7"
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

/**
 * Verify a Merkle inclusion proof
 * @param {string} leaf - voter hash (hex string)
 * @param {Array} proof - array of {position: "left"|"right", data: {type:"Buffer", data:[...]}}
 * @param {string} expectedRoot - merkle root (hex with or without 0x prefix)
 * @returns {boolean} true if proof is valid
 */
function verifyMerkleProof(leaf, proof, expectedRoot) {
    try {
        // Strip 0x prefix if present
        const cleanRoot = expectedRoot.startsWith('0x') ? expectedRoot.slice(2) : expectedRoot;
        
        // Start with the leaf as a Buffer
        let currentHash = Buffer.from(leaf, 'hex');
        
        // Walk up the tree
        for (let i = 0; i < proof.length; i++) {
            const sibling = proof[i];
            const siblingData = Buffer.from(sibling.data.data);
            
            // Concatenate based on position
            let combined;
            if (sibling.position === 'left') {
                combined = Buffer.concat([siblingData, currentHash]);
            } else {
                combined = Buffer.concat([currentHash, siblingData]);
            }
            
            // Hash the concatenation
            currentHash = crypto.createHash('sha256').update(combined).digest();
        }
        
        // Compare computed root with expected root
        const computedRoot = currentHash.toString('hex');
        return computedRoot === cleanRoot;
    } catch (err) {
        console.error('Merkle proof verification error:', err);
        return false;
    }
}

// Hashing over vector contents
var calculateHash = (index, previousHash, timestamp, voterHash, merkleProof, voteVector) => {
    const votePart = Array.isArray(voteVector) ? JSON.stringify(voteVector) : "";
    return CryptoJS.SHA256(
        index + previousHash + timestamp + voterHash + JSON.stringify(merkleProof) + votePart
    ).toString();
};

var calculateHashForBlock = (block) => {
    return calculateHash(
        block.index,
        block.previousHash,
        block.timestamp,
        block.voterHash,
        block.merkleProof,
        block.voteVector
    );
};

// Block creation
var generateNextBlock = (voterHash, merkleProof, voteVector) => {
    var previousBlock = getLatestBlock();
    var nextIndex = previousBlock.index + 1;
    var nextTimestamp = new Date().getTime() / 1000;
    var nextHash = calculateHash(
        nextIndex,
        previousBlock.hash,
        nextTimestamp,
        voterHash,
        merkleProof,
        voteVector
    );
    return new Block(
        nextIndex,
        previousBlock.hash,
        nextTimestamp,
        voterHash,
        merkleProof,
        voteVector,
        nextHash
    );
};

// Block validation with Merkle proof verification
var isValidNewBlock = (newBlock, previousBlock) => {
    if (previousBlock.index + 1 !== newBlock.index) {
        console.log('invalid index'); return false;
    } else if (previousBlock.hash !== newBlock.previousHash) {
        console.log('invalid previoushash'); return false;
    } else if (calculateHashForBlock(newBlock) !== newBlock.hash) {
        console.log('invalid hash'); return false;
    }

    if (newBlock.index === 0) return true;

    if (!MERKLE_ROOT) {
        console.log('Merkle root not yet fetched, cannot verify voter eligibility');
        return false;
    }

    if (!verifyMerkleProof(newBlock.voterHash, newBlock.merkleProof, MERKLE_ROOT)) {
        console.log('invalid merkle proof: voter not in eligible set');
        return false;
    }

    // Double-vote protection (on-chain)
    if (hasVoterAlreadyVoted(newBlock.voterHash)) {
        console.log('double vote detected: voter already voted');
        return false;
    }

    // Optional: reject if another pending proposal already uses this voterHash
    if (isVoterInPendingProposals(newBlock.voterHash)) {
        // Allow the exact same object we are validating; only reject if a distinct pending entry conflicts
        for (const [h, b] of Object.entries(global.pendingProposals || {})) {
            if (b && b !== newBlock && b.voterHash === newBlock.voterHash) {
                console.log('conflict: pending proposal uses same voterHash');
                return false;
            }
        }
    }

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
                if (blockchain[i].voterHash === voterHash) { blockIndex = i; break; }
            }
        }
        res.json({ voterHash, voted, blockIndex });
    });


    // Mine/propose a block (proposer does not vote)
    app.post('/mineBlock', async (req, res) => {
        try {
            const now = Math.floor(Date.now()/1000);
            if (ELECTION_START && now < ELECTION_START) {
                return res.status(403).json({ error: 'Election not started' });
            }
            
            if (ELECTION_END && now > ELECTION_END) {
                return res.status(403).json({ error: 'Election ended' });
            }

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

            // Double-vote protection (on-chain)
            if (hasVoterAlreadyVoted(voterHash)) {
                return res.status(409).json({ error: 'Double vote rejected: voter has already voted' });
            }

            // Optional: prevent conflicting concurrent proposals
            if (isVoterInPendingProposals(voterHash)) {
                return res.status(409).json({ error: 'Conflicting pending proposal exists for this voter' });
            }

            console.log(`Node ${NODE_ID} proposing new block (not voting)`);

            const newBlock = generateNextBlock(voterHash, merkleProof, voteVector);
            const blockHash = newBlock.hash;

            if (!global.pendingProposals) global.pendingProposals = {};
            global.pendingProposals[blockHash] = newBlock;

            if (!global.voteTally) global.voteTally = {};
            global.voteTally[blockHash] = {
                totalVoters: sockets.length,
                proposer: NODE_ID,
                votes: {}
            };

            console.log(`Node ${NODE_ID} waiting for ${sockets.length} votes from other nodes`);

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

    // Plaintext tally for testing
    /**
     * GET /tally
     * Computes an element-wise sum over voteVector in all non-genesis VOTE blocks.
     * - If the summed vector length matches ELECTION_CANDIDATES, returns a labeled object.
     * - Otherwise returns { totals: [...] }.
     * - Includes basic metadata for audit/debug.
     */
    app.get('/tally', (req, res) => {
        try {
            return res.json({
                candidates: ELECTION_CANDIDATES
            });
        } catch (err) {
            console.error('Error in /tally:', err);
            return res.status(500).json({ error: 'Tally failed' });
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

                // Validate including Merkle proof
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
    // skip genesis (index 0)
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
        broadcast(responseLatestMsg());
    } else {
        console.log(`Node ${nodeId} rejected block`);
    }

    delete global.pendingProposals[blockHash];
    delete global.voteTally[blockHash];
}

// Error handling
var initErrorHandler = (ws) => {
    var closeConnection = (ws) => {
        console.log('connection failed to peer: ' + ws.url);
        sockets.splice(sockets.indexOf(ws), 1);
    };
    ws.on('close', () => closeConnection(ws));
    ws.on('error', () => closeConnection(ws));
};

// Peer management and chain sync
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
        console.log('Received blockchain is valid. Replacing current blockchain with received blockchain');
        blockchain = newBlocks;
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

// Messaging helpers
var queryChainLengthMsg = () => ({ 'type': MessageType.QUERY_LATEST });
var queryAllMsg = () => ({ 'type': MessageType.QUERY_ALL });
var responseChainMsg = () => ({
    'type': MessageType.RESPONSE_BLOCKCHAIN, 'data': JSON.stringify(blockchain)
});
var responseLatestMsg = () => ({
    'type': MessageType.RESPONSE_BLOCKCHAIN,
    'data': JSON.stringify([getLatestBlock()])
});

var write = (ws, message) => ws.send(JSON.stringify(message));
var broadcast = (message) => sockets.forEach(socket => write(socket, message));

// Boot sequence
(async () => {
    // Fetch merkle root from authority first
    const rootFetched = await fetchMerkleRoot();
    if (!rootFetched) {
        console.error('Cannot start without Merkle Root. Exiting.');
        process.exit(1);
    }
    
    // Now start services
    connectToPeers(initialPeers);
    initHttpServer();
    initP2PServer();
    
    console.log(`Node ${NODE_ID} ready with Merkle Root: ${MERKLE_ROOT}`);
})();
