// Todo List
// 1. Verify Merkle Proofs of Voter Inclusion
// 2. Simple Double Voting Protections
// 3. Homomorphic Encryption for Vote Tallying
// 4. Zero-Knowledge Proof Verification for voteVector
// 5. Password attached to Voter ID for block proposals
// 6. Auditing Endpoints
// 7. Election Config Block (electionId, candidates, merkleRoot, keys)
// 8. Signed Validator Votes (NETWORK_VOTE authentication)

'use strict';
var CryptoJS = require("crypto-js");
var express = require("express");
var bodyParser = require('body-parser');
var WebSocket = require("ws");

// Config and identity
var http_port = process.env.HTTP_PORT || 3001;
var p2p_port = process.env.P2P_PORT || 6001;
var initialPeers = process.env.PEERS ? process.env.PEERS.split(',') : [];
const NODE_ID = process.env.NODE_ID || process.env.HTTP_PORT || 'unknown';

const CANDIDATES = ["candidateA", "candidateB", "candidateC"];

// Message types
var MessageType = {
    QUERY_LATEST: 0,
    QUERY_ALL: 1,
    RESPONSE_BLOCKCHAIN: 2,
    PROPOSE_BLOCK: 3,
    NETWORK_VOTE: 4
};

// Block structure: vector-only voting, no legacy vote string, no validation here
class Block {
    constructor(index, previousHash, timestamp, voterHash, merkleProof, voteVector, hash) {
        this.index = index;
        this.previousHash = previousHash.toString();
        this.timestamp = timestamp;
        this.voterHash = voterHash;
        this.merkleProof = merkleProof;
        this.voteVector = voteVector;   // Arbitrary numeric vector; validity deferred to ZKP
        this.hash = hash.toString();
    }
}

// Chain state
var sockets = [];
var blockchain = [getGenesisBlock()];

function getGenesisBlock() {
    // Empty vector in genesis for compatibility
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

// Hashing over vector contents (no semantic checks)
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

// Block creation (no validation of voteVector here)
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

// Minimal structural validation only (index/prev/hash), deferring vote checks to ZKP
var isValidNewBlock = (newBlock, previousBlock) => {
    if (previousBlock.index + 1 !== newBlock.index) {
        console.log('invalid index'); return false;
    } else if (previousBlock.hash !== newBlock.previousHash) {
        console.log('invalid previoushash'); return false;
    } else if (calculateHashForBlock(newBlock) !== newBlock.hash) {
        console.log('invalid hash'); return false;
    }
    // No voteVector validation here; ZKP verification to be added later
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

    // Mine/propose a block (proposer does not vote)
    app.post('/mineBlock', async (req, res) => {
        try {
            const { voterHash, merkleProof, voteVector } = req.body;

            // Minimal presence checks only; no voteVector validation
            if (!voterHash || !Array.isArray(merkleProof) || !Array.isArray(voteVector)) {
                return res.status(400).json({ error: 'voterHash, merkleProof, and voteVector are required' });
            }

            console.log(`Node ${NODE_ID} proposing new block (not voting)`);

            const newBlock = generateNextBlock(voterHash, merkleProof, voteVector);
            const blockHash = newBlock.hash;

            if (!global.pendingProposals) global.pendingProposals = {};
            global.pendingProposals[blockHash] = newBlock;

            if (!global.voteTally) global.voteTally = {};
            global.voteTally[blockHash] = {
                totalVoters: sockets.length, // only peers vote; proposer excluded
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

    // Plaintext tally for testing only (replace with HE + ZKP later)
    app.get('/tally', (req, res) => {
        try {
            // Determine vector length from first non-genesis block, fallback to CANDIDATES length
            let vecLen = CANDIDATES.length;
            for (const b of blockchain) {
                if (b.index > 0 && Array.isArray(b.voteVector)) {
                    vecLen = b.voteVector.length;
                    break;
                }
            }
            const totals = new Array(vecLen).fill(0);

            for (const block of blockchain) {
                if (block.index === 0) continue;
                if (Array.isArray(block.voteVector)) {
                    for (let i = 0; i < totals.length; i++) {
                        totals[i] += Number(block.voteVector[i] || 0);
                    }
                }
            }

            // Label by candidates if sizes match, else return raw vector
            if (totals.length === CANDIDATES.length) {
                const result = {};
                for (let i = 0; i < totals.length; i++) result[CANDIDATES[i]] = totals[i];
                return res.json(result);
            } else {
                return res.json({ totals });
            }
        } catch (err) {
            console.error('Error in /tally:', err);
            return res.status(500).json({ error: 'Tally failed' });
        }
    });

    app.get('/peers', (req, res) => {
        res.send(sockets.map(s => s._socket.remoteAddress + ':' + s._socket.remotePort));
    });

    app.post('/addPeer', (req, res) => {
        connectToPeers([req.body.peer]);
        res.send();
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
                        totalVoters: sockets.length, // only peers vote
                        proposer: proposer,
                        votes: {}
                    };
                }

                // Minimal structural validation only
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

// Boot
connectToPeers(initialPeers);
initHttpServer();
initP2PServer();
