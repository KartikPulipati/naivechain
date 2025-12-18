# Decentralized Blockchain Voting System

A proof-of-concept voting system using a blockchain plus homomorphic encryption and zero-knowledge proofs so nodes can validate votes without learning how anyone voted. This uses the [Naivechain](https://github.com/lhartikk/naivechain) implementation as a foundation. 

## What runs

This project starts four containerized components: an **authority** service, a Rust **zk-service**, and three blockchain nodes (**node1**, **node2**, **node3**) wired together via Docker Compose.
The authority exposes endpoints for the Merkle root and Paillier public key, which are used during voting.

## Start (Docker)

Build and start everything:

```bash
docker-compose up --build
```

## Cast votes (client)

In a separate terminal run the vote client:

```bash
node vote-client.js <node-url> <voter-id> <candidate-index>
```

Example:

```bash
node vote-client.js http://localhost:3001 VOTER001 0
```

The vote client fetches a Merkle proof from the authority, gets the homomorphic encryption public key, requests the encrypted vote + ZK proofs from the zk-service, then submits everything to the chosen node.[2]

## Show results (client)

Run the tally viewer:

```bash
node show-tally.js <node-url>
```

Example:

```bash
node show-tally.js http://localhost:3001
```

This script fetches encrypted totals from the node and sends them to the authority for decryption, then prints the plaintext totals per candidate.[3]

## Useful node endpoints

View the chain:

```bash
curl http://localhost:3001/blocks
```

View election config:

```bash
curl http://localhost:3001/config
```
