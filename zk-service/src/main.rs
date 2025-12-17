use std::{env, net::SocketAddr};

use axum::{http::StatusCode, routing::post, Json, Router};
use paillier_zk::{
    fast_paillier::{DecryptionKey, EncryptionKey},
    paillier_encryption_in_range as bit_zk,
    paillier_affine_operation_in_range as affine_zk,
    rug::{self, Complete, Integer},
    IntegerExt,
};
use generic_ec::{Point, curves::Secp256k1 as E};
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing_subscriber::prelude::*;
use tracing;
use anyhow::Result;

const SEED_ENC_ZERO: u64 = 42;
const SEED_ENC_ONE: u64 = 43;

//
// JSON types
//
#[derive(Deserialize)]
struct GenerateVoteProofsRequest {
    vote_vector: Vec<u64>,
}

#[derive(Serialize)]
struct GenerateVoteProofsResponse {
    encrypted_vote_vector: Vec<String>,
    bit_proofs: Vec<serde_json::Value>,
    sum_proof: serde_json::Value,
}

#[derive(Deserialize)]
struct VerifyVoteRequest {
    encrypted_vote_vector: Vec<String>,
    bit_proofs: Vec<serde_json::Value>,
    sum_proof: serde_json::Value,
}

#[derive(Serialize)]
struct VoteVerificationDetails {
    all_bits_valid: bool,
    sum_consistency_valid: bool,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    details: VoteVerificationDetails,
}

#[derive(Deserialize)]
struct HePublicKeyResponse {
    n: String,
    g: String,
    scheme: String,
}

#[derive(Deserialize)]
struct DecryptWithKeyRequest {
    ciphertext: String,
    decryption_key: DecryptKeyJson,
}

#[derive(Serialize, Deserialize)]
struct DecryptKeyJson {
    p: String,
    q: String,
}

#[derive(Serialize)]
struct DecryptResult {
    plaintext: String,
    low_bits: u64,
}

//
// Bit proof JSON
//
#[derive(Serialize, Deserialize)]
struct BitProofJson {
    a: String,
    c: String,
    s: String,
    z1: String,
    z2: String,
    z3: String,
}

fn encode_bit_proof(commitment: &bit_zk::Commitment, proof: &bit_zk::Proof) -> serde_json::Value {
    let a = commitment.a.to_string_radix(16);
    let c = commitment.c.to_string_radix(16);
    let s = commitment.s.to_string_radix(16);
    let z1 = proof.z1.to_string_radix(16);
    let z2 = proof.z2.to_string_radix(16);
    let z3 = proof.z3.to_string_radix(16);

    serde_json::json!(BitProofJson { a, c, s, z1, z2, z3 })
}

fn decode_bit_proof(v: &serde_json::Value) -> anyhow::Result<(bit_zk::Commitment, bit_zk::Proof)> {
    let bp: BitProofJson = serde_json::from_value(v.clone())?;

    let a = Integer::from_str_radix(&bp.a, 16)?;
    let c = Integer::from_str_radix(&bp.c, 16)?;
    let s = Integer::from_str_radix(&bp.s, 16)?;
    let z1 = Integer::from_str_radix(&bp.z1, 16)?;
    let z2 = Integer::from_str_radix(&bp.z2, 16)?;
    let z3 = Integer::from_str_radix(&bp.z3, 16)?;

    Ok((bit_zk::Commitment { a, c, s }, bit_zk::Proof { z1, z2, z3 }))
}

//
// Affine (sum=1) proof JSON
//
#[derive(Serialize, Deserialize)]
struct AffineProofJson {
    a: String,
    b_x: String,
    b_y: String,
    e: String,
    s: String,
    f: String,
    t: String,
    z1: String,
    z2: String,
    z3: String,
    z4: String,
    w: String,
    w_y: String,
}

fn point_to_hex(p: &Point<E>) -> String {
    let encoded = p.to_bytes(true);
    hex::encode(encoded.as_bytes())
}

fn point_from_hex(s: &str) -> Point<E> {
    let bytes = hex::decode(s).unwrap();
    Point::<E>::from_bytes(&bytes).unwrap() 
}

fn encode_affine_proof(
    c: &affine_zk::Commitment<E>,
    p: &affine_zk::Proof,
) -> serde_json::Value {
    let json = AffineProofJson {
        a: c.a.to_string_radix(16),
        b_x: point_to_hex(&c.b_x),
        b_y: c.b_y.to_string_radix(16),
        e: c.e.to_string_radix(16),
        s: c.s.to_string_radix(16),
        f: c.f.to_string_radix(16),
        t: c.t.to_string_radix(16),
        z1: p.z1.to_string_radix(16),
        z2: p.z2.to_string_radix(16),
        z3: p.z3.to_string_radix(16),
        z4: p.z4.to_string_radix(16),
        w: p.w.to_string_radix(16),
        w_y: p.w_y.to_string_radix(16),
    };
    serde_json::to_value(json).unwrap()
}

fn decode_affine_proof(
    v: &serde_json::Value,
) -> anyhow::Result<(affine_zk::Commitment<E>, affine_zk::Proof)> {
    let ap: AffineProofJson = serde_json::from_value(v.clone())?;

    let a = Integer::from_str_radix(&ap.a, 16)?;
    let b_x = point_from_hex(&ap.b_x);
    let b_y = Integer::from_str_radix(&ap.b_y, 16)?;
    let e = Integer::from_str_radix(&ap.e, 16)?;
    let s = Integer::from_str_radix(&ap.s, 16)?;
    let f = Integer::from_str_radix(&ap.f, 16)?;
    let t = Integer::from_str_radix(&ap.t, 16)?;

    let z1 = Integer::from_str_radix(&ap.z1, 16)?;
    let z2 = Integer::from_str_radix(&ap.z2, 16)?;
    let z3 = Integer::from_str_radix(&ap.z3, 16)?;
    let z4 = Integer::from_str_radix(&ap.z4, 16)?;
    let w  = Integer::from_str_radix(&ap.w, 16)?;
    let w_y = Integer::from_str_radix(&ap.w_y, 16)?;

    let commitment = affine_zk::Commitment::<E> { a, b_x, b_y, e, s, f, t };
    let proof = affine_zk::Proof { z1, z2, z3, z4, w, w_y };

    Ok((commitment, proof))
}

fn safe_bit_length(n: &Integer) -> u32 {
    if *n == Integer::ZERO { 0 } else { n.significant_bits() as u32 }
}

fn build_aux_bits(key: &EncryptionKey) -> bit_zk::Aux {
    bit_zk::Aux {
        crt: None,
        multiexp: None,
        rsa_modulo: key.n().clone(),
        s: Integer::from(42u32),
        t: Integer::from(123u32),
    }
}

fn build_sec_bits() -> bit_zk::SecurityParams {
    bit_zk::SecurityParams {
        l: 64,
        epsilon: 80,
        q: (Integer::ONE << 80_u32).complete(),
    }
}

fn build_affine_aux() -> affine_zk::Aux {
    affine_zk::Aux {
        s: Integer::from(2u32),
        t: Integer::from(3u32),
        rsa_modulo: Integer::from(10403u32),
        multiexp: None,
        crt: None,
    }
}

fn build_affine_sec() -> affine_zk::SecurityParams {
    let secp256k1_order = Integer::from_str_radix(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 
        16
    ).unwrap();

    affine_zk::SecurityParams {
        l_x: 64,
        l_y: 64,
        epsilon: 128,
        q: secp256k1_order,
    }
}

fn deterministic_encrypt(
    key: &EncryptionKey,
    plaintext: &Integer,
    seed: u64,
) -> (Integer, Integer) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    key.encrypt_with_random(&mut rng, plaintext)
        .expect("deterministic encrypt")
}

fn authority_url() -> String {
    env::var("AUTHORITY_URL").unwrap_or_else(|_| "http://authority:4000".to_string())
}

async fn get_encryption_key() -> EncryptionKey {
    let url = format!("{}/hePublicKey", authority_url());
    let resp = reqwest::get(&url)
        .await
        .expect("failed to call authority /hePublicKey");
    let body: HePublicKeyResponse = resp.json().await.expect("invalid JSON");

    let n_hex = body.n.trim_start_matches("0x");
    let n_bytes = hex::decode(n_hex).expect("invalid hex n");
    let n = Integer::from_digits(&n_bytes, rug::integer::Order::MsfBe);

    assert!(!n.is_even());
    assert!(n > Integer::from(2u32.pow(10)));

    EncryptionKey::from_n(n)
}

//
// Handlers
//
async fn generate_vote_proofs(Json(req): Json<GenerateVoteProofsRequest>) -> Json<GenerateVoteProofsResponse> {
    let mut rng = OsRng;
    let key = get_encryption_key().await;
    tracing::info!("✅ Key loaded: {} bits", safe_bit_length(key.n()));

    let aux_bits = build_aux_bits(&key);
    let sec_bits = build_sec_bits();
    let shared_state_bits = "vote_bits";

    if req.vote_vector.iter().any(|&v| v > 1) {
        return Json(GenerateVoteProofsResponse {
            encrypted_vote_vector: vec![],
            bit_proofs: vec![],
            sum_proof: serde_json::json!({"error": "votes must be 0 or 1"}),
        });
    }

    let mut encrypted_vote_vector = Vec::new();
    let mut bit_proofs = Vec::new();
    let mut vote_nonces = Vec::new();

    // 1. Per-bit encryption + bit proofs
    for (i, &vote) in req.vote_vector.iter().enumerate() {
        tracing::info!("🔄 Vote {}/{}", i + 1, req.vote_vector.len());

        let plaintext = if vote == 1 {
            Integer::ONE.clone()
        } else {
            Integer::ZERO.clone()
        };

        let (ciphertext, nonce) = key.encrypt_with_random(&mut rng, &plaintext).unwrap();
        let n_sq = key.n().clone().square();
        tracing::info!("🔐 Ciphertext OK: {} < n²", ciphertext < n_sq);

        let data = bit_zk::Data { key: &key, ciphertext: &ciphertext };
        let private = bit_zk::PrivateData { plaintext: &plaintext, nonce: &nonce };

        let (commitment, proof) = bit_zk::non_interactive::prove::<Sha256>(
            &shared_state_bits,
            &aux_bits,
            data,
            private,
            &sec_bits,
            &mut rng,
        ).expect("bit ZK prove");

        let ct_hex = ciphertext.to_string_radix(16);
        encrypted_vote_vector.push(ct_hex);
        bit_proofs.push(encode_bit_proof(&commitment, &proof));
        vote_nonces.push(nonce);
        tracing::info!("✅ Bit proof {} OK", i);
    }

    // 2. Compute homomorphic sum and combined nonce
    let mut sum_ct_opt: Option<Integer> = None;
    let mut combined_nonce_opt: Option<Integer> = None;
    let n_sq = key.n().clone().square();

    for (ct_hex, nonce) in encrypted_vote_vector.iter().zip(vote_nonces.iter()) {
        let ct = Integer::from_str_radix(ct_hex, 16).unwrap();
        assert!(ct < n_sq, "Prover ct invalid");

        sum_ct_opt = Some(match sum_ct_opt {
            None => ct,
            Some(acc) => key.oadd(&acc, &ct).expect("prover oadd"),
        });

        combined_nonce_opt = Some(match combined_nonce_opt {
            None => nonce.clone(),
            Some(acc_r) => (acc_r * nonce) % key.n(),
        });
    }

    let sum_ct = sum_ct_opt.unwrap_or(Integer::ZERO);
    let combined_nonce = combined_nonce_opt.unwrap_or(Integer::ONE.clone());
    tracing::info!("🔢 sum_ct computed");

    // 3. NEW APPROACH: Prove that (sum_ct - Enc(1)) = Enc(0)
    //
    // Strategy:
    //   - Compute diff_ct = sum_ct / Enc(1) homomorphically
    //   - This equals Enc(sum - 1) with nonce = combined_nonce / nonce_one
    //   - If sum = 1, then diff_ct = Enc(0)
    //   - Prove: diff_ct = Enc(0)^0 * Enc(0) using affine proof

    let aux_affine = build_affine_aux();
    let sec_affine = build_affine_sec();
    let shared_state_affine = "vote_sum_onehot";

    // Get Enc(1) and Enc(0) with deterministic nonces
    let (enc_one, nonce_one) = deterministic_encrypt(&key, &Integer::ONE, SEED_ENC_ONE);
    let (enc_zero, nonce_zero) = deterministic_encrypt(&key, &Integer::ZERO, SEED_ENC_ZERO);

    // Homomorphically compute: diff_ct = sum_ct / Enc(1)
    // In Paillier: division is multiplication by modular inverse
    let enc_one_inv = enc_one.clone().invert(&n_sq).expect("enc_one invert");
    let diff_ct = key.omul(&Integer::ONE, &enc_one_inv).expect("omul inv");
    let diff_ct = key.oadd(&sum_ct, &diff_ct).expect("oadd diff");

    // Compute the nonce for diff_ct
    // Since diff_ct = Enc(sum) / Enc(1), the nonce is: combined_nonce / nonce_one mod n
    let nonce_one_inv = nonce_one.clone().invert(key.n()).expect("nonce_one invert");
    let nonce_diff = (combined_nonce.clone() * nonce_one_inv) % key.n();

    tracing::info!("🔢 diff_ct = sum_ct - Enc(1) computed");

    // Now prove: diff_ct = Enc(0)^0 * Enc(0)
    // This means: D = C^X + Y where:
    //   C = Enc(0), X = 0, Y = Enc(0), D = diff_ct
    //   
    // The witness:
    //   x = 0, y = 0
    //   nonce = nonce_diff (randomness of D = diff_ct)
    //   nonce_y = nonce_zero (randomness of Y = Enc(0))

    let plaintext_x = Integer::ZERO;
    let plaintext_y = Integer::ZERO;

    let ciphertext_c = enc_zero.clone();
    let ciphertext_x = Point::<E>::generator() * plaintext_x.to_scalar();
    let ciphertext_y = enc_zero.clone();
    let ciphertext_d = diff_ct;

    let data_affine = affine_zk::Data {
        key0: &key,
        key1: &key,
        c: &ciphertext_c,
        d: &ciphertext_d,
        x: &ciphertext_x,
        y: &ciphertext_y,
    };

    let pdata_affine = affine_zk::PrivateData {
        x: &plaintext_x,
        y: &plaintext_y,
        nonce: &nonce_diff,
        nonce_y: &nonce_zero,
    };

    let (commitment_affine, proof_affine) =
        affine_zk::non_interactive::prove::<E, Sha256>(
            &shared_state_affine,
            &aux_affine,
            data_affine,
            pdata_affine,
            &sec_affine,
            &mut rng,
        ).expect("affine sum=1 prove");

    let sum_proof = encode_affine_proof(&commitment_affine, &proof_affine);
    tracing::info!("✅ Sum=1 proof (via subtraction) OK");

    Json(GenerateVoteProofsResponse {
        encrypted_vote_vector,
        bit_proofs,
        sum_proof,
    })
}

async fn verify_vote(Json(req): Json<VerifyVoteRequest>) -> Json<VerifyResponse> {
    let key = get_encryption_key().await;

    let aux_bits = build_aux_bits(&key);
    let sec_bits = build_sec_bits();
    let shared_state_bits = "vote_bits";
    let n_sq = key.n().clone().square();

    let mut all_bits_valid = true;

    // 1. Verify bit proofs
    for (ct_hex, proof_val) in req.encrypted_vote_vector.iter().zip(req.bit_proofs.iter()) {
        let ciphertext = match Integer::from_str_radix(ct_hex, 16) {
            Ok(ct) => {
                if ct >= n_sq || ct.is_negative() {
                    tracing::warn!("Invalid ct");
                    all_bits_valid = false;
                    break;
                }
                ct
            }
            Err(_) => {
                all_bits_valid = false;
                break;
            }
        };

        let (commitment, proof) = match decode_bit_proof(proof_val) {
            Ok(p) => p,
            Err(_) => {
                all_bits_valid = false;
                break;
            }
        };

        let data = bit_zk::Data { key: &key, ciphertext: &ciphertext };

        if bit_zk::non_interactive::verify::<Sha256>(
            &shared_state_bits,
            &aux_bits,
            data,
            &commitment,
            &sec_bits,
            &proof,
        ).is_err() {
            all_bits_valid = false;
            break;
        }
    }

    // 2. Recompute sum_ct from submitted ciphertexts
    let mut sum_ct_opt: Option<Integer> = None;
    for (i, ct_hex) in req.encrypted_vote_vector.iter().enumerate() {
        let ct = match Integer::from_str_radix(ct_hex, 16) {
            Ok(ct) => ct,
            Err(e) => {
                tracing::warn!("Invalid ct[{}]: {}", i, e);
                all_bits_valid = false;
                break;
            }
        };
        
        if ct >= n_sq || ct.is_negative() {
            tracing::warn!("Invalid ct[{}]: out of range", i);
            all_bits_valid = false;
            break;
        }
        
        sum_ct_opt = Some(match sum_ct_opt {
            None => ct,
            Some(ref acc) => {
                match key.oadd(acc, &ct) {
                    Ok(result) => result,
                    Err(e) => {
                        tracing::error!("oadd failed at ct[{}]: {:?}", i, e);
                        all_bits_valid = false;
                        break;
                    }
                }
            }
        });
    }

    let sum_ct = sum_ct_opt.unwrap_or_else(|| Integer::ZERO);

    // 3. Verify affine sum=1 proof using subtraction approach
    let aux_affine = build_affine_aux();
    let sec_affine = build_affine_sec();
    let shared_state_affine = "vote_sum_onehot";

    let (commitment_affine, proof_affine) = match decode_affine_proof(&req.sum_proof) {
        Ok(x) => x,
        Err(e) => {
            tracing::error!("Failed to decode affine proof: {:?}", e);
            let details = VoteVerificationDetails {
                all_bits_valid,
                sum_consistency_valid: false,
            };
            return Json(VerifyResponse {
                valid: false,
                details,
            });
        }
    };

    // Recompute diff_ct = sum_ct / Enc(1)
    let (enc_one, _) = deterministic_encrypt(&key, &Integer::ONE, SEED_ENC_ONE);
    let (enc_zero, _) = deterministic_encrypt(&key, &Integer::ZERO, SEED_ENC_ZERO);

    let enc_one_inv = enc_one.clone().invert(&n_sq).expect("enc_one invert");
    let diff_ct = key.omul(&Integer::ONE, &enc_one_inv).expect("omul inv");
    let diff_ct = key.oadd(&sum_ct, &diff_ct).expect("oadd diff");

    // Reconstruct the same public data as prover:
    // C = Enc(0), X = g^0, Y = Enc(0), D = diff_ct
    let ciphertext_c = enc_zero.clone();
    let ciphertext_x = Point::<E>::generator() * Integer::ZERO.to_scalar();
    let ciphertext_y = enc_zero.clone();
    let ciphertext_d = diff_ct;

    let data_affine = affine_zk::Data {
        key0: &key,
        key1: &key,
        c: &ciphertext_c,
        d: &ciphertext_d,
        x: &ciphertext_x,
        y: &ciphertext_y,
    };

    let sum_consistency_valid = affine_zk::non_interactive::verify::<E, Sha256>(
        &shared_state_affine,
        &aux_affine,
        data_affine,
        &commitment_affine,
        &sec_affine,
        &proof_affine,
    ).is_ok();

    tracing::info!("Sum consistency valid: {}", sum_consistency_valid);

    let details = VoteVerificationDetails {
        all_bits_valid,
        sum_consistency_valid,
    };

    Json(VerifyResponse {
        valid: all_bits_valid && sum_consistency_valid,
        details,
    })
}

fn decode_decryption_key(json: &DecryptKeyJson) -> Result<DecryptionKey> {
    let p_hex = json.p.trim_start_matches("0x");
    let q_hex = json.q.trim_start_matches("0x");

    let p = Integer::from_str_radix(p_hex, 16)?;
    let q = Integer::from_str_radix(q_hex, 16)?;
    DecryptionKey::from_primes(p, q).map_err(Into::into)
}

async fn decrypt_with_key(
    Json(req): Json<DecryptWithKeyRequest>,
) -> Result<Json<DecryptResult>, StatusCode> {
    let dec_key = decode_decryption_key(&req.decryption_key)
        .map_err(|e| {
            tracing::error!("decode_decryption_key failed: {:?}", e);
            StatusCode::BAD_REQUEST
        })?;

    let ct = Integer::from_str_radix(&req.ciphertext.replace("0x", ""), 16)
        .map_err(|e| {
            tracing::error!("ciphertext parse failed: {:?}", e);
            StatusCode::BAD_REQUEST
        })?;

    let mut plaintext = dec_key.decrypt(&ct)
        .map_err(|e| {
            tracing::error!("decrypt failed: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let key = get_encryption_key().await;
    plaintext %= key.n();

    Ok(Json(DecryptResult {
        plaintext: plaintext.to_string(),
        low_bits: 0,
    }))
}

async fn health() -> &'static str { "OK" }

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "paillier_zk_service=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app = Router::new()
        .route("/generate_vote_proofs", post(generate_vote_proofs))
        .route("/verify_vote", post(verify_vote))
        .route("/health", post(health))
        .route("/decrypt_with_key", post(decrypt_with_key));

    let addr = SocketAddr::from(([0, 0, 0, 0], 5000));
    tracing::info!("listening on {}", addr);

    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}
