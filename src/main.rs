
extern crate secp256k1;

use std::time::{Duration, Instant};

use blstrs::{Gt, Bls12, G1Projective, G1Affine, G2Affine, G2Projective, Scalar};
use group::{prime::PrimeCurveAffine, Curve, Group};
use ff::Field;
use pairing_lib::MillerLoopResult;
use pairing_lib::MultiMillerLoop;

use secp256k1::ecdsa::Signature;
use secp256k1::rand::rngs::OsRng;
use secp256k1::All;
use secp256k1::PublicKey;
use secp256k1::SecretKey;
use secp256k1::{Secp256k1, Message};
use secp256k1::hashes::{sha256, Hash};

const CSUITE: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

// Example message to be signed and verified
const MSG: &[u8; 11] = b"Hello, BLS!";

const BATCH_SIZE: usize = 4000;

fn main() {
    
    let mut start = Instant::now();
    let mut duration = start.elapsed();
    let mut micros: u128 = 0;
    let mut total_micros: u128 = 0;

    bls_ops(&mut start, &mut duration, &mut micros, &mut total_micros);
    ecdsa_ops(&mut start, &mut duration, &mut micros, &mut total_micros);
}

fn ecdsa_ops(start: &mut Instant, duration: &mut Duration, micros: &mut u128, total_micros: &mut u128) {

    println!("=== ECDSA Operations Start ===");
    
    *total_micros = 0;

    let secp = Secp256k1::new();
    
    let digest = sha256::Hash::hash(MSG);
    let message = Message::from_digest(digest.to_byte_array());
    
    // STAGE 1: Generating Keypairs

    *start = Instant::now();
    
    let (secret_keys, public_keys) = ecdsa_generate_keypairs(&secp);

    *duration = start.elapsed();
    
    *micros = duration.as_micros();

    *total_micros += *micros;
    
    println!("STAGE 1: {} usecs, Generated Keypairs", micros);
    
    // STAGE 2: Signing Message using all Secret Keys

    *start = Instant::now();
    
    let signatures = ecdsa_sign_all(&secp, &message, &secret_keys);
    
    *duration = start.elapsed();
    
    *micros = duration.as_micros();
    
    *total_micros += *micros;
    
    println!("STAGE 2: {} usecs, Signed message using all secret keys", micros);

    // STAGE 3: Verifying all signatures 

    *start = Instant::now();

    let is_valid = ecdsa_verify_all(&secp, &message, &signatures, &public_keys);
    
    *duration = start.elapsed();
    
    *micros = duration.as_micros();

    *total_micros += *micros;
    
    println!("STAGE 3: {} usecs, Verified all signatures using public keys", micros);

    println!("TOTAL TIME: {} usecs", total_micros);

    if is_valid {
        println!("All ECDSA Signatures are valid!");
    } else {
        println!("At least one ECDSA Signature is invalid!");
    }
}

fn ecdsa_generate_keypairs(secp: &Secp256k1<All>) -> (Vec<SecretKey>, Vec<PublicKey>) {
    
    let mut secret_keys: Vec<SecretKey> = Vec::new();
    let mut public_keys: Vec<PublicKey> = Vec::new();
    
    for _ in 0..BATCH_SIZE {
        let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
        secret_keys.push(secret_key);
        public_keys.push(public_key);
    }
    
    (secret_keys, public_keys)
    
}

fn ecdsa_sign_all(secp: &Secp256k1<All>, message: &Message, secret_keys: &Vec<SecretKey>) -> Vec<Signature> {
    let mut signatures: Vec<Signature> = Vec::new();
    
    for i in 0..BATCH_SIZE {
        signatures.push(secp.sign_ecdsa(&message, &secret_keys[i]));
    }

    signatures
}

fn ecdsa_verify_all(secp: &Secp256k1<All>, message: &Message, signatures: &Vec<Signature>, public_keys: &Vec<PublicKey>) -> bool {

    for i in 0..BATCH_SIZE {
        if !secp.verify_ecdsa(&message, &signatures[i], &public_keys[i]).is_ok() {
            return false;
        } 
    }

    true
}

fn bls_ops(start: &mut Instant, duration: &mut Duration, micros: &mut u128, total_micros: &mut u128) {
    
    println!("=== BLS Operations Start ===");

    *total_micros = 0;

    // STAGE 1: Generating Keypairs
    
    *start = Instant::now();

    let  (secret_keys, public_keys): (Vec<Scalar>, Vec<G1Affine>) = bls_generate_keypairs();
    
    *duration = start.elapsed();
    
    *micros = duration.as_micros();

    *total_micros += *micros;

    println!("STAGE 1: {} usecs, Generated Keypairs", micros);
    
    // STAGE 2: Signing Message using all Secret Keys

    *start = Instant::now();
    
    let signatures = bls_sign_all(MSG, &secret_keys);
    
    *duration = start.elapsed();
    
    *micros = duration.as_micros();
    
    *total_micros += *micros;

    println!("STAGE 2: {} usecs, Signed message using all secret keys", micros);
    
    // STAGE 3: Aggregating all signatures

    *start = Instant::now();
    
    let aggregate_signature = agrgegate_signatures(&signatures);
    
    *duration = start.elapsed();
    
    *micros = duration.as_micros();
    
    *total_micros += *micros;

    let mut total_relevant_micros = 0;
    total_relevant_micros += *micros;

    println!("STAGE 3: {} usecs, Aggregated all signatures", micros);
    
    // STAGE 4: Verifying aggregate signature

    *start = Instant::now();
    
    let is_valid = verify_aggregate(&aggregate_signature, MSG, &public_keys);
    
    *duration = start.elapsed();
    
    *micros = duration.as_micros();
    
    *total_micros += *micros;
    total_relevant_micros += *micros;

    println!("STAGE 4: {} usecs, Verify Aggregate Signature", micros);

    println!("TOTAL TIME: {} usecs", total_micros);
    
    println!("TOTAL RELEVANT TIME: {} usecs", total_relevant_micros);

    // Generate a key pair
    // let (secret_key, public_key) = generate_keypair();

    // Sign the message
    // let signature = sign(msg, &secret_key);

    // Verify the signature
    // let is_valid = verify_signature(msg, &signature, &public_key);

    if is_valid {
        println!("Aggregate Signature is valid!");
    } else {
        println!("Aggregate Signature is invalid!");
    }
}

fn bls_generate_keypairs() -> (Vec<Scalar>, Vec<G1Affine>) {
    let mut secret_keys: Vec<Scalar> = Vec::new();
    let mut public_keys: Vec<G1Affine> = Vec::new();

    for _ in 0..BATCH_SIZE {
        let (sk, pk) = bls_generate_keypair();
    
        secret_keys.push(sk);
        public_keys.push(pk);
    }
    
    (secret_keys, public_keys)
}

// Function to generate a keypair (secret key and public key)
fn bls_generate_keypair() -> (Scalar, G1Affine) {
    let sk = Scalar::random(&mut rand::rngs::OsRng); // Generate a random secret key
    let pk = G1Projective::generator() * sk; // Public key = G1 generator * secret key
    (sk, G1Affine::from(pk)) // Convert public key to affine coordinates
}

// Function to hash a message to a point on G2
fn bls_hash(msg: &[u8]) -> G2Projective {
    G2Projective::hash_to_curve(msg, CSUITE, &[]) // Hash message to G2
}

fn bls_sign_all(msg: &[u8], secret_keys: &Vec<Scalar>) -> Vec<G2Affine> {
    
    let mut signatures: Vec<G2Affine> = Vec::new();
    
    for i in 0..BATCH_SIZE {
        signatures.push(bls_sign(msg, &secret_keys[i]));
    }

    signatures
}

// Function to sign a message using the secret key
fn bls_sign(msg: &[u8], secret_key: &Scalar) -> G2Affine {
    let hashed_msg = bls_hash(msg); // Hash the message
    let signature = hashed_msg * secret_key; // Signature = H(msg) * secret key
    signature.to_affine() // Convert signature to affine coordinates
}

/*
// Function to verify a BLS signature
fn verify_signature(msg: &[u8], signature: &G2Affine, public_key: &G1Affine) -> bool {
    let hashed_msg = hash(msg).to_affine(); // Hash the message and convert to affine coordinates

    // Perform the pairing operation
    let signature_pairing = pairing(public_key, &hashed_msg);
    let msg_pairing = pairing(&G1Projective::generator().to_affine(), signature);

    // Verify the pairing
    signature_pairing == msg_pairing
}
*/

fn agrgegate_signatures(signatures: &Vec<G2Affine>) -> G2Affine {
    if signatures.is_empty() {
        return G2Affine::identity();
    }

    signatures
        .iter()
        .fold(G2Projective::identity(), |acc, &sig| acc + sig)
        .into()

}

fn verify_aggregate(agg_sig: &G2Affine, msg: &[u8], public_keys: &Vec<G1Affine>) -> bool {
    let hashed_msg = bls_hash(msg).to_affine();

    let mut ml = public_keys
    .iter()
    .map(|pk| {
        let h = hashed_msg.clone().into();
        Bls12::multi_miller_loop(&[ (&pk, &h) ])
    })
    .fold(blstrs::MillerLoopResult::default(), |acc, curr| acc + curr);

    let g1_neg = - G1Affine::generator();

    ml += Bls12::multi_miller_loop(&[ ( &g1_neg, &agg_sig.clone().into() ) ]);

    ml.final_exponentiation() == Gt::identity()

}


// use blst::blst_scalar;
// use blstrs::{G1Projective, G1Affine, G2Affine, G2Projective, Scalar, pairing};
// use rand::rngs::OsRng;
// use ff::Field;
// use group::{Group, Curve};

// const CSUITE: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
// const MSG: &str = "AAABBBCCCDDD";
// // const NUM_TXS: u32 = 4000;


// fn main() {
    
//     // let msg: String = String::from(MSG);

//     // let mut keys: Vec<(Scalar, G1Affine)> = Vec::new();

//     // for _ in 0..NUM_TXS {
//     //     keys.push(generate_keypair())
//     // }

//     let (priv_key, pub_key) = generate_keypair();

//     // println!("The Key Pairs are: {:?}", keys);

//     // hash(MSG.as_bytes())
//     // println!("The signature is: {:?}", sign(MSG, &((*keys.get(0).unwrap()).0)));

//     let sig = sign(MSG, &priv_key);

//     // println!("The first private key is: {:?}", keys.get(0).unwrap());

//     let is_valid = verify_signature(MSG, &sig, &pub_key);

//     if is_valid {
//         println!("Sig is valid!");
//     } else {
//         println!("Sig is invalid");
//     }
    
// }

// fn generate_keypair() -> (Scalar, G1Affine) {
//     let sk = Scalar::random(&mut OsRng);

//     let pk = G1Projective::generator() * sk;

//     let pk_affine = G1Affine::from(pk);

//     (sk, pk_affine)

// }

// fn hash(msg: &[u8]) -> G2Projective {
//     G2Projective::hash_to_curve(msg, CSUITE, &[])
// }

// fn sign(msg: &str, private_key: &Scalar) -> G2Affine {
    
//     let p = hash(msg.as_bytes());
//     let sig = p * private_key;

//     sig.to_affine()

    
//     // unsafe {
//     //     let private_key_blst: blst_scalar = (*private_key).clone().into();
//     //     blst::blst_sign_pk2_in_g1(
//     //         std::ptr::null_mut(),
//     //         sig.as_mut(),
//     //         p.as_ref(),
//     //         &private_key_blst
//     //     );
//     // }

//     // sig
// }

// fn verify_signature(msg: &str, sig: &G2Affine, public_key: &G1Affine) -> bool {
//     let hashed_message = hash(msg.as_bytes()).to_affine();

//     let sig_pairing = pairing(public_key, sig);
//     let msg_pairing = pairing(&G1Projective::generator().to_affine(), &hashed_message);

//     println!("Sig Pairing: {:?}", sig_pairing);
//     println!("Msg Pairing: {:?}", msg_pairing);

//     sig_pairing == msg_pairing
// }
