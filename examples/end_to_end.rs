//! A runnable walkthrough of the IHAT issuer-hiding endorsement
//! protocol: four-message issuance driven through the type-indexed state
//! machine, then issuer-hiding redemption against a set of accepted anchors.
//!
//! Run with: `cargo run --example end_to_end`

use ihat::anchor::{AnchorPublicKey, AnchorSecretKey};
use ihat::client::ClientNeedsSignature;
use ihat::Params;
use rand_core::{OsRng, RngCore};

fn main() {
    let pp = Params::standard();
    let mut rng = OsRng;

    // The Verifier's policy: a set of accepted anchors.
    let anchors: Vec<AnchorSecretKey> = (0..4).map(|_| AnchorSecretKey::random(&mut rng)).collect();
    let accepted: Vec<AnchorPublicKey> = anchors.iter().map(|k| k.public_key(&pp)).collect();
    println!("Verifier accepts {} anchors.", accepted.len());

    // A Client gets an endorsement from anchor #2 (secret to everyone else).
    let issuer_index = 2;
    let issuer = anchors[issuer_index];
    let mut nf = [0u8; 32]; // the issuance nullifier
    rng.fill_bytes(&mut nf);
    let ctx = b"epoch-2026-07".to_vec(); // the endorsement context, bound into e
    println!("\n== Issuance (GetEnd) from anchor #{issuer_index} ==");

    // Round 1: Client → Anchor (blinded input Y' = v·Y), Anchor → Client.
    // Each step consumes the previous state, so the sequence is type-enforced,
    // and all per-run randomness is sampled and carried internally.
    let (request, client) = ClientNeedsSignature::request(nf.to_vec(), ctx, &mut rng);
    println!("  Client  → Anchor : SignatureRequest  Y'  (blinded nullifier)");
    let (signature, anchor) = request.sign(&pp, &issuer, &mut rng);
    println!("  Anchor  → Client : Signature         (Z', C', T1', T2')");

    // Round 2: Client → Anchor (twisted challenge e'), Anchor → Client.
    let (proof_request, client) = client.request_proof(&pp, issuer.public_key(&pp), signature);
    println!("  Client  → Anchor : ProofRequest      e' = ε·α⁻¹·γ·e  (twisted challenge)");
    let proof = anchor.prove(proof_request);
    println!("  Anchor  → Client : Proof             (r', a', b')");

    // Local finalisation → endorsement (with its OR witness γ carried along).
    let issued = client
        .finalize(&pp, proof)
        .expect("honest issuance yields an endorsement");
    println!("  Client finalises → endorsement on rerandomised statement (X_hat, Z_hat)");

    assert!(issued.endorsement.dleq_valid(&pp));
    println!("  Endorsement's DLEQ proof is well-formed (issuer not yet bound): OK");

    // Redemption: present with a 1-of-n OR-proof; the Verifier learns nothing
    // about which of the 4 anchors issued.
    println!("\n== Redemption (Show) ==");
    let presentation = issued.show(&accepted, issuer_index, &mut rng);
    println!(
        "  Client sends Presentation: endorsement + 1-of-{} OR-proof",
        accepted.len()
    );

    let accepted_by_verifier = presentation.verify(&pp, &accepted);
    assert!(accepted_by_verifier);
    println!("  Verifier accepts (issuer identity hidden): OK");

    // Sanity: an endorsement from a non-accepted anchor is rejected. (Same
    // four-step issuance as above, just with an anchor outside the accepted set.)
    let rogue = AnchorSecretKey::random(&mut rng);
    let mut rogue_nf = [0u8; 32];
    rng.fill_bytes(&mut rogue_nf);
    let (request, client) =
        ClientNeedsSignature::request(rogue_nf.to_vec(), b"epoch-2026-07".to_vec(), &mut rng);
    let (signature, anchor) = request.sign(&pp, &rogue, &mut rng);
    let (proof_request, client) = client.request_proof(&pp, rogue.public_key(&pp), signature);
    let proof = anchor.prove(proof_request);
    let rogue_issued = client.finalize(&pp, proof).unwrap();
    let rogue_pres = rogue_issued.show(&accepted, 0, &mut rng);
    assert!(!rogue_pres.verify(&pp, &accepted));
    println!("\n  Endorsement from a non-accepted anchor is rejected: OK");

    println!("\nAll checks passed.");
}
