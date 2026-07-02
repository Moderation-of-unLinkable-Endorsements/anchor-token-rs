//! Wire-format round-trip and rejection tests.

use crate::anchor::{AnchorPublicKey, AnchorSecretKey};
use crate::client::ClientNeedsSignature;
use crate::{Params, Presentation, WireError, WireFormat};
use rand_core::{OsRng, RngCore};

fn random_nullifier() -> Vec<u8> {
    let mut nf = [0u8; 32];
    OsRng.fill_bytes(&mut nf);
    nf.to_vec()
}

/// Drive one honest issuance + presentation, capturing each wire message.
fn sample() -> Sample {
    let pp = Params::standard();
    let mut rng = OsRng;
    let key = AnchorSecretKey::random(&mut rng);
    let accepted = vec![
        key.public_key(&pp),
        AnchorSecretKey::random(&mut rng).public_key(&pp),
    ];

    let (sig_request, client) =
        ClientNeedsSignature::request(random_nullifier(), b"epoch-2026-07".to_vec(), &mut rng);
    let (signature, anchor) = sig_request.clone().sign(&pp, &key, &mut rng);
    let (proof_request, client) = client.request_proof(&pp, key.public_key(&pp), signature);
    let proof = anchor.prove(proof_request);
    let issued = client.finalize(&pp, proof).unwrap();
    let endorsement = issued.endorsement.clone();
    let presentation = issued.show(&accepted, 0, &mut rng);

    Sample {
        pp,
        accepted,
        sig_request,
        signature,
        proof_request,
        proof,
        endorsement,
        presentation,
    }
}

struct Sample {
    pp: Params,
    accepted: Vec<AnchorPublicKey>,
    sig_request: crate::SignatureRequest,
    signature: crate::Signature,
    proof_request: crate::ProofRequest,
    proof: crate::Proof,
    endorsement: crate::Endorsement,
    presentation: Presentation,
}

/// Encoding then decoding then re-encoding must be byte-stable (canonical
/// encodings are unique, so this is value equality for these types).
fn assert_stable<T: WireFormat>(value: &T) {
    let bytes = value.to_bytes().expect("encode");
    let decoded = T::from_bytes(&bytes).expect("decode");
    assert_eq!(decoded.to_bytes().expect("re-encode"), bytes);
}

#[test]
fn every_message_round_trips() {
    let s = sample();
    assert_stable(&s.sig_request);
    assert_stable(&s.signature);
    assert_stable(&s.proof_request);
    assert_stable(&s.proof);
    assert_stable(&s.endorsement);
    assert_stable(&s.presentation);
    assert_stable(&s.accepted[0]);
}

/// A decoded endorsement/presentation is still semantically valid.
#[test]
fn round_trip_preserves_validity() {
    let s = sample();

    let end = crate::Endorsement::from_bytes(&s.endorsement.to_bytes().unwrap()).unwrap();
    assert!(end.dleq_valid(&s.pp));

    let pres = Presentation::from_bytes(&s.presentation.to_bytes().unwrap()).unwrap();
    assert!(pres.verify(&s.pp, &s.accepted));
}

#[test]
fn truncated_input_is_rejected() {
    let s = sample();
    let bytes = s.signature.to_bytes().unwrap();
    assert!(matches!(
        crate::Signature::from_bytes(&bytes[..bytes.len() - 1]),
        Err(WireError::UnexpectedEof)
    ));
}

#[test]
fn trailing_bytes_are_rejected() {
    let s = sample();
    let mut bytes = s.signature.to_bytes().unwrap();
    bytes.push(0);
    assert!(matches!(
        crate::Signature::from_bytes(&bytes),
        Err(WireError::TrailingBytes)
    ));
}

#[test]
fn invalid_point_is_rejected() {
    // A key is a single compressed point; 0xFF is not a valid SEC1 tag.
    assert!(matches!(
        AnchorPublicKey::from_bytes(&[0xFF; 33]),
        Err(WireError::InvalidPoint)
    ));
}

#[test]
fn non_canonical_scalar_is_rejected() {
    // A ProofRequest is a single scalar; 0xFF..FF exceeds the group order.
    assert!(matches!(
        crate::ProofRequest::from_bytes(&[0xFF; 32]),
        Err(WireError::InvalidScalar)
    ));
}

#[cfg(feature = "serde")]
#[test]
fn serde_delegates_to_wire_format() {
    let s = sample();

    // The serde output is exactly the wire bytes (here, a JSON array of them).
    let json = serde_json::to_vec(&s.presentation).unwrap();
    let as_bytes: Vec<u8> = serde_json::from_slice(&json).unwrap();
    assert_eq!(as_bytes, s.presentation.to_bytes().unwrap());

    // And it round-trips back to a verifying presentation.
    let pres: Presentation = serde_json::from_slice(&json).unwrap();
    assert!(pres.verify(&s.pp, &s.accepted));
}
