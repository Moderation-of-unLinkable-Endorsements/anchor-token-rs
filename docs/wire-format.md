# IHAT wire format

The canonical byte encoding of the protocol's messages, written in the **TLS 1.3
presentation language** (RFC 8446 §3). Each structure here maps field-for-field
to the corresponding Rust type.

> **Status: implemented.** Each message type implements the crate's `WireFormat`
> trait (`to_bytes` / `from_bytes`); with the `serde` feature, `Serialize` /
> `Deserialize` delegate to this same encoding. The message fields are
> crate-internal — encoding and decoding go through `WireFormat`.

All values are fixed-endian as noted; there is no implicit padding or alignment.
All elliptic-curve operations are over NIST P-256 (secp256r1); `n` is the group
order.

## Primitive types

```
opaque Scalar[32];   /* a scalar mod n, big-endian (SEC1 I2OSP), 0 <= x < n */

opaque Point[33];    /* a group element, SEC1 compressed form:
                        0x02/0x03 prefix byte + 32-byte big-endian x-coord */
```

Variable-length byte strings carry a two-byte (big-endian) length prefix:

```
opaque VarBytes<0..2^16-1>;
```

## Keys

```
struct {
    Point pk;                    /* X = x·G */
} AnchorPublicKey;
```

A verifier's accepted set is distributed out of band as a vector, in a fixed
order that both `show` and `verify` agree on (the OR-proof transcripts are in the
same order):

```
struct {
    AnchorPublicKey keys<33..2^16-1>;   /* length is a multiple of 33 */
} AcceptedSet;
```

## Issuance (GetEnd), in protocol order

```
struct {
    Point    yp;                 /* Y' = v·Y, the blinded nullifier hash */
    VarBytes endorsement_context;/* e.g. an epoch; also appears in the Endorsement */
} SignatureRequest;              /* Client -> Anchor */

struct {
    Point zp;                    /* Z'  = x·Y'                           */
    Point cp;                    /* C'  = a'·G + b'·H(endorsement_context)*/
    Point t1p;                   /* T1' = t'·Y'                          */
    Point t2p;                   /* T2' = t'·G                           */
} Signature;                     /* Anchor -> Client */

struct {
    Scalar e_prime;              /* e' = ε·α⁻¹·γ·e, the twisted challenge */
} ProofRequest;                  /* Client -> Anchor */

struct {
    Scalar rp;                   /* r' = t' + e'·a'·x */
    Scalar ap;                   /* a'                */
    Scalar bp;                   /* b'                */
} Proof;                         /* Anchor -> Client */
```

The Anchor derives `H = H(endorsement_context)` (RFC 9380 hash-to-curve) from the
context in the `SignatureRequest`, so it must equal the one the Client and
Verifier use.

## Endorsement and redemption (Show)

```
struct {
    Point    x_hat;              /* X_hat = γ·X  */
    Point    z_hat;              /* Z_hat = γ·x·Y */
    VarBytes nf;                 /* nullifier */
    Scalar   e;                  /* Fiat–Shamir challenge
                                    e = H_FS(X_hat, Y, Z_hat, T1, T2, C, endorsement_context) */
    Scalar   a;
    Scalar   b;
    Scalar   r;
    VarBytes endorsement_context;
} Endorsement;

struct {
    Point  t;                    /* branch commitment  */
    Scalar c;                    /* branch sub-challenge*/
    Scalar s;                    /* branch response     */
} Transcript;                    /* 97 bytes */

struct {
    Transcript transcripts<0..2^16-1>;  /* one per accepted key, same order;
                                           length is a multiple of 97 */
} OrProof;

struct {
    Endorsement endorsement;
    OrProof     or_proof;        /* 1-of-n OR-proof that X_hat = γ·Xⱼ for some Xⱼ in the accepted set */
} Presentation;                  /* Client -> Verifier */
```

## Notes

- **Domain separation.** The hashes (`H₁`, `H_FS`, the OR-proof challenge, and
  `H`) are RFC 9380 constructions over P-256, each with a distinct tag of the
  form `MOLE-IHAT-P256:<use>:v1`. They are not part of the wire format but
  are fixed by the protocol.
- **Presentation binding.** The OR-proof's Fiat–Shamir challenge additionally
  absorbs a caller-supplied byte string (the `binding` argument of `show` /
  `verify`, length-prefixed) that never crosses the wire: both parties must
  supply the same bytes out of band — e.g. MoLE's `challenge_digest`, the
  SHA-256 hash of the Moderator's challenge — so a `Presentation` produced
  for one context fails verification in every other.
- **Length framing.** The Fiat–Shamir transcripts length-prefix every
  variable-count group, so hashing is injective independent of this wire framing.
- **`endorsement_context` consistency.** It appears in both `SignatureRequest`
  and `Endorsement`; a mismatch makes the Client's Pedersen check fail at
  finalize, because `H` would differ.
