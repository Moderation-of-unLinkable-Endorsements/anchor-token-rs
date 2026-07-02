//! The Anchor token wire format: a native implementation of the TLS 1.3
//! presentation-language encoding specified in `docs/wire-format.md`.
//!
//! Every protocol message implements [`WireFormat`], giving a canonical
//! [`to_bytes`](WireFormat::to_bytes) / [`from_bytes`](WireFormat::from_bytes).
//! With the `serde` feature the same types also implement `Serialize` /
//! `Deserialize`, delegating to this encoding — so any serde format embeds the
//! canonical wire bytes, and the messages can nest inside other serializable
//! types.

use crate::anchor::AnchorPublicKey;
use crate::orproof::{OrProof, Transcript};
use crate::{
    Endorsement, Point, Presentation, Proof, ProofRequest, Scalar, Signature, SignatureRequest,
};
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::PrimeField;
use std::fmt;

/// An error encoding or decoding the wire format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// The input ended before a complete value was read.
    UnexpectedEof,
    /// Bytes remained after a complete value was decoded.
    TrailingBytes,
    /// A point was not a valid SEC1-compressed P-256 group element.
    InvalidPoint,
    /// A scalar was not canonical (`0 <= x < n`).
    InvalidScalar,
    /// A length-prefixed field exceeded its `2^16 - 1` byte bound while encoding.
    Overflow,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            WireError::UnexpectedEof => "unexpected end of input",
            WireError::TrailingBytes => "trailing bytes after value",
            WireError::InvalidPoint => "invalid compressed point",
            WireError::InvalidScalar => "non-canonical scalar",
            WireError::Overflow => "length-prefixed field too long",
        })
    }
}

impl std::error::Error for WireError {}

/// Canonical byte encoding of a protocol message, per `docs/wire-format.md`
/// (TLS 1.3 presentation language over NIST P-256).
pub trait WireFormat: Sized {
    /// Append the canonical encoding of `self` to `out`.
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError>;

    /// Decode one value from the front of `buf`, advancing it past the bytes read.
    fn decode(buf: &mut &[u8]) -> Result<Self, WireError>;

    /// The canonical byte encoding.
    fn to_bytes(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode from a complete slice, erroring if any bytes remain unconsumed.
    fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut cursor = bytes;
        let value = Self::decode(&mut cursor)?;
        if cursor.is_empty() {
            Ok(value)
        } else {
            Err(WireError::TrailingBytes)
        }
    }
}

// -- primitive codecs (see the "Primitive types" section of the spec) --

/// Split `n` bytes off the front of `buf`, advancing it.
fn take<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8], WireError> {
    if buf.len() < n {
        return Err(WireError::UnexpectedEof);
    }
    let (head, tail) = buf.split_at(n);
    *buf = tail;
    Ok(head)
}

fn get_u16(buf: &mut &[u8]) -> Result<u16, WireError> {
    let raw = take(buf, 2)?;
    Ok(u16::from_be_bytes([raw[0], raw[1]]))
}

fn put_point(out: &mut Vec<u8>, p: &Point) {
    out.extend_from_slice(p.to_bytes().as_ref()); // 33-byte SEC1 compressed
}

fn get_point(buf: &mut &[u8]) -> Result<Point, WireError> {
    let raw = take(buf, 33)?;
    let mut repr = <Point as GroupEncoding>::Repr::default();
    repr.copy_from_slice(raw);
    Option::from(Point::from_bytes(&repr)).ok_or(WireError::InvalidPoint)
}

fn put_scalar(out: &mut Vec<u8>, s: &Scalar) {
    out.extend_from_slice(s.to_repr().as_ref()); // 32-byte big-endian
}

fn get_scalar(buf: &mut &[u8]) -> Result<Scalar, WireError> {
    let raw = take(buf, 32)?;
    let mut repr = <Scalar as PrimeField>::Repr::default();
    repr.copy_from_slice(raw);
    Option::from(Scalar::from_repr(repr)).ok_or(WireError::InvalidScalar)
}

fn put_varbytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), WireError> {
    let len = u16::try_from(bytes.len()).map_err(|_| WireError::Overflow)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn get_varbytes(buf: &mut &[u8]) -> Result<Vec<u8>, WireError> {
    let len = usize::from(get_u16(buf)?);
    Ok(take(buf, len)?.to_vec())
}

// -- issuance messages --

impl WireFormat for SignatureRequest {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        put_point(out, &self.yp);
        put_varbytes(out, &self.endorsement_context)
    }
    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        let yp = get_point(buf)?;
        let endorsement_context = get_varbytes(buf)?;
        Ok(SignatureRequest {
            yp,
            endorsement_context,
        })
    }
}

impl WireFormat for Signature {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        put_point(out, &self.zp);
        put_point(out, &self.cp);
        put_point(out, &self.t1p);
        put_point(out, &self.t2p);
        Ok(())
    }
    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        Ok(Signature {
            zp: get_point(buf)?,
            cp: get_point(buf)?,
            t1p: get_point(buf)?,
            t2p: get_point(buf)?,
        })
    }
}

impl WireFormat for ProofRequest {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        put_scalar(out, &self.e_prime);
        Ok(())
    }
    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        Ok(ProofRequest {
            e_prime: get_scalar(buf)?,
        })
    }
}

impl WireFormat for Proof {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        put_scalar(out, &self.rp);
        put_scalar(out, &self.ap);
        put_scalar(out, &self.bp);
        Ok(())
    }
    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        Ok(Proof {
            rp: get_scalar(buf)?,
            ap: get_scalar(buf)?,
            bp: get_scalar(buf)?,
        })
    }
}

// -- endorsement and redemption --

impl WireFormat for Endorsement {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        put_point(out, &self.x_hat);
        put_point(out, &self.z_hat);
        put_varbytes(out, &self.nf)?;
        put_scalar(out, &self.e);
        put_scalar(out, &self.a);
        put_scalar(out, &self.b);
        put_scalar(out, &self.r);
        put_varbytes(out, &self.endorsement_context)
    }
    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        Ok(Endorsement {
            x_hat: get_point(buf)?,
            z_hat: get_point(buf)?,
            nf: get_varbytes(buf)?,
            e: get_scalar(buf)?,
            a: get_scalar(buf)?,
            b: get_scalar(buf)?,
            r: get_scalar(buf)?,
            endorsement_context: get_varbytes(buf)?,
        })
    }
}

impl WireFormat for Transcript {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        put_point(out, &self.t);
        put_scalar(out, &self.c);
        put_scalar(out, &self.s);
        Ok(())
    }
    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        Ok(Transcript {
            t: get_point(buf)?,
            c: get_scalar(buf)?,
            s: get_scalar(buf)?,
        })
    }
}

impl WireFormat for OrProof {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        let mut body = Vec::new();
        for tr in &self.transcripts {
            tr.encode(&mut body)?;
        }
        let len = u16::try_from(body.len()).map_err(|_| WireError::Overflow)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(())
    }
    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        let len = usize::from(get_u16(buf)?);
        let mut body = take(buf, len)?;
        let mut transcripts = Vec::new();
        while !body.is_empty() {
            transcripts.push(Transcript::decode(&mut body)?);
        }
        Ok(OrProof { transcripts })
    }
}

impl WireFormat for Presentation {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        self.endorsement.encode(out)?;
        self.or_proof.encode(out)
    }
    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        let endorsement = Endorsement::decode(buf)?;
        let or_proof = OrProof::decode(buf)?;
        Ok(Presentation {
            endorsement,
            or_proof,
        })
    }
}

// -- keys --

impl WireFormat for AnchorPublicKey {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        put_point(out, &self.pk);
        Ok(())
    }
    fn decode(buf: &mut &[u8]) -> Result<Self, WireError> {
        Ok(AnchorPublicKey {
            pk: get_point(buf)?,
        })
    }
}

// -- optional serde support, delegating to the wire format --

#[cfg(feature = "serde")]
mod serde_impls {
    use super::{WireFormat, *};
    use serde::de::{self, Visitor};
    use serde::{Deserializer, Serializer};

    /// Deserializes any byte representation (borrowed, owned, or a sequence of
    /// `u8`) back through [`WireFormat::from_bytes`].
    struct WireVisitor<T>(std::marker::PhantomData<T>);

    impl<'de, T: WireFormat> Visitor<'de> for WireVisitor<T> {
        type Value = T;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Anchor token wire bytes")
        }

        fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<T, E> {
            T::from_bytes(v).map_err(E::custom)
        }

        fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<T, E> {
            self.visit_bytes(&v)
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<T, A::Error> {
            let mut bytes = Vec::new();
            while let Some(b) = seq.next_element::<u8>()? {
                bytes.push(b);
            }
            T::from_bytes(&bytes).map_err(de::Error::custom)
        }
    }

    macro_rules! wire_serde {
        ($($t:ty),* $(,)?) => {$(
            impl serde::Serialize for $t {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    let bytes = self.to_bytes().map_err(serde::ser::Error::custom)?;
                    serializer.serialize_bytes(&bytes)
                }
            }

            impl<'de> serde::Deserialize<'de> for $t {
                fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                    deserializer.deserialize_byte_buf(WireVisitor::<$t>(std::marker::PhantomData))
                }
            }
        )*};
    }

    wire_serde!(
        SignatureRequest,
        Signature,
        ProofRequest,
        Proof,
        Endorsement,
        Presentation,
        AnchorPublicKey,
    );
}
