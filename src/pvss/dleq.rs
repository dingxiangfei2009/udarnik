use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use failure::Fail;

use crate::common::Verifiable;

/// DLEQ proof of existence of α such that
/// g₁^α = h₁ and g₂^α = h₂ where g₁, g₂ ∈ G are generators
/// of a finite Group G, both having prime order of p
///
/// The proof is usually made into a non-interactive
/// version of DLEQ using Fiat-Shamir heuristics.
///
/// The protocol is executed in the following sequence.
/// 1. Prover generates a random ω ∈ ℤ, and compute a₁ = g₁^ω
///    and a₂ = g₂^ω; then sends the two values to Verifier;
/// 2. Verifier generates a random challenge β
/// 3. Prover sends r = ω - αβ to Verifier
/// 4. Verifier checks if g₁^r h₁^β = a₁ and g₂^r h₂^β = a₂
/// If Verifier can establish the said equalities, Prover
/// has passed the DLEQ test.
pub struct Proof {
    pub g1: EdwardsPoint,
    pub g2: EdwardsPoint,
    pub h1: EdwardsPoint,
    pub h2: EdwardsPoint,
    pub a1: EdwardsPoint,
    pub a2: EdwardsPoint,
    pub challenge: Scalar,
    pub response: Scalar,
}

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "invalid DLEQ proof")]
    NotValid,
}

impl Verifiable for Proof {
    type Error = Error;
    type Proof = ();
    type Output = Self;

    fn verify(self, _: ()) -> Result<Self, Self::Error> {
        let a1 = self.g1 * self.response + self.h1 * self.challenge;
        let a2 = self.g2 * self.response + self.h2 * self.challenge;
        if a1 == self.a1 && a2 == self.a2 {
            Ok(self)
        } else {
            Err(Error::NotValid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::u64_to_scalar;
    use super::*;

    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    #[test]
    fn it_works() {
        let g1 = ED25519_BASEPOINT_POINT;
        let g2 = ED25519_BASEPOINT_POINT * u64_to_scalar(3);
        Proof {
            g1,
            g2,
            h1: g1 * u64_to_scalar(5),
            h2: g2 * u64_to_scalar(5),
            a1: g1 * u64_to_scalar(7),
            a2: g2 * u64_to_scalar(7),
            challenge: u64_to_scalar(9),
            response: u64_to_scalar(7) - u64_to_scalar(5) * u64_to_scalar(9),
        }
        .verify_proof(())
        .unwrap();
    }
}
