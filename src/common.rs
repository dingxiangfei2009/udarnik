use std::ops::Deref;

pub struct Verified<T>(T);

impl<T> Verified<T> {
    pub fn inner(&self) -> &T {
        &self.0
    }
}

impl<T> Deref for Verified<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.inner()
    }
}

pub trait Verifiable: Sized {
    type Error;
    type Proof;
    fn verify(self, proof: Self::Proof) -> Result<Self, Self::Error>;
    fn verify_proof(self, proof: Self::Proof) -> Result<Verified<Self>, Self::Error> {
        Ok(Verified(self.verify(proof)?))
    }
}
