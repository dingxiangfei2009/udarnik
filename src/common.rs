use std::ops::Deref;

pub struct Verified<T>(T);

impl<T> Verified<T> {
    pub fn into_inner(self) -> T {
        self.0
    }

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
    type Output;
    fn verify(self, proof: Self::Proof) -> Result<Self::Output, Self::Error>;
    fn verify_proof(self, proof: Self::Proof) -> Result<Verified<Self::Output>, Self::Error> {
        Ok(Verified(self.verify(proof)?))
    }
}
