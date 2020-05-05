use std::{convert::TryFrom, fs::File, io::Write, path::PathBuf};

use sss::lattice::{keygen, Init, PrivateKey, SigningKey};
use structopt::StructOpt;
use thiserror::Error;
use udarnik::keyman::{
    Error as KeyError, RawInit, RawPrivateKey, RawPublicKey, RawSigningKey, RawVerificationKey,
};

#[derive(Debug, StructOpt)]
enum Opt {
    Init {
        out: PathBuf,
    },
    Key {
        init: PathBuf,
        private: PathBuf,
        public: PathBuf,
    },
    Signature {
        init: PathBuf,
        private: PathBuf,
        signing: PathBuf,
        verify: PathBuf,
    },
}

#[derive(Error, Debug)]
enum Error {
    #[error("serialization: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("key: {0}")]
    Key(#[from] KeyError),
}

fn main() -> Result<(), Error> {
    let opt = Opt::from_args();
    let mut rng = rand::rngs::OsRng;
    match opt {
        Opt::Init { out } => {
            let init = Init::new(&mut rng);
            let init = RawInit::from(init);
            write!(File::create(out)?, "{}", serde_json::to_string(&init)?)?;
            Ok(())
        }
        Opt::Key {
            init,
            private,
            public,
        } => {
            let init: RawInit = serde_json::from_reader(File::open(init)?)?;
            let init = Init::try_from(init)?;
            let (prikey, pubkey) = keygen(&mut rng, &init);
            let prikey = RawPrivateKey::from(prikey);
            let pubkey = RawPublicKey::from(pubkey);
            write!(
                File::create(private)?,
                "{}",
                serde_json::to_string(&prikey)?
            )?;
            write!(File::create(public)?, "{}", serde_json::to_string(&pubkey)?)?;
            Ok(())
        }
        Opt::Signature {
            init,
            private,
            signing,
            verify,
        } => {
            let init: RawInit = serde_json::from_reader(std::fs::File::open(init)?)?;
            let init = Init::try_from(init)?;
            let prikey: RawPrivateKey = serde_json::from_reader(std::fs::File::open(private)?)?;
            let prikey = PrivateKey::try_from(prikey)?;
            let sign_key = SigningKey::from_private_key(&prikey);
            let verify_key = sign_key.verification_key(&init);
            let sign_key = RawSigningKey::from(sign_key);
            let verify_key = RawVerificationKey::from(verify_key);
            write!(
                File::create(signing)?,
                "{}",
                serde_json::to_string(&sign_key)?
            )?;
            write!(
                File::create(verify)?,
                "{}",
                serde_json::to_string(&verify_key)?
            )?;
            Ok(())
        }
    }
}
