use std::error::Error;

use concrete::{LWE,Encoder};

//WISH  ciphertext should be more standalone type: it should hold a reference to its public keys & params so that operations can be done with only this type parameter
//      ale je to: zasrane, zamrdane
pub type ParmCiphertext = Vec<LWE>;

pub trait ParmCiphertextExt {
    fn triv(
        len: usize,
        encoder: &Encoder,
    ) -> Result<ParmCiphertext, Box<dyn Error>>;

    fn empty() -> ParmCiphertext;

    fn single(c: LWE) -> ParmCiphertext;
}

impl ParmCiphertextExt for ParmCiphertext {
    fn triv(
        len: usize,
        encoder: &Encoder,
    ) -> Result<ParmCiphertext, Box<dyn Error>> {
        Ok(vec![LWE::encrypt_uint_triv(0, encoder)?; len])
    }

    fn empty() -> ParmCiphertext {
        Vec::new()
    }

    fn single(c: LWE) -> ParmCiphertext {
        vec![c]
    }
}
