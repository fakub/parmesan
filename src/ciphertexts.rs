use std::error::Error;

use concrete::LWE;

//TODO  ciphertext should be more standalone type: it should hold a reference to its public keys & params so that operations can be done with only this type parameter
//      ale je to: zasrane, zamrdane
pub type ParmCiphertext = Vec<LWE>;

pub trait ParmCiphertextExt {
    fn triv(len: usize) -> Result<ParmCiphertext, Box<dyn Error>>;

    fn empty() -> ParmCiphertext;

    fn single(c: LWE) -> Result<ParmCiphertext, Box<dyn Error>>;
}

impl ParmCiphertextExt for ParmCiphertext {
    fn triv(len: usize) -> Result<ParmCiphertext, Box<dyn Error>> {
        Ok(vec![LWE::zero(0)?; len])
    }

    fn empty() -> ParmCiphertext {
        Vec::new()
    }

    fn single(c: LWE) -> Result<ParmCiphertext, Box<dyn Error>> {
        Ok(vec![c])
    }
}
