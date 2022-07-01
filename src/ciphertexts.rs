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

    //TODO add triv_const (from vec?), the above is triv_zero

    fn empty() -> ParmCiphertext;

    fn single(c: LWE) -> ParmCiphertext;

    fn to_str(&self) -> String;
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

    fn to_str(&self) -> String {
        let mut s = "[[".to_string();
        for c in self {
            s += &*format!("<{}|{}b>, ", if c.dimension == 0 {format!("{}", c.ciphertext.get_body().0)} else {"#".to_string()}, c.encoder.nb_bit_precision)
        }
        s += "]]";
        s
    }
}

//WISH this is not possible: error[E0117]: only traits defined in the current crate can be implemented for types defined outside of the crate
//~ impl fmt::Debug for ParmCiphertext {
    //~ // This trait requires `fmt` with this exact signature.
    //~ fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        //~ write!(f, "[[");
        //~ for c in self {
            //~ write!(f, "<{}>, ", if c.dimension == 0 {format!("{:3}", c.ciphertext.get_body().0)} else {"###"})
        //~ }
        //~ write!(f, "]]");
    //~ }
//~ }
