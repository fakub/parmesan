use std::error::Error;

use concrete_core::prelude::*;

//WISH  ciphertext should be more standalone type: it should hold a reference to its public keys & params so that operations can be done with only this type parameter
//      ale je to: zasrane, zamrdane
pub type ParmCiphertext = Vec<LweCiphertext64>;
//WISH Vec<(LweCiphertext64, usize)> .. to hold quadratic weights, bootstrap only when necessary (appears to be already implemented in Concrete v0.2)
//~ pub struct ParmCiphertext {
    //~ pub ct: Vec<(LweCiphertext64, usize)>,
    //~ pub pc: &ParmesanCloudovo,
//~ }

pub trait ParmCiphertextExt {
    fn triv(
        len: usize,
        encoder: &Encoder,
    ) -> Result<ParmCiphertext, Box<dyn Error>>;

    //TODO add triv_const (from vec?), the above is triv_zero, used internally (there is ParmArithmetics::zero)

    fn empty() -> ParmCiphertext;

    fn single(c: LweCiphertext64) -> ParmCiphertext;

    fn to_str(&self) -> String;
}

impl ParmCiphertextExt for ParmCiphertext {
    fn triv(
        len: usize,
        pub_keys: &PubKeySet,
    ) -> Result<ParmCiphertext, Box<dyn Error>> {
        let mut engine = CoreEngine::new(())?;
        let zero_plaintext = engine.create_plaintext(&0_u64)?;

        Ok(vec![
            engine.trivially_encrypt_lwe_ciphertext(
                pub_keys.ksk.output_lwe_dimension().to_lwe_size(),
                &zero_plaintext,
            )?;
            len
        ])
    }

    fn empty() -> ParmCiphertext {
        Vec::new()
    }

    fn single(c: LweCiphertext64) -> ParmCiphertext {
        vec![c]
    }

    //TODO
    //~ fn to_str(&self) -> String {
        //~ let mut s = "[[".to_string();
        //~ for c in self {
            //~ //FIXME extract from new struct
            //~ s += &*format!("<{}|{}b>, ", if c.dimension == 0 {format!("{}", c.ciphertext.get_body().0)} else {"#".to_string()}, c.encoder.nb_bit_precision)
        //~ }
        //~ s += "]]";
        //~ s
    //~ }
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
