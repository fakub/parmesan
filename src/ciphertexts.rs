use std::error::Error;

use concrete_core::prelude::*;

use crate::params::Params;
use crate::userovo::keys::PrivKeySet;



// =============================================================================
//
//  Encrypted Word
//

/// Parmesan's struct to hold single encrypted word
#[derive(Clone)]
pub struct ParmEncrWord(pub LweCiphertext64);

impl ParmEncrWord {
    pub fn encrypt_word(
        params: &Params,
        priv_keys_opt: Option<&PrivKeySet>,
        mut mi: i32,
    ) -> Result<Self, Box<dyn Error>> {

        // little hack, how to bring mi into positive interval [0, 2^pi)
        mi &= params.plaintext_mask() as i32;

        // create Concrete's engine
        let mut engine = CoreEngine::new(())?;

        // encode message & create Concrete's plaintext
        let enc_mi: u64 = (mi as u64) << (64 - params.bit_precision);
        let pi = engine.create_plaintext(&enc_mi)?;

        // encrypt
        let encr_word = match priv_keys_opt {
            Some(priv_keys) =>
                engine.encrypt_lwe_ciphertext(
                    &priv_keys.sk,
                    &pi,
                    Variance(params.lwe_var_f64()),
                )?,
            None =>
                engine.trivially_encrypt_lwe_ciphertext(
                    params.concrete_pars.lwe_dimension.to_lwe_size(),
                    &pi,
                )?,
        };

        Ok(Self(encr_word))
    }

    pub fn encrypt_word_triv(
        params: &Params,
        mi: i32,
    ) -> Result<Self, Box<dyn Error>> {
        Self::encrypt_word(params, None, mi)
    }

    pub fn decrypt_word_pos(
        &self,
        params: &Params,
        priv_keys_opt: Option<&PrivKeySet>,
    ) -> Result<u32, Box<dyn Error>> {
        // create Concrete's engine
        let mut engine = CoreEngine::new(())?;

        // decrypt
        let pi = match priv_keys_opt {
            Some(priv_keys) =>
                engine.decrypt_lwe_ciphertext(&priv_keys.sk, &self.0)?,
            None =>
                engine.trivially_decrypt_lwe_ciphertext(&self.0)?,
        };
        let mut enc_mi = 0_u64;
        engine.discard_retrieve_plaintext(&mut enc_mi, &pi)?;

        let pre_round_mi = (enc_mi >> (64 - params.bit_precision - 1)) as u32;  // take one extra bit for rounding
        let mi = ((pre_round_mi >> 1) + (pre_round_mi & 1u32)) & params.plaintext_mask(); // rounding: if the last bit is 1, add 1 to the shifted result

        Ok(mi)
    }

    pub fn add_inplace(&mut self, other: &Self) -> Result<(), Box<dyn Error>> {
        let mut engine = CoreEngine::new(())?;
        engine.fuse_add_lwe_ciphertext(&mut self.0, &other.0)?;
        Ok(())
    }

    pub fn add(&self, other: &Self) -> Result<Self, Box<dyn Error>> {
        let mut res = self.clone();
        res.add_inplace(other)?;
        Ok(res)
    }

    pub fn add_half_inplace(&mut self, params: &Params) -> Result<(), Box<dyn Error>> {
        let mut engine = CoreEngine::new(())?;
        let enc_half: u64 = 1u64 << (64 - params.bit_precision - 1);
        let p_half = engine.create_plaintext(&enc_half)?;
        let encr_half = engine.trivially_encrypt_lwe_ciphertext(
            params.concrete_pars.lwe_dimension.to_lwe_size(),
            &p_half,
        )?;
        engine.fuse_add_lwe_ciphertext(&mut self.0, &encr_half)?;
        Ok(())
    }

    pub fn sub_inplace(&mut self, other: &Self) -> Result<(), Box<dyn Error>> {
        let mut engine = CoreEngine::new(())?;
        engine.fuse_sub_lwe_ciphertext(&mut self.0, &other.0)?;
        Ok(())
    }

    pub fn sub(&self, other: &Self) -> Result<Self, Box<dyn Error>> {
        let mut res = self.clone();
        res.sub_inplace(other)?;
        Ok(res)
    }

    pub fn opposite(&self) -> Result<Self, Box<dyn Error>> {
        //FIXME
        Ok(self.clone())
    }

    pub fn mul_const(&self, k: i32) -> Result<Self, Box<dyn Error>> {
        //FIXME
        if k > 0 {Ok(self.clone())} else {Ok(self.clone())}
    }

    pub fn is_triv(&self) -> bool {
        //FIXME implement this shit
        true
    }

    pub fn is_triv_zero(&self) -> bool {
        //FIXME implement this shit
        true
    }
}



// =============================================================================
//
//  Parmesan Ciphertext
//

/// Parmesan's ciphertext holds individual encrypted words
pub type ParmCiphertext = Vec<ParmEncrWord>;
//WISH  ciphertext should be more standalone type: it should hold a reference to its public keys & params so that operations can be done with only this type parameter
//      ale je to: zasrane, zamrdane
//WISH Vec<(ParmEncrWord, usize)> .. to hold quadratic weights, bootstrap only when necessary (appears to be already implemented in Concrete v0.2)
//~ pub struct ParmCiphertext {
    //~ pub ct: Vec<(ParmEncrWord, usize)>,
    //~ pub pc: &ParmesanCloudovo,
//~ }

pub trait ParmCiphertextImpl {
    fn triv(
        len: usize,
        params: &Params,
    ) -> Result<ParmCiphertext, Box<dyn Error>>;

    //TODO add triv_const (from vec?), the above is triv_zero, used internally (there is ParmArithmetics::zero)

    fn empty() -> ParmCiphertext;

    //TODO keep this?
    //~ fn single(c: ParmEncrWord) -> ParmCiphertext;

    fn to_str(&self) -> String;
}

impl ParmCiphertextImpl for ParmCiphertext {
    fn triv(
        len: usize,
        params: &Params,
    ) -> Result<ParmCiphertext, Box<dyn Error>> {
        Ok(vec![ParmEncrWord::encrypt_word_triv(params, 0)?; len])
    }

    fn empty() -> ParmCiphertext {
        Vec::new()
    }

    //~ fn single(c: ParmEncrWord) -> ParmCiphertext {
        //~ vec![c]
    //~ }

    fn to_str(&self) -> String {
        let mut s = "[[".to_string();
        //~ for c in self {
            //~ //TODO extract from new struct
            //~ s += &*format!("<{}|{}b>, ", if c.dimension == 0 {format!("{}", c.ciphertext.get_body().0)} else {"#".to_string()}, c.encoder.nb_bit_precision)
        //~ }
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
