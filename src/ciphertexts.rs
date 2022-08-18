use std::error::Error;

use concrete_core::prelude::*;

use crate::params::Params;
use crate::userovo::keys::PrivKeySet;
use crate::ParmesanCloudovo;



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
                    LweDimension(0usize).to_lwe_size(),
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
                if self.is_triv() {engine.trivially_decrypt_lwe_ciphertext(&self.0)?} else {engine.decrypt_lwe_ciphertext(&priv_keys.sk, &self.0)?},
            None =>
                engine.trivially_decrypt_lwe_ciphertext(&self.0)?,
        };
        let mut enc_mi = 0_u64;
        engine.discard_retrieve_plaintext(&mut enc_mi, &pi)?;

        let pre_round_mi = (enc_mi >> (64 - params.bit_precision - 1)) as u32;  // take one extra bit for rounding
        let mi = ((pre_round_mi >> 1) + (pre_round_mi & 1u32)) & params.plaintext_mask(); // rounding: if the last bit is 1, add 1 to the shifted result

        Ok(mi)
    }

    // -------------------------------------------------------------------------
    //  Basic operations with encrypted words

    pub fn add_inplace(
        &mut self,
        other: &Self,
    ) -> Result<(), Box<dyn Error>> {
        let mut engine = CoreEngine::new(())?;

        // self is triv and other is not => extend mutable self to dimension
        if self.is_triv() && !other.is_triv() {
            let ps = engine.trivially_decrypt_lwe_ciphertext(&self.0)?;
            // re-"encrypt" self with the full dimension
            *self = Self(engine.trivially_encrypt_lwe_ciphertext(
                other.0.lwe_dimension().to_lwe_size(),
                &ps,
            )?);
        }

        // other is triv and self is not => extend other to dimension, otherwise clone
        let other_w_dim = if !self.is_triv() && other.is_triv() {
            let po = engine.trivially_decrypt_lwe_ciphertext(&other.0)?;
            Self(engine.trivially_encrypt_lwe_ciphertext(
                self.0.lwe_dimension().to_lwe_size(),
                &po,
            )?)
        } else {
            other.clone()
        };

        // add aligned ciphertexts
        engine.fuse_add_lwe_ciphertext(&mut self.0, &other_w_dim.0)?;
        Ok(())
    }

    pub fn add(
        &self,
        other: &Self,
    ) -> Result<Self, Box<dyn Error>> {
        let mut res = self.clone();
        res.add_inplace(other)?;
        Ok(res)
    }

    pub fn add_half_inplace(&mut self, pc: &ParmesanCloudovo) -> Result<(), Box<dyn Error>> {
        let mut engine = CoreEngine::new(())?;
        let enc_half: u64 = 1u64 << (64 - pc.params.bit_precision - 1);
        let p_half = engine.create_plaintext(&enc_half)?;
        engine.fuse_add_lwe_ciphertext_plaintext(&mut self.0, &p_half)?;
        Ok(())
    }

    pub fn sub_inplace(
        &mut self,
        other: &Self,
    ) -> Result<(), Box<dyn Error>> {
        let neg_other = other.opp()?;
        self.add_inplace(&neg_other)
    }

    pub fn sub(
        &self,
        other: &Self,
    ) -> Result<Self, Box<dyn Error>> {
        let mut res = self.clone();
        res.sub_inplace(other)?;
        Ok(res)
    }

    pub fn opp_inplace(&mut self) -> Result<(), Box<dyn Error>> {
        let mut engine = CoreEngine::new(())?;
        engine.fuse_opp_lwe_ciphertext(&mut self.0)?;
        Ok(())
    }

    pub fn opp(&self) -> Result<Self, Box<dyn Error>> {
        let mut res = self.clone();
        res.opp_inplace()?;
        Ok(res)
    }

    pub fn mul_const_inplace(&mut self, k: i32) -> Result<(), Box<dyn Error>> {
        let mut engine = CoreEngine::new(())?;
        let k_abs: u64 = k.abs() as u64;
        let k_abs_ct64: Cleartext64 = engine.create_cleartext(&k_abs)?;
        engine.fuse_mul_lwe_ciphertext_cleartext(&mut self.0, &k_abs_ct64)?;
        if k < 0 {self.opp_inplace()?;}
        Ok(())
    }

    pub fn mul_const(&self, k: i32) -> Result<Self, Box<dyn Error>> {
        let mut res = self.clone();
        res.mul_const_inplace(k)?;
        Ok(res)
    }

    pub fn is_triv(&self) -> bool {
        self.0.lwe_dimension().0 == 0
    }

    pub fn is_triv_zero(&self, params: &Params) -> Result<bool, Box<dyn Error>> {
        Ok(self.is_triv() && (self.decrypt_word_pos(params, None)? == 0u32))
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
