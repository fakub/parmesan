use std::error::Error;

//~ use concrete_core::prelude::*;
use tfhe::shortint::prelude::*;
use tfhe::core_crypto::algorithms::*;

use crate::params::Params;
use crate::userovo::keys::{PrivKeySet,PubKeySet};
use crate::ParmesanCloudovo;



// =============================================================================
//
//  Encrypted Word
//

/// Enum that allows both trivial and non-trivial ciphertext
#[derive(Clone)]
pub enum ParmEncrWord<'a> {
    Ct{
        c: tfhe::shortint::CiphertextBig,
        server_key: &'a ServerKey,
    },
    Triv(i32),
}

impl ParmEncrWord<'_> {
    pub fn encrypt_word(
        params: &Params,
        priv_keys: &PrivKeySet,
        mi: i32,
    ) -> Self {
        // little hack, how to bring mi into positive interval [0, 2^pi)
        let mu = (mi & params.plaintext_mask() as i32) as u64;
        // encrypt
        ParmEncrWord::Ct{
            c: priv_keys.client_key.encrypt_without_padding(mu),
            server_key: priv_keys.server_key,
        }
    }

    pub fn encrypt_word_triv(
        mi: i32,
    ) -> Self {
        ParmEncrWord::Triv(mi)
    }

    pub fn decrypt_word_pos(
        &self,
        params: &Params,
        priv_keys_opt: Option<&PrivKeySet>,
    ) -> Result<u64, Box<dyn Error>> {
        match self {
            ParmEncrWord::Ct{c, ..} =>
                if let Some(priv_keys) = priv_keys_opt {
                    priv_keys.client_key.decrypt_without_padding(&c)
                } else {
                    Err("Client key is None for decryption of non-trivial ciphertext.".into())
                },
            ParmEncrWord::Triv(mi) =>
                // little hack, how to bring mi into positive interval [0, 2^pi)
                (mi & params.plaintext_mask() as i32) as u64,
        }
    }

    //~ pub fn is_triv(&self) -> bool {
        //~ self.0.lwe_dimension().0 == 0
    //~ }

    //~ pub fn is_triv_zero(&self, params: &Params) -> Result<bool, Box<dyn Error>> {
        //~ Ok(self.is_triv() && (self.decrypt_word_pos(params, None)? == 0u32))
    //~ }


    // -------------------------------------------------------------------------
    //  Basic operations with encrypted words

    pub fn add_inplace(
        &mut self,
        other: &Self,
    ) -> Result<(), Box<dyn Error>> {

        match self {
            ParmEncrWord::Ct(cs, server_key_s) =>
                // !self.is_triv
                match other {
                    ParmEncrWord::Ct{co, ..} => {
                        // !other.is_triv -> addition of two ciphertexts
                        lwe_ciphertext_add_assign(&mut cs.ct, &co.ct);
                    },
                    ParmEncrWord::Triv(mio) =>
                        // other.is_triv
                        lwe_ciphertext_add_assign(&mut cs.ct, &server_key_s.create_trivial(mio).ct),
                }
                ,
            ParmEncrWord::Triv(mis) =>
                // self.is_triv
                match other {
                    ParmEncrWord::Ct{co, server_key_o} => {
                        // !other.is_triv
                        *self = server_key_o.create_trivial(mis);
                        lwe_ciphertext_add_assign(&mut self.ct, &co);
                    },
                    ParmEncrWord::Triv(mio) =>
                        // other.is_triv
                        ParmEncrWord::Triv(mis + mio),
                }
        }
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
        engine.fuse_opp_lwe_ciphertext(&mut self.0)?;
        Ok(())
    }

    pub fn opp(&self) -> Result<Self, Box<dyn Error>> {
        let mut res = self.clone();
        res.opp_inplace()?;
        Ok(res)
    }

    pub fn mul_const_inplace(&mut self, k: i32) -> Result<(), Box<dyn Error>> {
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
}



// =============================================================================
//
//  Parmesan Ciphertext
//

/// Parmesan's ciphertext holds individual encrypted words
pub type ParmCiphertext<'a> = Vec<ParmEncrWord<'a>>;
//WISH  ciphertext should be more standalone type: it should hold a reference to its public keys & params so that operations can be done with only this type parameter
//      ale je to: zasrane, zamrdane
//WISH Vec<(ParmEncrWord, usize)> .. to hold quadratic weights, bootstrap only when necessary (appears to be already implemented in Concrete v0.2)
//~ pub struct ParmCiphertext {
    //~ pub ct: Vec<(ParmEncrWord, usize)>,
    //~ pub pc: &ParmesanCloudovo,
//~ }

pub trait ParmCiphertextImpl {
    fn triv<'a>(
        len: usize,
        pc: &'a ParmesanCloudovo<'a>,
    ) -> ParmCiphertext<'a>;

    //TODO add triv_const (from vec?), the above is triv_zero, used internally (there is ParmArithmetics::zero)

    fn empty() -> ParmCiphertext<'static>;

    fn single(ew: ParmEncrWord) -> ParmCiphertext;

    fn to_str(&self) -> String;
}

impl ParmCiphertextImpl<'_> for ParmCiphertext<'_> {
    fn triv<'a>(
        len: usize,
        pc: &'a ParmesanCloudovo<'a>,
    ) -> ParmCiphertext<'a> {
        vec![ParmEncrWord::encrypt_word_triv(0); len]
    }

    fn empty() -> ParmCiphertext<'static> {
        Vec::new()
    }

    fn single(ew: ParmEncrWord) -> ParmCiphertext {
        vec![ew]
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
