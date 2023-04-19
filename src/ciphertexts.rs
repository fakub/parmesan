use std::error::Error;

//~ use concrete_core::prelude::*;
use tfhe::shortint::prelude::*;
use tfhe::core_crypto::algorithms::*;
use tfhe::core_crypto::entities::plaintext::*;
use tfhe::core_crypto::entities::cleartext::*;

use crate::params::Params;
use crate::userovo::keys::{PrivKeySet,PubKeySet};
use crate::ParmesanCloudovo;



// =============================================================================
//
//  Encrypted Word
//

/// Enum that holds either plaintext (triv. ciphertext), or actual ciphertext
#[derive(Clone)]
pub enum ParmCtWord {
    Ct(tfhe::shortint::CiphertextBig),
    Triv(tfhe::core_crypto::entities::plaintext::Plaintext<u64>),   //TODO check if u64 is ok?
}

/// Struct that holds encrypted Parmesan word
#[derive(Clone)]
pub struct ParmEncrWord<'a> {
    ct: ParmCtWord,
    server_key: &'a ServerKey,
}

impl ParmEncrWord<'_> {
    pub fn encrypt_word(
        priv_keys: &PrivKeySet,
        mi: i32,
    ) -> Self {
        Self{
            ct: ParmCtWord::Ct(priv_keys.client_key.encrypt_without_padding(Self::mi_to_mu(priv_keys, mi))),
            server_key: &priv_keys.server_key,
        }
    }

    pub fn encrypt_word_triv(
        pub_keys: &PubKeySet,
        mi: i32,
    ) -> Self {
        Self{
            ct: ParmCtWord::Triv(Self::mi_to_pt(&pub_keys.server_key, mi)),
            server_key: pub_keys.server_key,
        }
    }

    pub fn decrypt_mu(
        &self,
        priv_keys_opt: Option<&PrivKeySet>,
    ) -> Result<u64, Box<dyn Error>> {
        match self.ct {
            ParmCtWord::Ct(ctb) =>
                if let Some(priv_keys) = priv_keys_opt {
                    Ok(priv_keys.client_key.decrypt_without_padding(&ctb))
                } else {
                    Err("Client key is None for decryption of non-trivial ciphertext.".into())
                },
            ParmCtWord::Triv(pt) =>
                Ok(pt_to_mu(self.server_key, &pt)),
        }
    }

    pub fn decrypt_mi(
        &self,
        priv_keys_opt: Option<&PrivKeySet>,
    ) -> Result<i32, Box<dyn Error>> {
        mu_to_mi(self.server_key, self.decrypt_mu(priv_keys_opt)?)
    }

    fn delta(server_key: &ServerKey) -> u64 {((1_u64 << 63) / server_key.message_modulus.0 as u64) * 2}

    fn mi_to_mu(
        server_key: &ServerKey,
        mi: i32,
    ) -> u64 {
        mi.rem_euclid(server_key.message_modulus.0) as u64
    }

    fn mu_to_mi(
        server_key: &ServerKey,
        mut mu: u64,
    ) -> i32 {
        mu %= server_key.message_modulus.0;
        if mu >= server_key.message_modulus.0 / 2 {
            mu as i32 - server_key.message_modulus.0 as i32
        } else {
            mu as i32
        }
    }

    fn mi_to_pt(
        server_key: &ServerKey,
        mi: i32,
    ) -> Plaintext<u64> {
        Plaintext(Self::mi_to_mu(server_key, mi) * delta(server_key))
    }

    fn half_to_pt(
        server_key: &ServerKey,
    ) -> Plaintext<u64> {
        Plaintext(1u64 * delta(server_key) / 2)
    }

    pub fn pt_to_mu(
        server_key: &ServerKey,
        pt: &Plaintext<u64>,
    ) -> u64 {
        let delta = delta(server_key);

        let rounding_bit = delta >> 1;
        let rounding = (pt.0 & rounding_bit) << 1;

        (pt.0.wrapping_add(rounding)) / delta
    }

    fn pt_to_mi(
        server_key: &ServerKey,
        pt: &Plaintext<u64>,
    ) -> i32 {
        mu_to_mi(pt_to_mu(server_key, pt))
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
    ) {
        match self.ct {
            ParmCtWord::Ct(ctbs) =>
                // !self.is_triv
                match other {
                    ParmCtWord::Ct(ctbo) =>
                        // !other.is_triv -> addition of two ciphertexts
                        lwe_ciphertext_add_assign(&mut ctbs.ct, &ctbo.ct),
                    ParmCtWord::Triv(pto) =>
                        // other.is_triv
                        lwe_ciphertext_plaintext_add_assign(&mut ctbs.ct, pto),
                },
            ParmCtWord::Triv(pts) =>
                // self.is_triv
                match other {
                    ParmCtWord::Ct(ctbo) => {
                        // !other.is_triv
                        let pts_clone = pts.clone();
                        *self.ct = ctbo.clone();
                        lwe_ciphertext_plaintext_add_assign(&mut self.ct.ct, pts_clone);

                        //~ let mut new_self_ct = self.server_key.create_trivial(pt_to_mu(pts));
                        //~ lwe_ciphertext_add_assign(&mut new_self_ct, &ctbo);
                        //~ *self.ct = ParmCtWord::Ct(new_self_ct);
                    },
                    ParmCtWord::Triv(pto) =>
                        // other.is_triv
                        *self.ct = ParmCtWord::Triv(Plaintext(pts.0.wrapping_add(pto.0))),
                },
        }
    }

    pub fn add(
        &self,
        other: &Self,
    ) -> Self {
        let mut res = self.clone();
        res.add_inplace(other);
        res
    }

    pub fn add_half_inplace(&mut self) {
        let half_pt = half_to_pt(self.server_key);

        match self.ct {
            ParmCtWord::Ct(ctbs) => {
                // !self.is_triv, half.is_triv
                lwe_ciphertext_plaintext_add_assign(&mut ctbs.ct, half_pt);
            },
            ParmCtWord::Triv(pts) =>
                // self.is_triv, half.is_triv
                *self.ct = ParmCtWord::Triv(Plaintext(pts.0.wrapping_add(half_pt.0))),
        }
    }

    pub fn sub_inplace(
        &mut self,
        other: &Self,
    ) {
        let neg_other = other.opp();
        self.add_inplace(&neg_other)
    }

    pub fn sub(
        &self,
        other: &Self,
    ) -> Self {
        let mut res = self.clone();
        res.sub_inplace(other);
        res
    }

    pub fn opp_inplace(&mut self) {
        match self.ct {
            ParmCtWord::Ct(ctbs) =>
                lwe_ciphertext_opposite_assign(&mut ctbs),
            ParmCtWord::Triv(pts) =>
                *self.ct = ParmCtWord::Triv(Plaintext(pts.0.wrapping_neg())),
        }
    }

    pub fn opp(&self) -> Result<Self, Box<dyn Error>> {
        let mut res = self.clone();
        res.opp_inplace()?;
        Ok(res)
    }

    pub fn mul_const_inplace(&mut self, k: i32) -> Result<(), Box<dyn Error>> {
        let k_abs: u64 = k.abs() as u64;
        match self.ct {
            ParmCtWord::Ct(ctbs) =>
                lwe_ciphertext_cleartext_mul_assign(&mut ctbs, Cleartext(k_abs)),
            ParmCtWord::Triv(pts) =>
                *self.ct = ParmCtWord::Triv(Plaintext(pts.0.wrapping_mul(k_abs))),
        }
        if k < 0 {self.opp_inplace();}
    }

    pub fn mul_const(&self, k: i32) -> Self {
        let mut res = self.clone();
        res.mul_const_inplace(k);
        res
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

impl ParmCiphertextImpl for ParmCiphertext<'_> {
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
