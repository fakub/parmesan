use std::error::Error;

use tfhe::shortint::prelude::*;
use tfhe::core_crypto::algorithms::*;
use tfhe::core_crypto::entities::plaintext::*;
use tfhe::core_crypto::entities::cleartext::*;

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
pub struct ParmEncrWord {
    pub ct: ParmCtWord,
    pub msg_mod: MessageModulus,
}

impl ParmEncrWord {
    pub fn encrypt_word(
        priv_keys: &PrivKeySet,
        mi: i32,
    ) -> ParmEncrWord {
        Self{
            ct: ParmCtWord::Ct(priv_keys.client_key.encrypt_without_padding(Self::mi_to_mu(priv_keys.server_key.message_modulus, mi))),
            msg_mod: priv_keys.server_key.message_modulus,
        }
    }

    pub fn encrypt_word_triv(
        pub_keys: &PubKeySet,
        mi: i32,
    ) -> ParmEncrWord {
        Self{
            ct: ParmCtWord::Triv(Self::mi_to_pt(pub_keys.server_key.message_modulus, mi)),
            msg_mod: pub_keys.server_key.message_modulus,
        }
    }

    pub fn decrypt_mu(
        &self,
        priv_keys_opt: Option<&PrivKeySet>,
    ) -> Result<u64, Box<dyn Error>> {
        match &self.ct {
            ParmCtWord::Ct(ctb) =>
                if let Some(priv_keys) = priv_keys_opt {
                    Ok(priv_keys.client_key.decrypt_without_padding(&ctb))
                } else {
                    Err("Client key is None for decryption of non-trivial ciphertext.".into())
                },
            ParmCtWord::Triv(pt) =>
                Ok(Self::pt_to_mu(self.msg_mod, &pt)),
        }
    }

    pub fn decrypt_mi(
        &self,
        priv_keys_opt: Option<&PrivKeySet>,
    ) -> Result<i32, Box<dyn Error>> {
        Ok(Self::mu_to_mi(self.msg_mod, self.decrypt_mu(priv_keys_opt)?))
    }

    fn delta(msg_mod: MessageModulus) -> u64 {((1_u64 << 63) / msg_mod.0 as u64) * 2}

    fn mi_to_mu(
        msg_mod: MessageModulus,
        mi: i32,
    ) -> u64 {
        mi.rem_euclid(msg_mod.0 as i32) as u64
    }

    fn mu_to_mi(
        msg_mod: MessageModulus,
        mut mu: u64,
    ) -> i32 {
        mu %= msg_mod.0 as u64;
        if mu >= msg_mod.0 as u64 / 2 {
            mu as i32 - msg_mod.0 as i32
        } else {
            mu as i32
        }
    }

    fn mi_to_pt(
        msg_mod: MessageModulus,
        mi: i32,
    ) -> Plaintext<u64> {
        Plaintext(Self::mi_to_mu(msg_mod, mi) * Self::delta(msg_mod))
    }

    fn half_to_pt(
        msg_mod: MessageModulus,
    ) -> Plaintext<u64> {
        Plaintext(1u64 * Self::delta(msg_mod) / 2)
    }

    pub fn pt_to_mu(
        msg_mod: MessageModulus,
        pt: &Plaintext<u64>,
    ) -> u64 {
        let delta = Self::delta(msg_mod);

        let rounding_bit = delta >> 1;
        let rounding = (pt.0 & rounding_bit) << 1;

        (pt.0.wrapping_add(rounding)) / delta
    }

    #[allow(dead_code)]
    fn pt_to_mi(
        msg_mod: MessageModulus,
        pt: &Plaintext<u64>,
    ) -> i32 {
        Self::mu_to_mi(msg_mod, Self::pt_to_mu(msg_mod, pt))
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
        match &mut self.ct {
            ParmCtWord::Ct(ctbs) =>
                // !self.is_triv
                match &other.ct {
                    ParmCtWord::Ct(ctbo) =>
                        // !other.is_triv -> addition of two ciphertexts
                        lwe_ciphertext_add_assign(&mut ctbs.ct, &ctbo.ct),
                    ParmCtWord::Triv(pto) =>
                        // other.is_triv
                        lwe_ciphertext_plaintext_add_assign(&mut ctbs.ct, *pto),
                },
            ParmCtWord::Triv(pts) =>
                // self.is_triv
                match &other.ct {
                    ParmCtWord::Ct(ctbo) => {
                        // !other.is_triv
                        let mut new_self_ct = ctbo.clone();
                        lwe_ciphertext_plaintext_add_assign(&mut new_self_ct.ct, *pts);
                        self.ct = ParmCtWord::Ct(new_self_ct);
                    },
                    ParmCtWord::Triv(pto) =>
                        // other.is_triv
                        self.ct = ParmCtWord::Triv(Plaintext(pts.0.wrapping_add(pto.0))),
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
        let half_pt = Self::half_to_pt(self.msg_mod);

        match &mut self.ct {
            ParmCtWord::Ct(ctbs) => {
                // !self.is_triv, half.is_triv
                lwe_ciphertext_plaintext_add_assign(&mut ctbs.ct, half_pt);
            },
            ParmCtWord::Triv(pts) =>
                // self.is_triv, half.is_triv
                self.ct = ParmCtWord::Triv(Plaintext(pts.0.wrapping_add(half_pt.0))),
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
        match &mut self.ct {
            ParmCtWord::Ct(ctbs) =>
                lwe_ciphertext_opposite_assign(&mut ctbs.ct),
            ParmCtWord::Triv(pts) =>
                self.ct = ParmCtWord::Triv(Plaintext(pts.0.wrapping_neg())),
        }
    }

    pub fn opp(&self) -> Self {
        let mut res = self.clone();
        res.opp_inplace();
        res
    }

    pub fn mul_const_inplace(&mut self, k: i32) {
        let k_abs: u64 = k.abs() as u64;
        match &mut self.ct {
            ParmCtWord::Ct(ctbs) =>
                lwe_ciphertext_cleartext_mul_assign(&mut ctbs.ct, Cleartext(k_abs)),
            ParmCtWord::Triv(pts) =>
                self.ct = ParmCtWord::Triv(Plaintext(pts.0.wrapping_mul(k_abs))),
        }
        if k < 0 {self.opp_inplace();}
    }

    pub fn mul_const(&self, k: i32) -> Self {
        let mut res = self.clone();
        res.mul_const_inplace(k);
        res
    }


    // -------------------------------------------------------------------------
    //  Check trivial values

    pub fn is_triv(&self) -> bool {
        matches!(self.ct, ParmCtWord::Triv(_))
    }

    pub fn is_triv_zero(&self) -> bool {
        if let ParmCtWord::Triv(pts) = self.ct {pts.0 == 0} else {false}
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
        pc: &ParmesanCloudovo,
    ) -> ParmCiphertext;

    //TODO add triv_const (from vec?), the above is triv_zero, used internally (there is ParmArithmetics::zero)

    fn empty() -> ParmCiphertext;

    fn single(ew: ParmEncrWord) -> ParmCiphertext;

    fn to_str(&self) -> String;
}

impl ParmCiphertextImpl for ParmCiphertext {
    fn triv(
        len: usize,
        pc: &ParmesanCloudovo,
    ) -> ParmCiphertext {
        vec![ParmEncrWord::encrypt_word_triv(&pc.pub_keys, 0); len]
    }

    fn empty() -> ParmCiphertext {
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
