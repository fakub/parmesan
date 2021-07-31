
////////////////////////////////////////////////////////////////////////////////
//!
//! # PARMESAN: Parallel-ARithMEticS-on-tfhe-ENcrypted-data
//!
//! *A library for fast parallel arithmetics on TFHE-encrypted data.*
//!
////////////////////////////////////////////////////////////////////////////////



#[allow(unused_imports)]
use colored::Colorize;
use concrete::*;

/// Keeps log level for nested time measurements
static mut LOG_LVL: u8 = 0;


// =============================================================================
//
//  Parmesan Modules & Paths
//

// Global modules
#[macro_use]
pub mod misc;
pub mod params;
pub use params::Params;
pub mod ciphertexts;
pub use ciphertexts::ParmCiphertext;

// Userovo modules
pub mod userovo;
pub use userovo::keys::{PrivKeySet,PubKeySet};
pub use userovo::encryption;

// Cloudovo modules
pub mod cloudovo;
pub use cloudovo::addition;
pub use cloudovo::signum;
pub use cloudovo::maximum;


// =============================================================================
//
//  Parmesan Structs
//

// -----------------------------------------------------------------------------
//  Userovo

/// # User-side Parmesan
pub struct ParmesanUserovo<'a> {
    pub params: &'a Params,
    priv_keys: PrivKeySet,
}

impl ParmesanUserovo<'_> {
    /// Create an instance of `ParmesanUserovo`
    /// * save immutable reference to params
    /// * generate keys
    pub fn new(params: &Params) -> ParmesanUserovo {
        ParmesanUserovo {
            params,
            priv_keys: PrivKeySet::new(params),
        }
    }

    /// Get the Public Key Set
    pub fn export_pub_keys(&self) -> PubKeySet {
        PubKeySet {
            bsk:     &self.priv_keys.bsk,
            ksk:     &self.priv_keys.ksk,
            encoder: &self.priv_keys.encoder,
        }
    }

    /// Encrypt a 32-bit signed integer
    /// * `bits` states how many bits of input `m` are to be encrypted, since this will be public
    /// * least significant bits, including sign, are taken
    pub fn encrypt(
        &self,
        m: i32,
        bits: usize,
    ) -> ParmCiphertext {   //TODO change to a template for other integer types/lengths, too
        encryption::parm_encrypt(self.params, &self.priv_keys, m, bits)
    }

    /// Decrypt a 32-bit signed integer
    pub fn decrypt(&self, c: &ParmCiphertext) -> i32 {   //TODO change to a template for other integer types/lengths, too
        encryption::parm_decrypt(self.params, &self.priv_keys, c)
    }
}

// -----------------------------------------------------------------------------
//  Cloudovo

/// # Cloud-side Parmesan
pub struct ParmesanCloudovo<'a> {
    pub params: &'a Params,
    pub_keys: &'a PubKeySet<'a>,
}

impl ParmesanCloudovo<'_> {
    /// Create an instance of `ParmesanCloudovo`
    pub fn new<'a>(
        params: &'a Params,
        pub_keys: &'a PubKeySet,
    ) -> ParmesanCloudovo<'a> {
        ParmesanCloudovo {
            params,
            pub_keys,
        }
    }

    /// Add two ciphertexts in parallel
    pub fn add(
        &self,
        x: &ParmCiphertext,
        y: &ParmCiphertext,
    ) -> ParmCiphertext {
        addition::add_impl(
            //~ self.params,
            self.pub_keys,
            x,
            y,
        )
    }

    /// Signum of a ciphertext by parallel reduction
    pub fn sgn(
        &self,
        x: &ParmCiphertext,
    ) -> ParmCiphertext {
        signum::sgn_impl(
            self.params,
            self.pub_keys,
            x,
        )
    }
}


// =============================================================================
//
//  Global Functions
//

// -----------------------------------------------------------------------------
//  Dev

pub fn parmesan_main() -> Result<(), CryptoAPIError> {
    // say hello
    //~ infobox!("Hi, I am {}, using local {} with custom patches & an unsafe PRNG.", String::from("Parmesan").yellow().bold(), String::from("Concrete").blue().bold());


    // =================================
    //  Initialization

    // ---------------------------------
    //  Global Scope
    let par = &params::PARM90__PI_5__D_20__LEN_32;   //     PARM90__PI_5__D_20__LEN_32      PARMXX__TRIVIAL

    // ---------------------------------
    //  Userovo Scope
    let pu = ParmesanUserovo::new(par);
    let pub_k = pu.export_pub_keys();

    // ---------------------------------
    //  Cloudovo Scope
    let pc = ParmesanCloudovo::new(par, &pub_k);


    // =================================
    //  U: Encryption
    let m1 =  0b00100111i32;
    let m2 =  0b00101110i32;
    let c1 = pu.encrypt(m1, 6);
    let c2 = pu.encrypt(m2, 6);
    infoln!("{} messages\nm1 = {}{:b} ({}),\nm2 = {}{:b} ({}).", String::from("User:").bold().yellow(),
                          if m1 >= 0 {""} else {"-"}, m1.abs(), m1,
                                  if m2 >= 0 {""} else {"-"}, m2.abs(), m2);


    // =================================
    //  C: Evaluation
    let c_sum = pc.add(&c1, &c2);
    let c_sgn = pc.sgn(&c1);


    // =================================
    //  U: Decryption
    let m_sum  = pu.decrypt(&c_sum);
    let m_sgn  = pu.decrypt(&c_sgn);

    infoln!("{} result\nm1 + m2 = {} :: {} (exp. {})\nsgn(m1) = {} :: {}.", String::from("User:").bold().yellow(),
                                   m_sum,
                                         if m_sum == (m1+m2) % (1<<6) {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                                                  (m1+m2) % (1<<6),
                                                                 m_sgn,
                                                                       if m_sgn == m1.signum() {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},);

    infobox!("Demo END");

    Ok(())
}
