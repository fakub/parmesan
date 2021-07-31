
////////////////////////////////////////////////////////////////////////////////
//!
//! # PARMESAN: Parallel-ARithMEticS-on-tfhe-ENcrypted-data
//!
//! *A library for fast parallel arithmetics on TFHE-encrypted data.*
//!
////////////////////////////////////////////////////////////////////////////////



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
    let m1 =  0b00101110i32;
    let m2 = -0b10110100i32;
    let c1 = pu.encrypt(m1, 6);
    let c2 = pu.encrypt(m2, 6);
    infoln!("{} messages ({}{:b} ({}), {}{:b} ({})) encrypted.", String::from("User:").bold().yellow(),
                          if m1 >= 0 {""} else {"-"}, m1.abs(), m1,
                                  if m2 >= 0 {""} else {"-"}, m2.abs(), m2);


    // =================================
    //  C: Evaluation
    let c = pc.add(&c1, &c2);


    // =================================
    //  U: Decryption
    //~ let m1d = pu.decrypt(&c1);
    //~ let m2d = pu.decrypt(&c2);
    let md  = pu.decrypt(&c );
    infoln!("{}\ninput 1: {},\ninput 2: {}\nresult: {}.", String::from("User:").bold().yellow(), -99i32, -99i32, md);   // String::from(format!("{}", m)).bold().yellow()

    infobox!("Demo END");

    Ok(())
}
