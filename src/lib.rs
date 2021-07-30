//!
//! # PARMESAN: Parallel-ARithMEticS-on-tfhe-ENcrypted-data
//!
//! *A library for fast parallel arithmetics on TFHE-encrypted data.*
//!

#[allow(unused_imports)]
use std::io::{self,Write};

use colored::Colorize;
use concrete::*;

static mut LOG_LVL: u8 = 0;



// =============================================================================
//
//  Parmesan Modules & Paths
//

// Global modules
#[macro_use]
mod misc;
mod params;
pub use params::Params;
mod ciphertexts;
pub use ciphertexts::ParmCiphertext;

// Userovo modules
mod userovo;
pub use userovo::keys::{PrivKeySet,PubKeySet};
pub use userovo::encryption;

// Cloudovo modules
mod cloudovo;
pub use cloudovo::addition;



// =============================================================================
//
//  Parmesan Structs
//

// -----------------------------------------------------------------------------
//  Userovo

/// User-side Parmesan
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
    pub fn get_pub_keys(&self) -> PubKeySet {
        PubKeySet {
            bsk: &self.priv_keys.bsk,
            ksk: &self.priv_keys.ksk,
        }
    }

    /// Encrypt a 32-bit signed integer
    pub fn encrypt(&self, m: i32) -> ParmCiphertext {   //TODO change to a template for other integer lengths, too
        ParmCiphertext {
            maxlen: 32,
        }
    }

    /// Decrypt a 32-bit signed integer
    pub fn decrypt(&self, c: ParmCiphertext) -> i32 {   //TODO change to a template for other integer lengths, too
        42
    }
}

// -----------------------------------------------------------------------------
//  Cloudovo

/// Cloud-side Parmesan
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
    pub fn add(x: ParmCiphertext, y: ParmCiphertext) -> ParmCiphertext {
        ParmCiphertext {
            maxlen: 5,
        }
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
    parmesan_hello();


    // =================================
    //  Initialization

    // ---------------------------------
    //  Global Scope
    let par = &params::PARMXX__TRIVIAL;

    // ---------------------------------
    //  Userovo Scope
    let pu = ParmesanUserovo::new(par);
    infoln!("Generated {} scope.", String::from("Userovo").bold().yellow());
    let pub_k = pu.get_pub_keys();

    // ---------------------------------
    //  Cloudovo Scope
    let pc = ParmesanCloudovo::new(par, &pub_k);
    infoln!("Generated {} scope.", String::from("Cloudovo").bold().yellow());


    // =================================
    //  U: Encryption


    // =================================
    //  C: Evaluation


    // =================================
    //  U: Decryption






    // encoders
    let encoder_input  = Encoder::new_rounding_context(0., 15., 4, 1)?;         // input message can be in the interval [0,16)
    let encoder_output = Encoder::new_rounding_context(0., 15., 4, 0)?;

    // keys
    let keys = PrivKeySet::new(&params::PARM90__PI_5__D_20);
    //~ let keys = KeySet::new(&params::PARMXX__TRIVIAL);

    // messages
    let m: f64 = 3.;

    // encode and encrypt
    let p: Plaintext = encoder_input.encode_single(m)?;
    let m_dec = p.decode()?;
    let c = LWE::encode_encrypt(&keys.sk, m, &encoder_input)?;

    // bootstrap
    let fc_r =    c.bootstrap_with_function(&keys.bsk, |x| x * x, &encoder_output)?;
    let fc   = fc_r.keyswitch(&keys.ksk)?;

    // try LUT
    //~ let lut = |x| [1, 2, 3, 4, 5][x];
    //~ let var = 3;
    //~ println!("LUT({}) = {}", var, lut(var));

    // decrypt
    let fm = fc.decrypt_decode(&keys.sk)?;

    println!("before bootstrap: {}, after bootstrap: {}", m_dec[0], fm);

    Ok(())
}

pub fn parmesan_hello() {
    infoln!("Hi, I am {}, using local {} with custom patches & an unsafe PRNG.", String::from("Parmesan").yellow().bold(), String::from("Concrete").blue().bold());
}
