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
pub use userovo::keys::{PrivKeySet,PubKeySet,KeySet};   //TODO remove KeySet
pub use userovo::encryption;

// Cloudovo modules
mod cloudovo;
pub use cloudovo::addition;



// =============================================================================
//
//  Parmesan Structs
//

pub struct ParmesanUserovo {
    priv_keys: PrivKeySet,
    pub params: Params,
}

pub struct ParmesanCloudovo {
    pub_keys: PubKeySet,
    pub params: Params,
}

pub fn parmesan_hello() {
    infoln!("Hi, I am {}, using local {} with custom patches & an unsafe PRNG.", String::from("Parmesan").yellow().bold(), String::from("Concrete").blue().bold());
}

pub fn parmesan_main() -> Result<(), CryptoAPIError> {
    // say hello
    parmesan_hello();

    // encoders
    let encoder_input  = Encoder::new_rounding_context(0., 15., 4, 1)?;         // input message can be in the interval [0,16)
    let encoder_output = Encoder::new_rounding_context(0., 15., 4, 0)?;

    // keys
    let keys = KeySet::load_gen(&params::PARM90__PI_5__D_20);
    //~ let keys = KeySet::load_gen(&params::PARMXX__TRIVIAL);

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

// a list of modules goes here:
