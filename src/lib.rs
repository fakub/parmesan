
////////////////////////////////////////////////////////////////////////////////
//!
//! # PARMESAN: Parallel-ARithMEticS-on-tfhe-ENcrypted-data
//!
//! *A library for fast parallel arithmetics on TFHE-encrypted data.*
//!
//!  ╭─────────╮
//!  │  P.M.S  │
//!  ╰─────────╯
//!
//! Employs the Concrete Library.
//!
//!  •        •
//!    ▂█████
//!    ██
//!    ██
//!    ▀█████
//!  •        •
//!
////////////////////////////////////////////////////////////////////////////////



use std::error::Error;

pub use std::fs::{self,File,OpenOptions};
pub use std::path::Path;
pub use std::io::Write;
pub use std::collections::BTreeMap;

extern crate chrono;
extern crate lazy_static;

#[allow(unused_imports)]
use colored::Colorize;


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
pub use ciphertexts::{ParmCiphertext, ParmCiphertextExt};
pub mod arithmetics;
pub use arithmetics::ParmArithmetics;
pub mod experiments;

// Userovo modules
pub mod userovo;
pub use userovo::*;
pub use userovo::keys::{PrivKeySet,PubKeySet};

// Cloudovo modules
pub mod cloudovo;
pub use cloudovo::*;
pub use cloudovo::neural_network::{Perceptron, PercType, NeuralNetwork};
pub use cloudovo::scalar_multiplication::asc::*;


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
    pub fn new(params: &Params) -> Result<ParmesanUserovo, Box<dyn Error>> {
        Ok(ParmesanUserovo {
            params,
            priv_keys: PrivKeySet::new(params)?,
        })
    }

    /// Get the Public Key Set
    pub fn export_pub_keys(&self) -> PubKeySet {
        PubKeySet {
            bsk:     &self.priv_keys.bsk,
            ksk:     &self.priv_keys.ksk,
            encoder: &self.priv_keys.encoder,
        }
    }

    /// Encrypt a 64-bit signed integer
    /// * `bits` states how many bits of input `m` are to be encrypted, since this will be public
    /// * least significant bits, including sign, are taken
    pub fn encrypt(
        &self,
        m: i64,
        words: usize,
    ) -> Result<ParmCiphertext, Box<dyn Error>> {   //WISH change to a template for other integer types/lengths, too
        Ok(encryption::parm_encrypt(self.params, &self.priv_keys, m, words)?)
    }

    /// Encrypt a vector of words from alphabet `{-1,0,1}`
    pub fn encrypt_vec(
        &self,
        mv: &Vec<i32>,
    ) -> Result<ParmCiphertext, Box<dyn Error>> {   //WISH change to a template for other integer types/lengths, too
        Ok(encryption::parm_encrypt_vec(self.params, &self.priv_keys, mv)?)
    }

    /// Decrypt ciphertext into a 64-bit signed integer
    pub fn decrypt(&self, c: &ParmCiphertext) -> Result<i64, Box<dyn Error>> {   //WISH change to a template for other integer types/lengths, too
        Ok(encryption::parm_decrypt(self.params, &self.priv_keys, c)?)
    }
}

// -----------------------------------------------------------------------------
//  Cloudovo

/// # Cloud-side Parmesan
pub struct ParmesanCloudovo<'a> {
    pub params: &'a Params,
    pub pub_keys: &'a PubKeySet<'a>,
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
}


// =============================================================================
//
//  Global Variables
//

/// Keeps log level for nested time measurements
pub static mut LOG_LVL: u8 = 0;
/// Log file
pub const LOGFILE: &str = "./operations.log";
pub static mut LOG_INITED: bool = false;

/// Addition-Subtraction Chains' bitlength
pub static ASC_BITLEN: usize = 12;
// this file must be present in <exec-dir/assets>, copy it from <lib-root/assets>
static ASC_12_FILE: &str = "assets/asc-12.yaml";

lazy_static::lazy_static! {
/// Addition-Subtraction Chains for Scalar Multiplication
pub static ref ASC_12: BTreeMap<usize, Vec<AddShift>> = Asc::map_from_yaml(ASC_BITLEN, ASC_12_FILE).expect("Asc::map_from_yaml failed.");
}


// =============================================================================
//
//  TODO / Wishlist
//
//  - WISH: track quadratic weight within Parmesan Ciphertext (Vec<(LWE, usize)> ??)
//      - identity-bootstrapped only if needed
//      => keeps track of sample freshness (e.g., in signum recursion that's mess)
//      - warn if a fresh sample gets bootstraped -- that could be done a step in advance
