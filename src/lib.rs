
////////////////////////////////////////////////////////////////////////////////
//!
//! # PARMESAN: Parallel-ARithMEticS-over-tfhe-ENcrypted-data
//!
//! *A library for fast parallel arithmetics over TFHE-encrypted data.*
//!
//!  ╭─────────╮
//!  │  P.M.S  │
//!  ╰─────────╯
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
pub use ciphertexts::{ParmCiphertext, ParmCiphertextImpl};
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

// Cloudovo modules
pub mod demos;
pub use demos::*;

// Fake threads for sequential analysis
#[cfg(feature = "seq_analyze")]
pub mod seq_utils;


// =============================================================================
//
//  Global Variables
//

/// Minimum value for the parameters' quadratic weights (addition needs 20, maximum needs 22)
static MIN_QUAD_WEIGHT: usize = 22;

/// Addition-Subtraction Chains' bitlength
pub static ASC_BITLEN: usize = 12;
// this file must be present in <exec-dir/assets>, copy it from <lib-root/assets>
static ASC_12_FILE: &str = "assets/asc-12.yaml";

lazy_static::lazy_static! {
/// Addition-Subtraction Chains for Scalar Multiplication
pub static ref ASC_12: BTreeMap<usize, Vec<AddShift>> = Asc::map_from_yaml(ASC_BITLEN, ASC_12_FILE).expect("Asc::map_from_yaml failed.");
}

/// Keeps log level for nested time measurements
pub static mut LOG_LVL: u8 = 0;
/// Log file
pub const LOGFILE: &str = "./operations.log";
pub static mut LOG_INITED: bool = false;

#[cfg(feature = "seq_analyze")]
pub static mut N_PBS: Vec<usize> = Vec::new();


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
        if params.quad_weight < MIN_QUAD_WEIGHT {
            Err(format!("Quadratic weight of provided parameters ({}) is lower than required ({}).", params.quad_weight, MIN_QUAD_WEIGHT).into())
        } else {
            Ok(ParmesanUserovo {
                params,
                priv_keys: PrivKeySet::new(params)?,
            })
        }
    }

    /// Get the Public Key Set
    pub fn export_pub_keys(&self) -> PubKeySet {
        PubKeySet {
            bsk:     &self.priv_keys.bsk,
            ksk:     &self.priv_keys.ksk,
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
        encryption::parm_encrypt(self.params, &self.priv_keys, m, words)
    }

    /// Encrypt a vector of words from alphabet `{-1,0,1}`
    pub fn encrypt_vec(
        &self,
        mv: &Vec<i32>,
    ) -> Result<ParmCiphertext, Box<dyn Error>> {   //WISH change to a template for other integer types/lengths, too
        encryption::parm_encrypt_from_vec(self.params, &self.priv_keys, mv)
    }

    /// Decrypt ciphertext into a 64-bit signed integer
    pub fn decrypt(&self, c: &ParmCiphertext) -> Result<i64, Box<dyn Error>> {   //WISH change to a template for other integer types/lengths, too
        encryption::parm_decrypt(self.params, &self.priv_keys, c)
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
//  TODO / Wishlist
//
//  - scalar mul: 13-bit chains are mostly in 4 additions, but those in 5 additions might not occur in the K-T recoding $\Rightarrow$ check it out!
//
//  - mul_lwe .. for more than 1x1 bit? let say 1x2 bit? what about squaring?
//      - well, for squ it works, for mul?
//      - in squ, can there be more zeros? we have redundant repre..
//  - check optimality of squaring (incorrect estimates for longer inputs)
//  - parallel mulary reduction? is it worth?
//
//  - WISH: track quadratic weight within Parmesan Ciphertext (Vec<(LWE, usize)> ??)
//      - keep track of sample freshness (e.g., in signum recursion that's mess)
//          - identity-bootstrapped only if needed
//          - warning if a fresh sample gets bootstraped -- that could have been done a step in advance
//
//  - NOTES:
//      - very peculiar optimization: Karatsuba splits odd numbers into "halves" .. 31 and 33 worth splitting differently due to 15(s) 16(K) 17(s)
//          - for B = r_0 * s_0 it is worth calling schoolbook, which keeps its length without overlap to A
//          => simple concat, no addition needed
//
//  * check that *everything* runs in parallel (e.g., pairs of operations; nested parallel iterators work as expected, i.e., they put everything into one pool)
//  * for squaring of non-power-of-2: multiply |n|n+1|-bit numbers (isn't this too technical? it can be bypassed by adding a triv zero)
//  * make new estimates on Karatsuba and D&C squaring BS complexity (actually only for 2 and more nested recursion levels, schoolbook does not add extra bits)
//
//  * "floating-point-like" feature:
//      ? at which position shall the number be rounded?
//      ! it may happen that there is a leading zero
//      * devise a "conditional shift": bootstrap the leading position in a maximum-like manner
//      * here, at i-th position, pick either x_i (leading +-1), or x_i-1 (leading 0)
//          0 1 1 0 1 0 0|1 1   / round and cond. shift
//      ->  1 1 0 1 0 1
//
//  * make lib & bin in single project: https://stackoverflow.com/questions/26946646/rust-package-with-both-a-library-and-a-binary
//
//  * cfg for max{} behavior
//  * resolve bootstraps before / after / in between operations
//
//  * wish: add standard base algorithms
//  * WISH: add tree-based method for arbitrary function evaluation
//
//
//
//
//