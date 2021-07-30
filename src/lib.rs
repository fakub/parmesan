
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
use cloudovo::pbs;   //WISH to be removed after tested


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
        encryption::encrypt(self.params, &self.priv_keys, m, bits)
    }

    /// Decrypt a 32-bit signed integer
    pub fn decrypt(&self, c: &ParmCiphertext) -> i32 {   //TODO change to a template for other integer types/lengths, too
        encryption::decrypt(self.params, &self.priv_keys, c)
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
        addition::add_impl(self.params, self.pub_keys, x, y)
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
    infoln!("Initialized {} scope.", String::from("Userovo").bold().yellow());
    let pub_k = pu.export_pub_keys();

    // ---------------------------------
    //  Cloudovo Scope
    let pc = ParmesanCloudovo::new(par, &pub_k);
    infoln!("Initialized {} scope.", String::from("Cloudovo").bold().yellow());


    // =================================
    //  U: Encryption
    let m1 = 42i32;
    let m2 = -69i32;
    let c1 = pu.encrypt(m1, 6);
    let c2 = pu.encrypt(m2, 6);
    infoln!("{} messages ({}, {}) encrypted.", String::from("User:").bold().yellow(), m1, m2);


    // =================================
    //  C: Evaluation
    let c = pc.add(&c1, &c2);
    infoln!("{} addition evaluated over ciphertexts.", String::from("Cloud:").bold().yellow());


    // =================================
    //  U: Decryption
    let m1d = pu.decrypt(&c1);
    let m2d = pu.decrypt(&c2);
    let md  = pu.decrypt(&c );
    infoln!("{}\ninput 1: {},\ninput 2: {}\nresult: {}.", String::from("User:").bold().yellow(), m1d, m2d, md);   // String::from(format!("{}", m)).bold().yellow()

    infobox!("Demo END");




    // encoders
    let encoder_input  = Encoder::new_rounding_context(0., 15., 4, 1)?;         // input message can be in the interval [0,16)
    let encoder_output = Encoder::new_rounding_context(0., 15., 4, 0)?;

    // keys
    let keys = PrivKeySet::new(&params::PARM90__PI_5__D_20);
    //  PARMXX__TRIVIAL
    //  PARM90__PI_5__D_20

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
    infobox!("Hi, I am {}, using local {} with custom patches & an unsafe PRNG.", String::from("Parmesan").yellow().bold(), String::from("Concrete").blue().bold());
}
