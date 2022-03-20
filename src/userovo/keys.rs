use std::error::Error;
use std::path::Path;
#[allow(unused_imports)]
use std::io::{self,Write};
//TODO add feature condition
pub use std::fs::{self,File,OpenOptions};
//~ pub use std::path::Path;
//~ pub use std::io::Write;

#[allow(unused_imports)]
use colored::Colorize;

use concrete::*;

use crate::*;
use crate::params::Params;

pub const KEYS_PATH: &str = "./keys/";



// =============================================================================
//
//  Private Keys
//

//WISH #[derive(Serialize, Deserialize)]
pub struct PrivKeySet {
    // keys
    pub  sk: LWESecretKey,
    pub bsk: LWEBSK,
    pub ksk: LWEKSK,
    // rlwe_sk: RLWESecretKey,   // encrypts bsk .. add?
    // encoders
    pub encoder: Encoder,
}

impl PrivKeySet {

    /// Load or generate a TFHE key set
    pub fn new(params: &Params) -> Result<PrivKeySet, Box<dyn Error>> {
        // derive filenames
        let (sk_file, bsk_file, ksk_file) = PrivKeySet::filenames_from_params(params);

        // check if the keys exist
        if     Path::new( sk_file.as_str()).is_file()
            && Path::new(bsk_file.as_str()).is_file()
            && Path::new(ksk_file.as_str()).is_file()
        {
            // load keys from files
            measure_duration!(
                ["Load PrivKeySet"],
                [
                    let keys = PrivKeySet {
                         sk: LWESecretKey::load( sk_file.as_str())?,
                        bsk:       LWEBSK::load(bsk_file.as_str()),     // does not return Result enum
                        ksk:       LWEKSK::load(ksk_file.as_str()),     // does not return Result enum
                        encoder:   PrivKeySet::get_encoder(params)?,
                    };
                ]
            );

            return Ok(keys);
        } else {
            // generate & save keys
            measure_duration!(
                ["Generate & Save PrivKeySet"],
                [
                    let keys = PrivKeySet::generate(params)?;

                    measure_duration!(
                        ["Saving  LWE secret key"],
                        [keys .sk.save( sk_file.as_str())?;]);
                    measure_duration!(
                        ["Saving bootstrapping keys"],
                        [keys.bsk.save(bsk_file.as_str());]);
                    measure_duration!(
                        ["Saving key-switching keys"],
                        [keys.ksk.save(ksk_file.as_str());]);
                ]
            );

            return Ok(keys);
        }
    }

    /// Generate a fresh TFHE key set
    fn generate(params: &Params) -> Result<PrivKeySet, Box<dyn Error>> {
        // generate LWE & RLWE secret keys
        measure_duration!(
            ["Generating  LWE secret key ({}-bit)", params.lwe_params.dimension],
            [let      sk:  LWESecretKey =  LWESecretKey::new(&params.lwe_params );]);
        measure_duration!(
            ["Generating RLWE secret key (deg = {})", params.rlwe_params.polynomial_size],
            [let rlwe_sk: RLWESecretKey = RLWESecretKey::new(&params.rlwe_params);]);

        // calculate bootstrapping & key-switching keys
        measure_duration!(
            ["Calculating bootstrapping keys"],
            [let bsk: LWEBSK = LWEBSK::new(
                &sk,
                &rlwe_sk,
                params.bs_base_log,
                params.bs_level,
            );]);
        measure_duration!(
            ["Calculating key-switching keys"],
            [let ksk: LWEKSK = LWEKSK::new(
                &rlwe_sk.to_lwe_secret_key(),
                &sk,
                params.ks_base_log,
                params.ks_level,
            );]);

        // fill & return PrivKeySet struct
        Ok(PrivKeySet {
            sk,     // shortand when variables and fields have the same name
            bsk,    // https://doc.rust-lang.org/book/ch05-01-defining-structs.html#using-the-field-init-shorthand-when-variables-and-fields-have-the-same-name
            ksk,
            encoder: PrivKeySet::get_encoder(params)?,
        })
    }

    /// Get appropriate Encoder
    fn get_encoder(params: &Params) -> Result<Encoder, Box<dyn Error>> {
        Ok(Encoder::new_rounding_context(
            0.,                                                 // min
            ((1usize << params.bit_precision) - 1) as f64,      // max
            params.bit_precision,                               // bit-precision
            0,                                                  // padding
            true,                                               // negacyclic?
        )?)
    }

    /// Get filenames from params
    fn filenames_from_params(par: &Params) -> (String, String, String) {
        let suffix = format!("n-{}_N-{}_gamma-{}_l-{}_kappa-{}_t-{}.key",
                                par.lwe_params.dimension,
                                     par.rlwe_params.polynomial_size,
                                              par.bs_base_log,
                                                   par.bs_level,
                                                            par.ks_base_log,
                                                                 par.ks_level,
        );
        let  sk_file = format!( "{}/SK__{}", KEYS_PATH, suffix);
        let  bk_file = format!( "{}/BK__{}", KEYS_PATH, suffix);
        let ksk_file = format!("{}/KSK__{}", KEYS_PATH, suffix);

        (sk_file, bk_file, ksk_file)
    }
}



// =============================================================================
//
//  Public Keys
//

//WISH #[derive(Serialize, Deserialize)]
pub struct PubKeySet<'a> {
    pub bsk:     &'a LWEBSK,
    pub ksk:     &'a LWEKSK,
    pub encoder: &'a Encoder,
}
