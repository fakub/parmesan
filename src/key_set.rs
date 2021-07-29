use concrete::*;
use std::path::Path;
use colored::Colorize;

#[allow(unused_imports)]
use std::io::{self,Write};

use super::params;

pub struct KeySet {
    pub  sk: LWESecretKey,
    pub bsk: LWEBSK,
    pub ksk: LWEKSK,
    // rlwe_sk: RLWESecretKey,   // encrypts bsk .. add?
}

impl KeySet {

    /// Load or generate a TFHE key set
    pub fn load_gen(prms: &params::Params) -> KeySet {
        // derive filenames
        let (sk_file, bsk_file, ksk_file) = KeySet::filenames_from_params(prms);

        // check if the keys exist
        if     Path::new( sk_file.as_str()).is_file()
            && Path::new(bsk_file.as_str()).is_file()
            && Path::new(ksk_file.as_str()).is_file()
        {
            // load keys from files
            crate::measure_duration!(
                "Load KeySet",
                [
                    let keys = KeySet {
                         sk: LWESecretKey::load( sk_file.as_str()).expect("Failed to load secret key from file."),
                        bsk:       LWEBSK::load(bsk_file.as_str()),     // does not return Result enum
                        ksk:       LWEKSK::load(ksk_file.as_str()),     // does not return Result enum
                    };
                ]
            );

            return keys;
        } else {
            // generate & save keys
            crate::measure_duration!(
                "Generate & Save KeySet",
                [
                    let keys = KeySet::generate(prms);

                    crate::measure_duration!(
                        "Saving  LWE secret key",
                        [keys.sk.save( sk_file.as_str()).expect("Failed to save secret key to file.");]);
                    crate::measure_duration!(
                        "Saving bootstrapping keys",
                        [keys.bsk.save(bsk_file.as_str());]);
                    crate::measure_duration!(
                        "Saving key-switching keys",
                        [keys.ksk.save(ksk_file.as_str());]);
                ]
            );

            return keys;
        }
    }

    /// Get filenames from params
    fn filenames_from_params(prms: &params::Params) -> (String, String, String) {
        let  sk_file: String = format!("secret-key__n-{}.key",
                                                      prms.lwe_params.dimension,
        );
        let bsk_file: String = format!("bootstrapping-keys__n-{}_k-{}_N-{}_gamma-{}_l-{}.key",
                                                            prms.lwe_params.dimension,
                                                                 prms.rlwe_params.dimension,
                                                                      prms.rlwe_params.polynomial_size,
                                                                           prms.bs_base_log,
                                                                                    prms.bs_level,
        );
        let ksk_file: String = format!("key-switching-keys__n-{}_k-{}_N-{}_kappa-{}_t-{}.key",
                                                            prms.lwe_params.dimension,
                                                                 prms.rlwe_params.dimension,
                                                                      prms.rlwe_params.polynomial_size,
                                                                           prms.ks_base_log,
                                                                                    prms.ks_level,
        );

        (sk_file, bsk_file, ksk_file)
    }

    /// Generate a fresh TFHE key set
    fn generate(prms: &params::Params) -> KeySet {
        // generate LWE & RLWE secret keys
        crate::measure_duration!(
            "Generating  LWE secret key",   //TODO add formatting for: "{}-bit", prms.lwe_params.dimension
            [let      sk:  LWESecretKey =  LWESecretKey::new(&prms.lwe_params );]);
        crate::measure_duration!(
            "Generating RLWE secret key",
            [let rlwe_sk: RLWESecretKey = RLWESecretKey::new(&prms.rlwe_params);]);

        // calculate bootstrapping & key-switching keys
        crate::measure_duration!(
            "Calculating bootstrapping keys",
            [let bsk: LWEBSK = LWEBSK::new(
                &sk,
                &rlwe_sk,
                prms.bs_base_log,
                prms.bs_level,
            );]);
        crate::measure_duration!(
            "Calculating key-switching keys",
            [let ksk: LWEKSK = LWEKSK::new(
                &rlwe_sk.to_lwe_secret_key(),
                &sk,
                prms.ks_base_log,
                prms.ks_level,
            );]);

        // fill & return KeySet struct
        KeySet {
            sk,     // shortand when variables and fields have the same name
            bsk,    // https://doc.rust-lang.org/book/ch05-01-defining-structs.html#using-the-field-init-shorthand-when-variables-and-fields-have-the-same-name
            ksk,
        }
    }
}
