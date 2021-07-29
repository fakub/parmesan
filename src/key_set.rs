use concrete::*;
use std::path::Path;

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
            return KeySet {
                 sk: LWESecretKey::load( sk_file.as_str()).expect("Failed to load secret key from file."),
                bsk:       LWEBSK::load(bsk_file.as_str()),     // does not return Result enum
                ksk:       LWEKSK::load(ksk_file.as_str()),     // does not return Result enum
            }
        } else {
            // generate & save keys
            let key_set = KeySet::generate(prms);

             key_set.sk.save( sk_file.as_str()).expect("Failed to save secret key to file.");
            key_set.bsk.save(bsk_file.as_str());
            key_set.ksk.save(ksk_file.as_str());

            return key_set;
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
        let      sk:  LWESecretKey =  LWESecretKey::new(&prms.lwe_params);
        let rlwe_sk: RLWESecretKey = RLWESecretKey::new(&prms.rlwe_params);

        // calculate bootstrapping & key-switching keys
        let bsk: LWEBSK = LWEBSK::new(
            &sk,
            &rlwe_sk,
            prms.bs_base_log,
            prms.bs_level,
        );
        let ksk: LWEKSK = LWEKSK::new(
            &rlwe_sk.to_lwe_secret_key(),
            &sk,
            prms.ks_base_log,
            prms.ks_level,
        );

        // fill & return KeySet struct
        KeySet {
            sk,     // shortand when variables and fields have the same name
            bsk,    // https://doc.rust-lang.org/book/ch05-01-defining-structs.html#using-the-field-init-shorthand-when-variables-and-fields-have-the-same-name
            ksk,
        }
    }
}
