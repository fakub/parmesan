use std::error::Error;

use std::path::Path;
#[allow(unused_imports)]
use std::io::{self,Write,BufReader,BufWriter};
pub use std::fs::{self,File,OpenOptions};

#[allow(unused_imports)]
use colored::Colorize;

use concrete_core::prelude::*;

use crate::*;
use crate::params::Params;

pub const KEYS_PATH: &str = "./keys/";



// =============================================================================
//
//  Private Keys
//

//WISH #[derive(Serialize, Deserialize)]
pub struct PrivKeySet {
    pub sk : LweSecretKey64,
    pub ksk: LweKeyswitchKey64,
    pub bsk: FourierLweBootstrapKey64,
}

impl PrivKeySet {

    /// Load or generate a Concrete's v0.2 TFHE key set
    pub fn new(params: &Params) -> Result<PrivKeySet, Box<dyn Error>> {

        // -------------------------------------------------------------------------
        //  Generate / load params & keys
        let filename = Self::filename_from_params(params);
        let path = Path::new(&filename);
        let (_lwe_secret_key_after_ks, _glwe_secret_key, lwe_secret_key, key_switching_key, bootstrapping_key):
            (LweSecretKey64, GlweSecretKey64, LweSecretKey64, LweKeyswitchKey64, FourierLweBootstrapKey64);

        if !path.is_file() {
            measure_duration!(
                ["Generating new keys"],
                [
                    let mut engine = CoreEngine::new(())?;

                    // client keys
                    measure_duration!(
                        ["Generating secret keys (n = {}, N = {})", params.lwe_dimension, params.polynomial_size],
                        [
                            _lwe_secret_key_after_ks = engine.create_lwe_secret_key(params.concrete_pars.lwe_dimension)?;
                            _glwe_secret_key = engine.create_glwe_secret_key(params.concrete_pars.glwe_dimension, params.concrete_pars.polynomial_size)?;
                            lwe_secret_key = engine.transmute_glwe_secret_key_to_lwe_secret_key(_glwe_secret_key.clone())?;
                        ]
                    );

                    // server keys
                    measure_duration!(
                        ["Calculating public key-switching keys"],
                        [
                            key_switching_key = engine.create_lwe_keyswitch_key(
                                &lwe_secret_key,
                                &_lwe_secret_key_after_ks,
                                params.concrete_pars.ks_level,
                                params.concrete_pars.ks_base_log,
                                Variance(params.lwe_var_f64()),
                            )?;
                        ]
                    );
                    measure_duration!(
                        ["Calculating public bootstrapping keys"],
                        [
                            bootstrapping_key = engine.create_lwe_bootstrap_key(
                                &_lwe_secret_key_after_ks,
                                &_glwe_secret_key,
                                params.concrete_pars.pbs_base_log,
                                params.concrete_pars.pbs_level,
                                Variance(params.glwe_var_f64()),
                            )?;
                        ]
                    );
                ]
            );

            measure_duration!(
                ["Exporting new keys"],
                [
                    let keys_file = File::create(path).map(BufWriter::new)?;
                    bincode::serialize_into(keys_file, &(&_lwe_secret_key_after_ks, &_glwe_secret_key, &lwe_secret_key, &key_switching_key, &bootstrapping_key))?;
                ]
            );
        } else {
            // create KEYS_PATH directory, unless it exists
            fs::create_dir_all(KEYS_PATH)?;

            measure_duration!(
                ["Loading saved keys"],
                [
                    let keys_file = File::open(path).map(BufReader::new)?;
                    (_lwe_secret_key_after_ks, _glwe_secret_key, lwe_secret_key, key_switching_key, bootstrapping_key) = bincode::deserialize_from(keys_file)?;
                ]
            );
        }

        // fill & return PrivKeySet struct
        Ok(PrivKeySet {
            sk : lwe_secret_key,
            ksk: key_switching_key,
            bsk: bootstrapping_key,
        })
    }

    /// Get filename from params
    fn filename_from_params(pars: &Params) -> String {
        let suffix = format!("n-{}_N-{}_gamma-{}_l-{}_kappa-{}_t-{}_v0.2.key",
                                pars.lwe_dimension(),
                                     pars.polynomial_size(),
                                              pars.pbs_base_log(),
                                                   pars.pbs_level(),
                                                            pars.ks_base_log(),
                                                                 pars.ks_level(),
        );
        let filename = format!("{}/concrete_keys__{}", KEYS_PATH, suffix);

        filename
    }
}



// =============================================================================
//
//  Public Keys
//

pub struct PubKeySet<'a> {
    pub ksk: &'a LweKeyswitchKey64,
    pub bsk: &'a FourierLweBootstrapKey64,
}
