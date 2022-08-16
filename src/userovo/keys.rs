use std::error::Error;

use std::path::Path;
#[allow(unused_imports)]
use std::io::{self,Write};
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
//FIXME change to new Concrete
pub struct PrivKeySet {
    // keys
    pub  sk: LweSecretKey64,
    pub ksk: LweKeyswitchKey64,
    pub bsk: FourierLweBootstrapKey64,
}

impl PrivKeySet {

    /// Load or generate a TFHE key set
    pub fn new(params: &Params) -> Result<PrivKeySet, Box<dyn Error>> {

        //~ // -------------------------------------------------------------------------
        //~ //  Generate / load params & keys
        //~ let path_m3c2  = Path::new(M3_C2_STP_FILE);
        //~ let (params, _lwe_secret_key_after_ks, _glwe_secret_key, lwe_secret_key, key_switching_key, bootstrapping_key) = if !path_m3c2 .is_file() {
            //~ println!("Generating new params & keys");
            //~ let params = concrete_shortint::parameters::PARAM_MESSAGE_3_CARRY_2;
            //~ let var_lwe = Variance(params.lwe_modular_std_dev.get_variance());
            //~ let var_rlwe = Variance(params.glwe_modular_std_dev.get_variance());
            //~ let mut engine = CoreEngine::new(())?;

            //~ // client keys
            //~ let lwe_secret_key_after_ks: LweSecretKey64 = engine.create_lwe_secret_key(params.lwe_dimension)?;
            //~ let glwe_secret_key: GlweSecretKey64 = engine.create_glwe_secret_key(params.glwe_dimension, params.polynomial_size)?;
            //~ let lwe_secret_key: LweSecretKey64 = engine.transmute_glwe_secret_key_to_lwe_secret_key(glwe_secret_key.clone())?;

            //~ // server keys
            //~ let key_switching_key: LweKeyswitchKey64 = engine.create_lwe_keyswitch_key(
                //~ &lwe_secret_key,
                //~ &lwe_secret_key_after_ks,
                //~ params.ks_level,
                //~ params.ks_base_log,
                //~ var_lwe,
            //~ )?;
            //~ let bootstrapping_key: FourierLweBootstrapKey64 = engine.create_lwe_bootstrap_key(
                //~ &lwe_secret_key_after_ks,
                //~ &glwe_secret_key,
                //~ params.pbs_base_log,
                //~ params.pbs_level,
                //~ var_rlwe,
            //~ )?;

            //~ println!("Exporting new params & keys");
            //~ let stp_file = File::create(path_m3c2).map(BufWriter::new)?;
            //~ bincode::serialize_into(stp_file, &(&params, &lwe_secret_key_after_ks, &glwe_secret_key, &lwe_secret_key, &key_switching_key, &bootstrapping_key))?;

            //~ (params, lwe_secret_key_after_ks, glwe_secret_key, lwe_secret_key, key_switching_key, bootstrapping_key)
        //~ } else {
            //~ println!("Loading saved params & keys");
            //~ let stp_file = File::open(path_m3c2).map(BufReader::new)?;
            //~ bincode::deserialize_from(stp_file)?
        //~ };

        //FIXME ------------    was:    ----------------------------------------

        //~ // derive filenames
        //~ let (sk_file, bsk_file, ksk_file) = PrivKeySet::filenames_from_params(params);

        //~ // check if the keys exist
        //~ if     Path::new( sk_file.as_str()).is_file()
            //~ && Path::new(bsk_file.as_str()).is_file()
            //~ && Path::new(ksk_file.as_str()).is_file()
        //~ {
            //~ // load keys from files
            //~ measure_duration!(
                //~ ["Load PrivKeySet"],
                //~ [
                    //~ let keys = PrivKeySet {
                         //~ sk: LWESecretKey::load( sk_file.as_str())?,
                        //~ bsk:       LWEBSK::load(bsk_file.as_str()),     // does not return Result enum
                        //~ ksk:       LWEKSK::load(ksk_file.as_str()),     // does not return Result enum
                        //~ encoder:   PrivKeySet::get_encoder(params)?,
                    //~ };
                //~ ]
            //~ );

            //~ return Ok(keys);
        //~ } else {
            //~ // generate & save keys
            //~ measure_duration!(
                //~ ["Generate & Save PrivKeySet"],
                //~ [
                    //~ let keys = PrivKeySet::generate(params)?;

                    //~ // create KEYS_PATH directory, unless it exists
                    //~ fs::create_dir_all(KEYS_PATH)?;

                    //~ measure_duration!(
                        //~ ["Saving  LWE secret key"],
                        //~ [keys .sk.save( sk_file.as_str())?;]);
                    //~ measure_duration!(
                        //~ ["Saving bootstrapping keys"],
                        //~ [keys.bsk.save(bsk_file.as_str());]);
                    //~ measure_duration!(
                        //~ ["Saving key-switching keys"],
                        //~ [keys.ksk.save(ksk_file.as_str());]);
                //~ ]
            //~ );

            //~ return Ok(keys);
        //~ }
    }

    //~ /// Generate a fresh TFHE key set
    //~ fn generate(params: &Params) -> Result<PrivKeySet, Box<dyn Error>> {
        //~ // generate LWE & RLWE secret keys
        //~ measure_duration!(
            //~ ["Generating  LWE secret key ({}-bit)", params.lwe_params.dimension],
            //~ [let      sk:  LWESecretKey =  LWESecretKey::new(&params.lwe_params );]);
        //~ measure_duration!(
            //~ ["Generating RLWE secret key (deg = {})", params.rlwe_params.polynomial_size],
            //~ [let rlwe_sk: RLWESecretKey = RLWESecretKey::new(&params.rlwe_params);]);

        //~ // calculate bootstrapping & key-switching keys
        //~ measure_duration!(
            //~ ["Calculating bootstrapping keys"],
            //~ [let bsk: LWEBSK = LWEBSK::new(
                //~ &sk,
                //~ &rlwe_sk,
                //~ params.bs_base_log,
                //~ params.bs_level,
            //~ );]);
        //~ measure_duration!(
            //~ ["Calculating key-switching keys"],
            //~ [let ksk: LWEKSK = LWEKSK::new(
                //~ &rlwe_sk.to_lwe_secret_key(),
                //~ &sk,
                //~ params.ks_base_log,
                //~ params.ks_level,
            //~ );]);

        //~ // fill & return PrivKeySet struct
        //~ Ok(PrivKeySet {
            //~ sk,     // shortand when variables and fields have the same name
            //~ bsk,    // https://doc.rust-lang.org/book/ch05-01-defining-structs.html#using-the-field-init-shorthand-when-variables-and-fields-have-the-same-name
            //~ ksk,
            //~ encoder: PrivKeySet::get_encoder(params)?,
        //~ })
    //~ }

    //~ /// Get filenames from params
    //~ fn filenames_from_params(par: &Params) -> (String, String, String) {
        //~ let suffix = format!("n-{}_N-{}_gamma-{}_l-{}_kappa-{}_t-{}.key",
                                //~ par.lwe_params.dimension,
                                     //~ par.rlwe_params.polynomial_size,
                                              //~ par.bs_base_log,
                                                   //~ par.bs_level,
                                                            //~ par.ks_base_log,
                                                                 //~ par.ks_level,
        //~ );
        //~ let  sk_file = format!( "{}/SK__{}", KEYS_PATH, suffix);
        //~ let  bk_file = format!( "{}/BK__{}", KEYS_PATH, suffix);
        //~ let ksk_file = format!("{}/KSK__{}", KEYS_PATH, suffix);

        //~ (sk_file, bk_file, ksk_file)
    //~ }
}



// =============================================================================
//
//  Public Keys
//

pub struct PubKeySet<'a> {
    pub ksk: &'a LweKeyswitchKey64,
    pub bsk: &'a FourierLweBootstrapKey64,
}
