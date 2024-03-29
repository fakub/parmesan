use std::error::Error;

use std::path::Path;
#[allow(unused_imports)]
use std::io::{self,Write,BufReader,BufWriter};
pub use std::fs::{self,File,OpenOptions};

#[allow(unused_imports)]
use colored::Colorize;

use tfhe::shortint::prelude::*;

use crate::*;
use crate::params::Params;

pub const KEYS_PATH: &str = "./keys/";



// =============================================================================
//
//  Private Keys
//

//WISH #[derive(Serialize, Deserialize)]
pub struct PrivKeySet {
    pub client_key: ClientKey,
    pub server_key: ServerKey,
}

impl PrivKeySet {

    /// Load or generate a Concrete's v0.2 TFHE key set
    pub fn new(params: &Params) -> Result<PrivKeySet, Box<dyn Error>> {

        // -------------------------------------------------------------------------
        //  Generate / load params & keys
        let filename = Self::filename_from_params(params);
        let path = Path::new(&filename);
        let (client_key, server_key): (ClientKey, ServerKey);

        if !path.is_file() {
            // create KEYS_PATH directory, unless it exists
            fs::create_dir_all(KEYS_PATH)?;

            measure_duration!(
                ["Generating new keys"],
                [
                    (client_key, server_key) = gen_keys(params.concrete_pars);
                ]
            );

            measure_duration!(
                ["Exporting new keys"],
                [
                    let keys_file = File::create(path).map(BufWriter::new)?;
                    bincode::serialize_into(keys_file, &(&client_key, &server_key))?;
                ]
            );
        } else {
            measure_duration!(
                ["Loading saved keys"],
                [
                    let keys_file = File::open(path).map(BufReader::new)?;
                    (client_key, server_key) = bincode::deserialize_from(keys_file)?;
                ]
            );
        }

        // fill & return PrivKeySet struct
        Ok(PrivKeySet {client_key, server_key})
    }

    /// Get filename from params
    fn filename_from_params(pars: &Params) -> String {
        let suffix = format!("n-{}_N-{}_gamma-{}_l-{}_kappa-{}_t-{}.key",
                                pars.lwe_dimension(),
                                     pars.polynomial_size(),
                                              pars.pbs_base_log(),
                                                   pars.pbs_level(),
                                                            pars.ks_base_log(),
                                                                 pars.ks_level(),
        );
        let filename = format!("{}/parm__tfhe_rs_v0_2-keys__{}", KEYS_PATH, suffix);

        filename
    }
}



// =============================================================================
//
//  Public Keys
//

pub struct PubKeySet<'a> {
    pub server_key: &'a ServerKey,
}
