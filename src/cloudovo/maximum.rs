use concrete::LWE;
#[allow(unused_imports)]
use colored::Colorize;
use crate::params::Params;
use crate::ciphertexts::ParmCiphertext;
use crate::userovo::keys::PubKeySet;
use super::pbs;

/// Implementation of parallel maximum using signum
pub fn max_impl(
    params: &Params,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
) -> ParmCiphertext {
    // run parallel addition algorithm
    let mut z: ParmCiphertext = Vec::new();

    z
}
