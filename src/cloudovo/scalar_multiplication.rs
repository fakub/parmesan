use std::error::Error;

#[cfg(not(feature = "sequential"))]
use rayon::prelude::*;
#[allow(unused_imports)]
use colored::Colorize;

use crate::params::Params;
use crate::ciphertexts::ParmCiphertext;
use crate::userovo::keys::PubKeySet;
use super::pbs;
use super::addition;

/// Implementation of signum via parallel reduction
pub fn scalar_mul_impl(
    params: &Params,
    pub_keys: &PubKeySet,
    k: i32,
    x: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    //TODO double-and-add with subtraction if there is a block of ones
    Ok(Vec::new())
}
