use concrete::LWE;
use colored::Colorize;
use crate::params::Params;
use crate::ciphertexts::ParmCiphertext;
use crate::userovo::keys::PubKeySet;
use super::pbs;

pub fn add_impl(
    params: &Params,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> ParmCiphertext {
    // run parallel addition algorithm
    let mut ctv: Vec<LWE> = Vec::new();

    measure_duration!(
        "Parallel addition",
        [
            for ct in &x.ctv {
                ctv.push(pbs::id(pub_keys, ct));
            }
        ]
    );

    ParmCiphertext {
        ctv,
        maxlen: 32,
    }
}
