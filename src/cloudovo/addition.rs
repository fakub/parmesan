use concrete::LWE;
use colored::Colorize;
//~ use crate::params::Params;
use crate::ciphertexts::ParmCiphertext;
use crate::userovo::keys::PubKeySet;
use super::pbs;

pub fn add_impl(
    //~ params: &Params,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> ParmCiphertext {
    // run parallel addition algorithm
    let mut ctv: Vec<LWE> = Vec::new();

    measure_duration!(
        "Parallel addition",
        [
            for (i, ct) in x.ctv.iter().enumerate() {
                ctv.push(
                    if i & 1 != 0 {pbs::id(pub_keys, ct)} else {y.ctv[i].clone()}
                );
            }
        ]
    );

    ParmCiphertext {
        ctv,
        maxlen: 32,
    }
}
