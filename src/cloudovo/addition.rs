use concrete::LWE;
use crate::params::Params;
use crate::userovo::keys::PubKeySet;
use crate::ciphertexts::ParmCiphertext;

pub fn add_impl(
    params: &Params,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> ParmCiphertext {
    // run parallel addition algorithm
    let mut ctv: Vec<LWE> = Vec::new();

    ParmCiphertext {
        ctv,
        maxlen: 32,
    }
}
