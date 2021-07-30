use crate::params::Params;
use crate::userovo::keys::PrivKeySet;
use crate::ciphertexts::ParmCiphertext;

pub fn encrypt(
    params: &Params,
    priv_keys: &PrivKeySet,
    m: &i32,
) -> ParmCiphertext {
    //~ LWE::encode_encrypt(&priv_keys.sk, m, &priv_keys.encd_i)?;
    ParmCiphertext {
        maxlen: (m % 32) as usize,
    }
}

pub fn decrypt (
    params: &Params,
    priv_keys: &PrivKeySet,
    c: &ParmCiphertext,
) -> i32 {
    42
}
