use concrete::LWE;
use crate::params::Params;
use crate::userovo::keys::PrivKeySet;
use crate::ciphertexts::ParmCiphertext;

pub fn encrypt(
    params: &Params,
    priv_keys: &PrivKeySet,
    m: &i32,
) -> ParmCiphertext {
    let mut ctv: Vec<LWE> = Vec::new();

    for i in 0..4 {
        infoln!("Encrypting {}. element", i);
        ctv.push(LWE::encode_encrypt(&priv_keys.sk, 1.0, &priv_keys.encd_i).expect("LWE encryption failed."));
    }

    ParmCiphertext {
        ctv,
        maxlen: (m % 32) as usize,
    }
}

pub fn decrypt (
    params: &Params,
    priv_keys: &PrivKeySet,
    pc: &ParmCiphertext,
) -> i32 {
    let mut m = 0i32;

    for (i, ct) in pc.ctv.iter().enumerate() {
        let mf = ct.decrypt_decode(&priv_keys.sk).expect("LWE decryption failed.");
        infoln!("Decrypted {}. element: {}", i, mf);
        m += if mf.round() == 1. {1i32 << i} else {0i32};
    }

    m
    //~ decrypt_decode(&keys.sk)
}
