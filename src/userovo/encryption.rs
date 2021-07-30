use concrete::LWE;
use crate::params::Params;
use crate::userovo::keys::PrivKeySet;
use crate::ciphertexts::ParmCiphertext;

pub fn encrypt(
    params: &Params,
    priv_keys: &PrivKeySet,
    m: i32,
    bits: usize,
) -> ParmCiphertext {
    //WISH some warning if bits is more than given type (-1 for signed)
    let mut ctv: Vec<LWE> = Vec::new();
    let m_pos = m >= 0;
    let m_abs = if m >= 0 {m} else {-m};

    for i in 0..bits {
        infoln!("Encrypting {}. bit", i);
        let m_bit = if m_pos {
            (m_abs >> i) & 1
        } else {
            if ((m_abs >> i) & 1) != 0 {(1 << params.bit_precision) - 1} else {0i32}
        };
        ctv.push(
            LWE::encode_encrypt(
                &priv_keys.sk,
                m_bit as f64,
                &priv_keys.encd_i,
            ).expect("LWE encryption failed.")
        );
    }

    ParmCiphertext {
        ctv,
        maxlen: 32,
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
        let mi = mf.round() as i32;
        let minus_one = 1i32 << (params.bit_precision) - 1;
        m += match mi {
            1 => {1i32 << i},
            0 => {0i32},
            minus_one => {-(1i32 << i)},
            _ => {0i32},   //WISH fail
        };
    }

    m
    //~ decrypt_decode(&keys.sk)
}
