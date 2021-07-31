use concrete::LWE;
use colored::Colorize;
use crate::params::Params;
use crate::userovo::keys::PrivKeySet;
use crate::ciphertexts::ParmCiphertext;



// =============================================================================
//
//  Encryption
//

/// Parmesan encryption
/// * splits signed integer into nibbles (bits)
/// * encrypt one-by-one
pub fn parm_encrypt(
    params: &Params,
    priv_keys: &PrivKeySet,
    m: i32,
    bits: usize,
) -> ParmCiphertext {
    //WISH some warning if bits is more than given type (-1 for signed)
    let mut ctv: Vec<LWE> = Vec::new();
    let m_abs = m.abs();
    let m_pos = m >= 0;

    for i in 0..bits {
        // calculate i-th bit with sign
        let mi = if ((m_abs >> i) & 1) == 0 {
            0i32
        } else {
            if m_pos {1i32} else {-1i32}
        };
        ctv.push(parm_encr_nibble(params, priv_keys, mi));
    }

    ParmCiphertext {
        ctv,
        maxlen: 32,
    }
}

fn parm_encr_nibble(
    params: &Params,
    priv_keys: &PrivKeySet,
    mut mi: i32,
) -> LWE {
    // little hack, how to bring mi into positive interval [0,2^pi)
    mi &= params.plaintext_mask();

    LWE::encrypt_uint(
        &priv_keys.sk,
        mi as u32,
        &priv_keys.encoder,
    ).expect("LWE encryption failed.")
}



// =============================================================================
//
//  Decryption
//

/// Parmesan decryption
/// * composes signed integer from multiple encrypted nibbles (bits)
/// * considers symmetric alphabet around zero
pub fn parm_decrypt(
    params: &Params,
    priv_keys: &PrivKeySet,
    pc: &ParmCiphertext,
) -> i32 {
    let mut m = 0i32;

    measure_duration!(
        "Decrypt",
        [
            for (i, ct) in pc.ctv.iter().enumerate() {
                let mi = parm_decr_nibble(params, priv_keys, ct);
                infoln!("m[{}] = {} (pi = {})", i, mi, ct.encoder.nb_bit_precision);
                m += match mi {
                     1 => {1i32 << i},
                     0 => {0i32},
                    -1 => {-(1i32 << i)},
                    _  => {0i32},   //WISH fail
                };
            }
        ]
    );

    m
}

fn parm_decr_nibble(
    params: &Params,
    priv_keys: &PrivKeySet,
    ct: &LWE,
) -> i32 {
    let mi = ct.decrypt_uint(&priv_keys.sk)
               .expect("LWE decryption failed.") as i32;   // rounding included in Encoder
    if mi >= params.plaintext_pos_max() {mi - params.plaintext_space_size()} else {mi}
}
