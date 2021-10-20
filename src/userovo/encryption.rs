use std::error::Error;

#[allow(unused_imports)]
use colored::Colorize;

use concrete::LWE;

use crate::params::Params;
use crate::userovo::keys::PrivKeySet;
use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};



// =============================================================================
//
//  Encryption
//

/// Parmesan encryption of a 64-bit signed integer
/// * splits signed integer into words
/// * encrypt one-by-one
pub fn parm_encrypt(
    params: &Params,
    priv_keys: &PrivKeySet,
    m: i64,
    words: usize,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    let mut res = ParmCiphertext::empty();
    let m_abs = m.abs();
    let m_pos = m >= 0;

    for i in 0..words {
        // calculate i-th word with sign
        let mi = if ((m_abs >> i) & 1) == 0 {
            0i32
        } else {
            if m_pos {1i32} else {-1i32}
        };
        res.push(parm_encr_word(params, priv_keys, mi)?);
    }

    Ok(res)
}

/// Parmesan encryption of a vector of words from alphabet `{-1,0,1}`
pub fn parm_encrypt_vec(
    params: &Params,
    priv_keys: &PrivKeySet,
    mv: &Vec<i32>,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    let mut res = ParmCiphertext::triv(mv.len())?;

    res.iter_mut().zip(mv.iter()).for_each(| (ri, mi) | {
        *ri = parm_encr_word(params, priv_keys, *mi).expect("parm_encr_word failed.");
    });

    Ok(res)
}

fn parm_encr_word(
    params: &Params,
    priv_keys: &PrivKeySet,
    mut mi: i32,
) -> Result<LWE, Box<dyn Error>> {

    // check that mi is in alphabet
    if mi < -1 || mi > 1 {
        #[allow(non_fmt_panics)]
        panic!("Word to be encrypted outside alphabet {{-1,0,1}}.");
    }

    // little hack, how to bring mi into positive interval [0, 2^pi)
    mi &= params.plaintext_mask();

    Ok(LWE::encrypt_uint(
        &priv_keys.sk,
        mi as u32,
        &priv_keys.encoder,
    )?)
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
) -> Result<i64, Box<dyn Error>> {
    let mut m = 0i64;

    for (i, ct) in pc.iter().enumerate() {
        let mi = parm_decr_word(params, priv_keys, ct)?;
        // infoln!("m[{}] = {} (pi = {})", i, mi, ct.encoder.nb_bit_precision);
        // if i >= 63 {dbgln!("i >= 63 !! namely {}", i);}
        m += match mi {
             1 => {  1i64 << i},
             0 => {  0i64},
            -1 => {-(1i64 << i)},
             _ => {panic!("Word m_[{}] out of redundant bin alphabet: {}.", i, mi)},
        };
    }

    Ok(m)
}

fn parm_decr_word(
    params: &Params,
    priv_keys: &PrivKeySet,
    ct: &LWE,
) -> Result<i32, Box<dyn Error>> {
    let mi = ct.decrypt_uint(&priv_keys.sk)? as i32;   // rounding included in Encoder
    if mi >= params.plaintext_pos_max() {Ok(mi - params.plaintext_space_size())} else {Ok(mi)}
}



// =============================================================================
//
//  Conversion
//

/// Conversion from redundant
pub fn convert(mv: &Vec<i32>) -> Result<i64, Box<dyn Error>> {
    let mut m = 0i64;
    for (i, mi) in mv.iter().enumerate() {
        m += match mi {
             1 => {  1i64 << i},
             0 => {  0i64},
            -1 => {-(1i64 << i)},
             _ => {panic!("Word m_[{}] out of redundant bin alphabet: {}.", i, mi)},
        };
    }
    Ok(m)
}
