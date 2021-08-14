use std::error::Error;

use concrete::LWE;
#[allow(unused_imports)]
use colored::Colorize;
#[allow(unused_imports)]
use rayon::prelude::*;
use crate::params::Params;
use crate::userovo::keys::{PrivKeySet, PubKeySet};
use crate::ciphertexts::ParmCiphertext;



// =============================================================================
//
//  Encryption
//

/// Parmesan encryption of a 64-bit signed integer
/// * splits signed integer into bits
/// * encrypt one-by-one
pub fn parm_encrypt<'a>(
    params: &'a Params,
    priv_keys: &'a PrivKeySet,
    pub_keys: &'a PubKeySet,
    m: i64,
    bits: usize,
) -> Result<ParmCiphertext<'a>, Box<dyn Error>> {
    let mut res = ParmCiphertext::triv(params, pub_keys, 0)?;
    let m_abs = m.abs();
    let m_pos = m >= 0;

    for i in 0..bits {
        // calculate i-th bit with sign
        let mi = if ((m_abs >> i) & 1) == 0 {
            0i32
        } else {
            if m_pos {1i32} else {-1i32}
        };
        res.c.push(parm_encr_word(params, priv_keys, mi)?);
    }

    Ok(res)
}

/// Parmesan encryption of a vector of words from alphabet `{-1,0,1}`
pub fn parm_encrypt_vec<'a>(
    params: &'a Params,
    priv_keys: &'a PrivKeySet,
    pub_keys: &'a PubKeySet,
    mv: &Vec<i32>,
) -> Result<ParmCiphertext<'a>, Box<dyn Error>> {
    let mut res = ParmCiphertext::triv(params, pub_keys, 0)?;

    for mi in mv {
        res.c.push(parm_encr_word(params, priv_keys, *mi)?);
    }

    Ok(res)
}

fn parm_encr_word(
    params: &Params,
    priv_keys: &PrivKeySet,
    mut mi: i32,
) -> Result<LWE, Box<dyn Error>> {

    // check that mi is in alphabet
    if mi < -1 || mi > 1 {
        return Err("Word to be encrypted outside alphabet {-1,0,1}.".into());
    }

    // little hack, how to bring mi into positive interval [0,2^pi)
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

    //~ measure_duration!(
        //~ ["Decrypt"],
        //~ [
            for (i, ct) in pc.c.iter().enumerate() {
                let mi = parm_decr_word(params, priv_keys, ct)?;
                //~ infoln!("m[{}] = {} (pi = {})", i, mi, ct.encoder.nb_bit_precision);
                m += match mi {
                     1 => {  1i64 << i},
                     0 => {  0i64},
                    -1 => {-(1i64 << i)},
                     _ => {return Err(format!("Word m_[{}] out of alphabet: {}.", i, mi).into())},
                };
            }
        //~ ]
    //~ );

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
             _ => {return Err(format!("Word out of alphabet: {}.", mi).into())},
        };
    }
    Ok(m)
}
