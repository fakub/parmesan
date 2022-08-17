use std::error::Error;
//~ use std::option::*;

#[allow(unused_imports)]
use colored::Colorize;

use crate::params::Params;
use crate::userovo::keys::PrivKeySet;
use crate::ciphertexts::{ParmCiphertext,ParmCiphertextImpl,ParmEncrWord};

pub const PARM_CT_MAXLEN: usize = 63;



// =============================================================================
//
//  Encryption
//

/// Parmesan encryption of a 64-bit signed integer
/// * splits signed integer into words
/// * encrypts one-by-one
pub fn parm_encrypt(
    params: &Params,
    priv_keys: &PrivKeySet,
    m: i64,
    words: usize,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    let mv = convert_to_vec(m, words);
    parm_encrypt_from_vec(params, priv_keys, &mv)
}

/// Parmesan encryption of a vector of words from alphabet `{-1,0,1}`
pub fn parm_encrypt_from_vec(
    params: &Params,
    priv_keys: &PrivKeySet,
    mv: &Vec<i32>,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    let mut c = ParmCiphertext::empty();
    for mi in mv {

        // check that mi is in alphabet
        if *mi < -1 || *mi > 1 {
            return Err(format!("{}", "Word to be encrypted outside the alphabet {-1,0,1}.").into());
        }

        c.push(ParmEncrWord::encrypt_word(params, Some(priv_keys), *mi)?);
    }
    Ok(c)
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
    c: &ParmCiphertext,
) -> Result<i64, Box<dyn Error>> {
    let mv = parm_decrypt_to_vec(params, priv_keys, c)?;
    convert_from_vec(&mv)
}

/// Parmesan encryption of a vector of words from alphabet `{-1,0,1}`
pub fn parm_decrypt_to_vec(
    params: &Params,
    priv_keys: &PrivKeySet,
    c: &ParmCiphertext,
) -> Result<Vec<i32>, Box<dyn Error>> {
    let mut mv: Vec<i32> = Vec::new();
    for ci in c {
        let mi_pos = ci.decrypt_word_pos(params, Some(priv_keys))?;
        // wrap upper half to negative
        mv.push(if mi_pos >= params.plaintext_pos_max() {mi_pos as i32 - params.plaintext_space_size()} else {mi_pos as i32});
    }
    Ok(mv)
}



// =============================================================================
//
//  Conversion, Hamming Weight, ...
//

/// Conversion to signed binary
pub fn convert_to_vec(
    m: i64,
    words: usize,
) -> Vec<i32> {
    let mut mv: Vec<i32> = Vec::new();
    let m_abs = m.abs();
    let m_pos = m >= 0;

    for i in 0..words {
        // calculate i-th word with sign
        let mi = if ((m_abs >> i) & 1) == 0 {
            0i32
        } else {
            if m_pos {1i32} else {-1i32}
        };
        mv.push(mi);
    }

    mv
}

/// Conversion from signed binary
pub fn convert_from_vec(mv: &Vec<i32>) -> Result<i64, Box<dyn Error>> {
    if mv.len() > PARM_CT_MAXLEN {return Err(format!("ParmCiphertext longer than {}.", PARM_CT_MAXLEN).into());}
    let mut m = 0i64;
    for (i, mi) in mv.iter().enumerate() {
        m += match mi {
             1 =>   1i64 << i,
             0 =>   0i64,
            -1 => -(1i64 << i),
             _ => return Err(format!("Word m_[{}] out of redundant bin alphabet: {}.", i, mi).into()),
        };
    }
    Ok(m)
}

/// Hamming Weight of (expected) binary vector
pub fn bin_hw(v: &Vec<i32>) -> Result<usize, Box<dyn Error>> {
    let mut hw = 0;
    for vi in v {
        if vi.abs() > 1 {return Err("Element in abs > 1 for binary HW!".into());}
        hw += vi.abs() as usize;
    }
    Ok(hw)
}

/// Bit length of 32-bit unsigned integer
#[inline]
pub fn bit_len_32(k: u32) -> usize {
    // no 1 in binary
    if k == 0 {return 0;}
    let mut k_len = 1;
    for i in 1..=31 {if k & (1 << i) != 0 {k_len = i + 1;}}
    k_len
}

/// Bit length of 64-bit unsigned integer
#[inline]
pub fn bit_len_64(k: u64) -> usize {
    // no 1 in binary
    if k == 0 {return 0;}
    let mut k_len = 1;
    for i in 1..=63 {if k & (1 << i) != 0 {k_len = i + 1;}}
    k_len
}
