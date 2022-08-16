use std::error::Error;

// parallelization tools
use rayon::prelude::*;

#[allow(unused_imports)]
use colored::Colorize;

use concrete_core::prelude::*;

use crate::params::Params;
use crate::userovo::keys::PrivKeySet;
use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};

pub const PARM_CT_MAXLEN: usize = 63;



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
    let mut res = ParmCiphertext::triv(mv.len(), &priv_keys.encoder)?;

    res.iter_mut().zip(mv.iter()).for_each(| (ri, mi) | {
        *ri = parm_encr_word(params, priv_keys, *mi).expect("parm_encr_word failed.");
    });

    Ok(res)
}

fn parm_encr_word(
    params: &Params,
    priv_keys: &PrivKeySet,
    mut mi: i32,
) -> Result<LweCiphertext64, Box<dyn Error>> {

    // check that mi is in alphabet
    if mi < -1 || mi > 1 {
        return Err(format!("{}", "Word to be encrypted outside the alphabet {-1,0,1}.").into());
    }

    // little hack, how to bring mi into positive interval [0, 2^pi)
    mi &= params.plaintext_mask();

    Ok(
        //FIXME
        //~ engine.encrypt_lwe_ciphertext(&lwe_secret_key, &pi, var_lwe)?
        encrypt_uint(
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
    ct: &ParmCiphertext,
) -> Result<i64, Box<dyn Error>> {
    // init plain vector
    let mut pt: Vec<i32> = vec![0; ct.len()];
    // decrypt ct into pt (in parallel)
    ct.par_iter().zip(pt.par_iter_mut()).for_each(| (cti, pti) | {
        *pti = parm_decr_word(params, priv_keys, cti).expect("parm_decr_word failed.");
    });
    // convert vec to i64
    convert(&pt)
}

fn parm_decr_word(
    params: &Params,
    priv_keys: &PrivKeySet,
    ct: &LWE,
) -> Result<i32, Box<dyn Error>> {
    //FIXME
    //~ engine.decrypt_lwe_ciphertext(&lwe_secret_key, &ci)?
    let mi = ct.decrypt_uint(&priv_keys.sk)? as i32;   // rounding included in Encoder
    if mi >= params.plaintext_pos_max() {Ok(mi - params.plaintext_space_size())} else {Ok(mi)}
}



// =============================================================================
//
//  Conversion, Hamming Weight, ...
//

/// Conversion from redundant
pub fn convert(mv: &Vec<i32>) -> Result<i64, Box<dyn Error>> {
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
