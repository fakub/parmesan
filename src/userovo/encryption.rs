use std::error::Error;

use concrete::LWE;
#[allow(unused_imports)]
use colored::Colorize;
#[allow(unused_imports)]
use rayon::prelude::*;
use crate::params::Params;
use crate::userovo::keys::PrivKeySet;
use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};



// =============================================================================
//
//  Encryption
//

/// Parmesan encryption of a 64-bit signed integer
/// * splits signed integer into bits
/// * encrypt one-by-one
pub fn parm_encrypt(
    params: &Params,
    priv_keys: &PrivKeySet,
    m: i64,
    bits: usize,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    let mut res = ParmCiphertext::empty();
    let m_abs = m.abs();
    let m_pos = m >= 0;

    #[cfg(any(feature = "sc_A", feature = "sc_B"))]
    for i in 0..bits {
        if !m_pos {panic!("Negative numbers not supported in scenarios A, B.")}
        // calculate logical representation of i-th bit
        let mi = if ((m_abs >> i) & 1) == 0 {-1i32} else {1i32};
        res.push(parm_encr_word(params, priv_keys, mi)?);
    }
    #[cfg(any(feature = "sc_C"))]
    for i in 0..bits {
        if !m_pos {panic!("Negative numbers not supported in scenario C.")}
        // calculate i-th word (2 bits)
        let mi = (((m_abs >> (2*i)) & 0b11) * 2) as i32;
        res.push(parm_encr_word(params, priv_keys, mi)?);
    }
    #[cfg(any(feature = "sc_D", feature = "sc_E", feature = "sc_F"))]
    for i in 0..bits {
        // calculate i-th bit with sign
        let mi = if ((m_abs >> i) & 1) == 0 {
            0i32
        } else {
            if m_pos {1i32} else {-1i32}
        };
        res.push(parm_encr_word(params, priv_keys, mi)?);
    }
    #[cfg(any(feature = "sc_G", feature = "sc_H", feature = "sc_I"))]
    for i in 0..bits {
        // calculate i-th word with sign (n.b., this fails to parm_encr_word if there is a digit 3 .. out of alphabet)
        let mi = if m_pos {
            ((m_abs >> (2*i)) & 0b11) as i32
        } else {
            -((m_abs >> (2*i)) & 0b11) as i32
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

    res.par_iter_mut().zip(mv.par_iter()).for_each(| (ri, mi) | {
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
    #[cfg(any(feature = "sc_A", feature = "sc_B"))]
    if mi != -1 && mi != 1 {
        panic!("Word to be encrypted outside logical representation {{-1,1}}.");
    }
    #[cfg(feature = "sc_C")]
    if mi < 0 || mi > 6 || (mi & 1) != 0 {
        panic!("Word to be encrypted outside alphabet (2x) {{0,1,2,3}}.");
    }
    #[cfg(any(feature = "sc_D", feature = "sc_E", feature = "sc_F"))]
    if mi < -1 || mi > 1 {
        panic!("Word to be encrypted outside alphabet {{-1,0,1}}.");
    }
    #[cfg(any(feature = "sc_G", feature = "sc_H", feature = "sc_I"))]
    if mi < -2 || mi > 2 {
        panic!("Word to be encrypted outside alphabet {{-2,-1,0,1,2}}.");
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

        //  logical
        #[cfg(any(feature = "sc_A", feature = "sc_B"))]
        {
        m += match mi {
             1 => {  1i64 << i},
            -1 => {  0i64},
             _ => {panic!("Word m_[{}] out of logical representation: {}.", i, mi)},
        };
        }
        //  bin redundant
        #[cfg(any(feature = "sc_D", feature = "sc_E", feature = "sc_F"))]
        {
        m += match mi {
             1 => {  1i64 << i},
             0 => {  0i64},
            -1 => {-(1i64 << i)},
             _ => {panic!("Word m_[{}] out of redundant bin alphabet: {}.", i, mi)},
        };
        }
        //  quad standard
        #[cfg(feature = "sc_C")]
        {
        m += match mi {
             6 => {  3i64 << (2*i)},
             4 => {  2i64 << (2*i)},
             2 => {  1i64 << (2*i)},
             0 => {  0i64},
             _ => {panic!("Word m_[{}] out of standard quad alphabet: {}.", i, mi)},
        };
        }
        //  quad redundant
        #[cfg(any(feature = "sc_G", feature = "sc_H", feature = "sc_I"))]
        {
        m += match mi {
             2 => {  2i64 << (2*i)},
             1 => {  1i64 << (2*i)},
             0 => {  0i64},
            -1 => {-(1i64 << (2*i))},
            -2 => {-(2i64 << (2*i))},
             _ => {panic!("Word m_[{}] out of redundant quad alphabet: {}.", i, mi)},
        };
        }
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
        //  logical
        #[cfg(any(feature = "sc_A", feature = "sc_B"))]
        {
        m += match mi {
             1 => {  1i64 << i},
            -1 => {  0i64},
             _ => {panic!("Word m_[{}] out of logical representation: {}.", i, mi)},
        };
        }
        //  bin redundant
        #[cfg(any(feature = "sc_D", feature = "sc_E", feature = "sc_F"))]
        {
        m += match mi {
             1 => {  1i64 << i},
             0 => {  0i64},
            -1 => {-(1i64 << i)},
             _ => {panic!("Word m_[{}] out of redundant bin alphabet: {}.", i, mi)},
        };
        }
        //  quad standard
        #[cfg(feature = "sc_C")]
        {
        m += match mi {
             3 => {  3i64 << (2*i)},
             2 => {  2i64 << (2*i)},
             1 => {  1i64 << (2*i)},
             0 => {  0i64},
             _ => {panic!("Word m_[{}] out of standard quad alphabet: {}.", i, mi)},
        };
        }
        //  quad redundant
        #[cfg(any(feature = "sc_G", feature = "sc_H", feature = "sc_I"))]
        {
        m += match mi {
             2 => {  2i64 << (2*i)},
             1 => {  1i64 << (2*i)},
             0 => {  0i64},
            -1 => {-(1i64 << (2*i))},
            -2 => {-(2i64 << (2*i))},
             _ => {panic!("Word m_[{}] out of redundant quad alphabet: {}.", i, mi)},
        };
        }
    }

    Ok(m)
}
