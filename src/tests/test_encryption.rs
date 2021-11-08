use std::error::Error;

use rand::Rng;
use concrete::LWE;

use crate::tests::{self,*};
use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};
use crate::userovo::{encryption,keys::PrivKeySet};


// -----------------------------------------------------------------------------
//  Test Cases

#[test]
/// Decryption of trivial sample (no encryption of zero).
fn decrypt_triv() {
    // trivial ciphertext of length PLAIN_BITLEN_TESTS
    let c = ParmCiphertext::triv(PLAIN_BITLEN_TESTS).expect("ParmCiphertext::triv failed.");
    // decryption
    let m = encryption::parm_decrypt(
        tests::PARAMS,
        &tests::PRIV_KEYS,
        &c,
    ).expect("parm_decrypt failed.");

    assert_eq!(m, 0);
}

#[test]
/// Encryption & decryption of random integers.
fn encrypt_decrypt_int() {
    let mut rng = rand::thread_rng();

    for _ in 0..REPEAT_ENCR_TESTS {
        // generate random integer
        let mi: i64 = rng.gen_range(-((1i64 << PLAIN_BITLEN_TESTS) - 1)..(1i64 << PLAIN_BITLEN_TESTS));

        // encrypt & decrypt
        let c = encryption::parm_encrypt(
            tests::PARAMS,
            &tests::PRIV_KEYS,
            mi,
            PLAIN_BITLEN_TESTS,
        ).expect("parm_encrypt_vec failed.");
        let mp = encryption::parm_decrypt(
            tests::PARAMS,
            &tests::PRIV_KEYS,
            &c,
        ).expect("parm_decrypt failed.");

        assert_eq!(mp, mi);
    }
}

#[test]
/// Encryption & decryption of random vectors of {-1,0,1}.
fn encrypt_decrypt_vec() {
    let mut rng = rand::thread_rng();

    for _ in 0..REPEAT_ENCR_TESTS {
        // generate random vector
        let mut m_vec: Vec<i32>  = Vec::new();
        for _ in 0..PLAIN_BITLEN_TESTS {
            m_vec.push(rng.gen_range(-1..2));
        }

        // encrypt & decrypt
        let c = encryption::parm_encrypt_vec(
            tests::PARAMS,
            &tests::PRIV_KEYS,
            &m_vec,
        ).expect("parm_encrypt_vec failed.");
        let mp = encryption::parm_decrypt(
            tests::PARAMS,
            &tests::PRIV_KEYS,
            &c,
        ).expect("parm_decrypt failed.");

        // decode for reference
        let md = encryption::convert(&m_vec).expect("convert failed.");

        assert_eq!(mp, md);
    }
}

#[test]
/// Decryption of vectors of encrypted {-1,0,1}.
fn decrypt_non_triv() {
    test_decrypt_with_mode(EncrTrivWords::ENCR);
}

#[test]
/// Decryption of vectors of "encrypted" {-1,0,1} -- trivial samples only.
fn decrypt_all_triv() {
    test_decrypt_with_mode(EncrTrivWords::TRIV);
}

#[test]
/// Decryption of vectors of encrypted {-1,0,1} with trivial samples at random positions.
fn decrypt_some_triv() {
    test_decrypt_with_mode(EncrTrivWords::ENCRTRIV);
}


// -----------------------------------------------------------------------------
//  Auxilliary Functions

/// Implementation for three variants of vector to be decrypted.
fn test_decrypt_with_mode(mode: EncrTrivWords) {
    let mut rng = rand::thread_rng();

    for _ in 0..REPEAT_ENCR_TESTS {
        // generate random vectors: values and encryption flags (DO or DO NOT encrypt)
        let mut m_vec: Vec<i32>  = Vec::new();
        let mut m_flg: Vec<bool> = Vec::new();
        for _ in 0..PLAIN_BITLEN_TESTS {
            m_vec.push(rng.gen_range(-1..2));
            match mode {
                EncrTrivWords::ENCR => m_flg.push(true),
                EncrTrivWords::TRIV => m_flg.push(false),
                EncrTrivWords::ENCRTRIV => m_flg.push(rand::random()),
            }
        }

        // encrypt & decrypt
        let c = encrypt_custom(
            tests::PARAMS,
            &tests::PRIV_KEYS,
            &m_vec,
            &m_flg,
        ).expect("encrypt_custom failed.");
        let mp = encryption::parm_decrypt(
            tests::PARAMS,
            &tests::PRIV_KEYS,
            &c,
        ).expect("parm_decrypt failed.");

        // decode for reference
        let md = encryption::convert(&m_vec).expect("convert failed.");

        assert_eq!(mp, md);
    }
}

/// Encrypt input vector `m_vec` at positions given by `m_flags` vector (other samples trivial).
pub fn encrypt_custom(
    par: &Params,
    priv_keys: &PrivKeySet,
    m_vec: &Vec<i32>,
    m_flags: &Vec<bool>,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    let mut res = ParmCiphertext::triv(m_vec.len())?;

    res.iter_mut().zip(m_vec.iter().zip(m_flags.iter())).for_each(| (ri, (mi, fi)) | {
        let mi_pos = (mi & par.plaintext_mask()) as u32;
        *ri = if *fi {
            LWE::encrypt_uint(&priv_keys.sk, mi_pos, &priv_keys.encoder).expect("LWE::encrypt_uint failed.")
        } else {
            LWE::encrypt_uint_triv(mi_pos, &priv_keys.encoder).expect("LWE::encrypt_uint_triv failed.")
        };
    });

    Ok(res)
}
