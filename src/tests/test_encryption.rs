use rand::Rng;

use crate::tests::{self,*};
use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};
use crate::userovo::encryption;


// -----------------------------------------------------------------------------
//  Test Cases

#[test]
/// Decryption of trivial sample (no encryption of zero).
fn t_decrypt_triv() {
    // trivial ciphertext of length TESTS_PLAIN_BITLEN_FULL
    let c = ParmCiphertext::triv(TESTS_PLAIN_BITLEN_FULL).expect("ParmCiphertext::triv failed.");
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
fn t_encrypt_decrypt_int() {
    let mut rng = rand::thread_rng();

    for _ in 0..TESTS_REPEAT_ENCR {
        // generate random integer
        let mi: i64 = rng.gen_range(-((1i64 << TESTS_PLAIN_BITLEN_FULL) - 1)..(1i64 << TESTS_PLAIN_BITLEN_FULL));

        // encrypt & decrypt
        let c = encryption::parm_encrypt(
            tests::PARAMS,
            &tests::PRIV_KEYS,
            mi,
            TESTS_PLAIN_BITLEN_FULL,
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
fn t_encrypt_decrypt_vec() {
    for _ in 0..TESTS_REPEAT_ENCR {
        // generate random vector
        let m_vec = gen_rand_vec(TESTS_PLAIN_BITLEN_FULL);

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
/// Decryption of encrypted sub-samples only.
fn t_decrypt_non_triv() {
    t_impl_decr_with_mode(EncrVsTriv::ENCR);
}

#[test]
/// Decryption of trivial sub-samples only.
fn t_decrypt_all_triv() {
    t_impl_decr_with_mode(EncrVsTriv::TRIV);
}

#[test]
/// Decryption of mixed sub-samples.
fn t_decrypt_some_triv() {
    t_impl_decr_with_mode(EncrVsTriv::ENCRTRIV);
}


// -----------------------------------------------------------------------------
//  Test Implementations

/// Implementation for three variants of vector to be evaluated.
fn t_impl_decr_with_mode(mode: EncrVsTriv) {
    for _ in 0..TESTS_REPEAT_ENCR {
        // generate random vector(s)
        let m1_vec = gen_rand_vec(TESTS_PLAIN_BITLEN_FULL);
        // convert to integer(s)
        let m1 = encryption::convert(&m1_vec).expect("convert failed.");

        // encrypt -> homomorphic eval -> decrypt
        let c1 = encrypt_with_mode(&m1_vec, mode);
        // --- no evaluation ---
        let m_he = PU.decrypt(&c1).expect("ParmesanUserovo::decrypt failed.");

        // plain eval
        let m_pl = m1;

        // compare results
        assert_eq!(m_he, m_pl);
    }
}
