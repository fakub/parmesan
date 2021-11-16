#[macro_use]
extern crate lazy_static;

use rand::Rng;

use parmesan::userovo::encryption;
use parmesan::arithmetics::ParmArithmetics;
use parmesan::ciphertexts::{ParmCiphertext, ParmCiphertextExt};

#[allow(dead_code)]
mod common;
use common::*;


// -----------------------------------------------------------------------------
//  Test Cases

#[test]
/// Maximum of encrypted sub-samples only, aligned lengths.
fn t_max_non_triv_aligned() {
    println!("Non-Triv Aligned ...");
    t_impl_max_with_mode(EncrVsTriv::ENCR, true);
}

#[test]
/// Maximum of encrypted sub-samples only, different lengths.
fn t_max_non_triv_difflen() {
    println!("Non-Triv Misaligned ...");
    t_impl_max_with_mode(EncrVsTriv::ENCR, false);
}

#[test]
/// Maximum of trivial sub-samples only, aligned lengths.
fn t_max_all_triv_aligned() {
    println!("All-Triv Aligned ...");
    t_impl_max_with_mode(EncrVsTriv::TRIV, true);
}

#[test]
/// Maximum of trivial sub-samples only, different lengths.
fn t_max_all_triv_difflen() {
    println!("All-Triv Misaligned ...");
    t_impl_max_with_mode(EncrVsTriv::TRIV, false);
}

#[test]
/// Maximum of mixed sub-samples, aligned lengths.
fn t_max_some_triv_aligned() {
    println!("Mixed Aligned ...");
    t_impl_max_with_mode(EncrVsTriv::ENCRTRIV, true);
}

#[test]
/// Maximum of mixed sub-samples, different lengths.
fn t_max_some_triv_difflen() {
    println!("Mixed Misaligned ...");
    t_impl_max_with_mode(EncrVsTriv::ENCRTRIV, false);
}

// Special

#[test]
/// Maximum of two empty samples
fn t_max_both_empty() {
    println!("Both Empty ...");

    // encrypt -> homomorphic eval -> decrypt (in plain: 0)
    let c1 = ParmCiphertext::empty();
    let c2 = ParmCiphertext::empty();
    let c_he = ParmArithmetics::max(&common::TEST_PC, &c1, &c2);
    let m_he = common::TEST_PU.decrypt(&c_he).expect("ParmesanUserovo::decrypt failed.");
    let m_pl = 0;

    println!("  max = {} (exp. {})", m_he, m_pl);

    // compare results
    assert_eq!(m_he, m_pl);
}

#[test]
/// Maximum of empty and non-empty sample
fn t_max_empty_nonempty() {
    println!("Empty & Non-Empty Mixed ...");

    // generate random vector(s)
    let m1_vec: Vec<i32>  = Vec::new();
    let m2_vec = gen_rand_vec(common::TESTS_BITLEN_MAX);
    // convert to integer(s)
    let m1 = encryption::convert(&m1_vec).expect("convert failed.");
    let m2 = encryption::convert(&m2_vec).expect("convert failed.");

    println!("  m1 = {} ({}-bit: {:?})\n  m2 = {} ({}-bit: {:?})", m1, 0, m1_vec, m2, common::TESTS_BITLEN_MAX, m2_vec);

    // encrypt -> homomorphic eval -> decrypt
    let c1 = encrypt_with_mode(&m1_vec, EncrVsTriv::ENCRTRIV);
    let c2 = encrypt_with_mode(&m2_vec, EncrVsTriv::ENCRTRIV);

    let c_he = ParmArithmetics::max(&common::TEST_PC, &c1, &c2);

    let m_he = common::TEST_PU.decrypt(&c_he).expect("ParmesanUserovo::decrypt failed.");

    // plain eval
    let m_pl = ParmArithmetics::max(&common::TEST_PC, &m1, &m2);

    println!("  max = {} (exp. {})", m_he, m_pl);

    // compare results
    assert_eq!(m_he, m_pl);
}


// -----------------------------------------------------------------------------
//  Test Implementations

/// Implementation for three variants of vector to be evaluated.
fn t_impl_max_with_mode(
    mode: EncrVsTriv,
    aligned: bool,
) {
    // for mis-aligned length generation
    let mut rng = rand::thread_rng();

    for _ in 0..common::TESTS_REPEAT_MAX {
        // generate random vector(s)
        let bl1 = if aligned {common::TESTS_BITLEN_MAX} else {rng.gen_range(0..=common::TESTS_BITLEN_MAX)};
        let bl2 = if aligned {common::TESTS_BITLEN_MAX} else {rng.gen_range(0..=common::TESTS_BITLEN_MAX)};
        let m1_vec = gen_rand_vec(bl1);
        let m2_vec = gen_rand_vec(bl2);
        // convert to integer(s)
        let m1 = encryption::convert(&m1_vec).expect("convert failed.");
        let m2 = encryption::convert(&m2_vec).expect("convert failed.");

        println!("  m1 = {} ({}-bit: {:?})\n  m2 = {} ({}-bit: {:?})", m1, bl1, m1_vec, m2, bl2, m2_vec);

        // encrypt -> homomorphic eval -> decrypt
        let c1 = encrypt_with_mode(&m1_vec, mode);
        let c2 = encrypt_with_mode(&m2_vec, mode);

        let c_he = ParmArithmetics::max(&common::TEST_PC, &c1, &c2);

        let m_he = common::TEST_PU.decrypt(&c_he).expect("ParmesanUserovo::decrypt failed.");

        // plain eval
        let m_pl = ParmArithmetics::max(&common::TEST_PC, &m1, &m2);

        println!("  max = {} (exp. {})", m_he, m_pl);

        // compare results
        assert_eq!(m_he, m_pl);
    }
}
