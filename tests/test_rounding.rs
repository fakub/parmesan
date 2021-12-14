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
/// Rounding of encrypted sub-samples only.
fn t_round_non_triv() {
    println!("Non-Triv ...");
    t_impl_round_with_mode(EncrVsTriv::ENCR);
}

#[test]
/// Rounding of trivial sub-samples only.
fn t_round_all_triv() {
    println!("All-Triv ...");
    t_impl_round_with_mode(EncrVsTriv::TRIV);
}

#[test]
/// Rounding of mixed sub-samples.
fn t_round_some_triv() {
    println!("Mixed ...");
    t_impl_round_with_mode(EncrVsTriv::ENCRTRIV);
}

// Special

#[test]
/// Rounding of empty sample
fn t_round_empty() {
    println!("Empty ...");

    // encrypt -> homomorphic eval -> decrypt (in plain: 0)
    let c1 = ParmCiphertext::empty();
    let c_he = ParmArithmetics::round_at(&common::TEST_PC, &c1, 0);
    let m_he = common::TEST_PU.decrypt(&c_he).expect("ParmesanUserovo::decrypt failed.");
    let m_pl = 0;

    println!("round = {} (exp. {})", m_he, m_pl);

    // compare results
    assert_eq!(m_he, m_pl);
}

//TODO identify other special cases?


// -----------------------------------------------------------------------------
//  Test Implementations

/// Implementation for three variants of vector to be evaluated.
fn t_impl_round_with_mode(mode: EncrVsTriv) {
    // for random position generation
    let mut rng = rand::thread_rng();

    for _ in 0..common::TESTS_REPEAT_ROUND {
        // generate random vector(s)
        let m1_vec = gen_rand_vec(common::TESTS_BITLEN_ROUND);
        // convert to integer(s)
        let m1 = encryption::convert(&m1_vec).expect("convert failed.");
        // generate random position
        let pos: usize = rng.gen_range(0..=TESTS_POS_ROUND);

        println!("  m1 = {} ({}-bit: {:?})", m1, common::TESTS_BITLEN_ROUND, m1_vec);

        // encrypt -> homomorphic eval -> decrypt
        let c1 = encrypt_with_mode(&m1_vec, mode);
        let c_he = ParmArithmetics::round_at(&common::TEST_PC, &c1, pos);
        let m_he = common::TEST_PU.decrypt(&c_he).expect("ParmesanUserovo::decrypt failed.");

        // plain eval
        let m_pl = ParmArithmetics::round_at(&common::TEST_PC, &m1, pos);

        println!("round = {} (exp. {})", m_he, m_pl);

        // compare results
        assert_eq!(m_he, m_pl);
    }
}
