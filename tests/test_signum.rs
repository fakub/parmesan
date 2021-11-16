#[macro_use]
extern crate lazy_static;

use parmesan::userovo::encryption;
use parmesan::arithmetics::ParmArithmetics;
use parmesan::ciphertexts::{ParmCiphertext, ParmCiphertextExt};

#[allow(dead_code)]
mod common;
use common::*;


// -----------------------------------------------------------------------------
//  Test Cases

#[test]
/// Signum of encrypted sub-samples only.
fn t_sgn_non_triv() {
    println!("Non-Triv ...");
    t_impl_sgn_with_mode(EncrVsTriv::ENCR);
}

#[test]
/// Signum of trivial sub-samples only.
fn t_sgn_all_triv() {
    println!("All-Triv ...");
    t_impl_sgn_with_mode(EncrVsTriv::TRIV);
}

#[test]
/// Signum of mixed sub-samples.
fn t_sgn_some_triv() {
    println!("Mixed ...");
    t_impl_sgn_with_mode(EncrVsTriv::ENCRTRIV);
}

// Special

#[test]
/// Signum of empty sample
fn t_sgn_empty() {
    println!("Empty ...");

    // encrypt -> homomorphic eval -> decrypt (in plain: 0)
    let c1 = ParmCiphertext::empty();
    let c_he = ParmArithmetics::sgn(&common::TEST_PC, &c1);
    let m_he = common::TEST_PU.decrypt(&c_he).expect("ParmesanUserovo::decrypt failed.");
    let m_pl = 0;

    println!("  sgn = {} (exp. {})", m_he, m_pl);

    // compare results
    assert_eq!(m_he, m_pl);
}


// -----------------------------------------------------------------------------
//  Test Implementations

/// Implementation for three variants of vector to be evaluated.
fn t_impl_sgn_with_mode(mode: EncrVsTriv) {
    for _ in 0..common::TESTS_REPEAT_SGN {
        // generate random vector(s)
        let m1_vec = gen_rand_vec(common::TESTS_BITLEN_SGN);
        // convert to integer(s)
        let m1 = encryption::convert(&m1_vec).expect("convert failed.");

        println!("  m1 = {} ({}-bit: {:?})", m1, common::TESTS_BITLEN_SGN, m1_vec);

        // encrypt -> homomorphic eval -> decrypt
        let c1 = encrypt_with_mode(&m1_vec, mode);
        let c_he = ParmArithmetics::sgn(&common::TEST_PC, &c1);
        let m_he = common::TEST_PU.decrypt(&c_he).expect("ParmesanUserovo::decrypt failed.");

        // plain eval
        let m_pl = ParmArithmetics::sgn(&common::TEST_PC, &m1);

        println!("  sgn = {} (exp. {})", m_he, m_pl);

        // compare results
        assert_eq!(m_he, m_pl);
    }
}
