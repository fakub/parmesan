#[macro_use]
extern crate lazy_static;

use rand::Rng;

use parmesan::userovo::encryption;
use parmesan::arithmetics::ParmArithmetics;

#[allow(dead_code)]
mod common;
use common::*;


// -----------------------------------------------------------------------------
//  Test Cases

#[test]
/// Addition & Subtraction of encrypted sub-samples only, aligned lengths.
fn t_add_sub_non_triv_aligned() {
    println!("Non-Triv Aligned ...");
    t_impl_add_sub_with_mode(EncrVsTriv::ENCR, true);
}

#[test]
/// Addition & Subtraction of encrypted sub-samples only, different lengths.
fn t_add_sub_non_triv_difflen() {
    println!("Non-Triv Misaligned ...");
    t_impl_add_sub_with_mode(EncrVsTriv::ENCR, false);
}

#[test]
/// Addition & Subtraction of trivial sub-samples only, aligned lengths.
fn t_add_sub_all_triv_aligned() {
    println!("All-Triv Aligned ...");
    t_impl_add_sub_with_mode(EncrVsTriv::TRIV, true);
}

#[test]
/// Addition & Subtraction of trivial sub-samples only, different lengths.
fn t_add_sub_all_triv_difflen() {
    println!("All-Triv Misaligned ...");
    t_impl_add_sub_with_mode(EncrVsTriv::TRIV, false);
}

#[test]
/// Addition & Subtraction of mixed sub-samples, aligned lengths.
fn t_add_sub_some_triv_aligned() {
    println!("Mixed Aligned ...");
    t_impl_add_sub_with_mode(EncrVsTriv::ENCRTRIV, true);
}

#[test]
/// Addition & Subtraction of mixed sub-samples, different lengths.
fn t_add_sub_some_triv_difflen() {
    println!("Mixed Misaligned ...");
    t_impl_add_sub_with_mode(EncrVsTriv::ENCRTRIV, false);
}


// -----------------------------------------------------------------------------
//  Test Implementations

/// Implementation for three variants of vector to be evaluated.
fn t_impl_add_sub_with_mode(
    mode: EncrVsTriv,
    aligned: bool,
) {
    // for mis-aligned length generation
    let mut rng = rand::thread_rng();

    // set up bit-lengths
    let mut range: Vec<_> = (0..=common::TESTS_BITLEN_ADD).collect();
    range.extend(common::TESTS_EXTRA_BITLEN_ADD);

    for bl in range {
        // generate random vector(s)
        let bl1 = if aligned {bl} else {rng.gen_range(0..=bl)};
        let bl2 = if aligned {bl} else {rng.gen_range(0..=bl)};
        let m1_vec = gen_rand_vec(bl1);
        let m2_vec = gen_rand_vec(bl2);
        // convert to integer(s)
        let m1 = encryption::convert_from_vec(&m1_vec).expect("convert failed.");
        let m2 = encryption::convert_from_vec(&m2_vec).expect("convert failed.");

        println!("  m1 = {} ({}-bit: {:?})\n  m2 = {} ({}-bit: {:?})", m1, bl1, m1_vec, m2, bl2, m2_vec);

        // encrypt -> homomorphic eval -> decrypt
        let c1 = encrypt_with_mode(&m1_vec, mode);
        let c2 = encrypt_with_mode(&m2_vec, mode);

        let c_he_a = ParmArithmetics::add(&common::TEST_PC, &c1, &c2);
        let c_he_s = ParmArithmetics::sub(&common::TEST_PC, &c1, &c2);

        let m_he_a = common::TEST_PU.decrypt(&c_he_a).expect("ParmesanUserovo::decrypt failed.");
        let m_he_s = common::TEST_PU.decrypt(&c_he_s).expect("ParmesanUserovo::decrypt failed.");
        // also decrypt into vec
        let m_he_a_vec = encryption::parm_decrypt_to_vec(common::TEST_PARAMS, &common::TEST_PRIV_KEYS, &c_he_a).expect("ParmesanUserovo::parm_decrypt_to_vec failed.");
        let m_he_s_vec = encryption::parm_decrypt_to_vec(common::TEST_PARAMS, &common::TEST_PRIV_KEYS, &c_he_s).expect("ParmesanUserovo::parm_decrypt_to_vec failed.");

        // plain eval
        let m_pl_a = ParmArithmetics::add(&common::TEST_PC, &m1, &m2);
        let m_pl_s = ParmArithmetics::sub(&common::TEST_PC, &m1, &m2);

        println!("  add = {} {:?} (exp. {})", m_he_a, m_he_a_vec, m_pl_a);
        println!("  sub = {} {:?} (exp. {})", m_he_s, m_he_s_vec, m_pl_s);

        // compare results
        assert_eq!(m_he_a, m_pl_a);
        assert_eq!(m_he_s, m_pl_s);
    }
}
