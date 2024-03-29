#[macro_use]
extern crate lazy_static;

use rand::Rng;

use parmesan::userovo::encryption::{self, *};
use parmesan::arithmetics::ParmArithmetics;
use parmesan::scalar_multiplication::*;
use parmesan::*;

#[allow(dead_code)]
mod common;
use common::*;


// -----------------------------------------------------------------------------
//  Test Cases

#[test]
/// Scalar multiplication of encrypted sub-samples only.
fn t_scm_non_triv() {
    println!("Non-Triv ...");
    t_impl_scm_with_mode(EncrVsTriv::ENCR);
}

#[test]
/// Scalar multiplication of trivial sub-samples only.
fn t_scm_all_triv() {
    println!("All-Triv ...");
    t_impl_scm_with_mode(EncrVsTriv::TRIV);
}

#[test]
/// Scalar multiplication of mixed sub-samples.
fn t_scm_some_triv() {
    println!("Mixed ...");
    t_impl_scm_with_mode(EncrVsTriv::ENCRTRIV);
}

// Special

#[test]
/// Scalar multiplication by specific values
fn t_scm_pow_2() {
    for mode in [EncrVsTriv::ENCR, EncrVsTriv::TRIV, EncrVsTriv::ENCRTRIV] {
        t_impl_scm_with_mode_and_scalar(mode, 0);
        t_impl_scm_with_mode_and_scalar(mode, 1);
        t_impl_scm_with_mode_and_scalar(mode,-1);
        t_impl_scm_with_mode_and_scalar(mode, 2);
        t_impl_scm_with_mode_and_scalar(mode,-2);
        t_impl_scm_with_mode_and_scalar(mode, 4);
        t_impl_scm_with_mode_and_scalar(mode,-4);
        t_impl_scm_with_mode_and_scalar(mode, 256);
        t_impl_scm_with_mode_and_scalar(mode,-256);
    }
}

// ASC*, Koyama-Tsuruoka

#[test]
/// Addition-Subtraction Chains: non-emptiness & correctness.
fn t_asc() {
    println!("ASC ...");

    // ASC_12 has 2048 elements
    assert_eq!(ASC_12.len(), 2048);

    // ASC_12 is correct
    for (n, asc) in ASC_12.iter() {
        assert_eq!(*n as i64, asc.value(&common::TEST_PC));
    }
}

#[test]
/// Koyama-Tsuruoka representation
fn t_koy_tsu() {
    println!("Koyama-Tsuruoka ...");

    // for random scalar generation
    let mut rng = rand::thread_rng();

    for _ in 0..common::TESTS_REPEAT_KOY_TSU {
        // generate random scalar
        let k: i32 = rng.gen_range(0..=(1 << common::TESTS_BITLEN_KOY_TSU));

        println!("  k = {}", k);

        // calc Koyama-Tsuruoka representation
        let kt_vec = naf::koyama_tsuruoka_vec(k.abs() as u32);
        // eval it
        let k_val = convert_from_vec(&kt_vec).expect("convert failed.");

        println!("  kt_vec = {:?} ~ {}", kt_vec, k_val);

        // compare results
        assert_eq!(k.abs() as i64, k_val);
    }
}


// -----------------------------------------------------------------------------
//  Test Implementations

/// Implementation for three variants of vector to be evaluated.
fn t_impl_scm_with_mode(mode: EncrVsTriv) {
    // for random scalar generation
    let mut rng = rand::thread_rng();

    for _ in 0..common::TESTS_REPEAT_SCM {
        // generate random scalar
        let k: i32 = rng.gen_range(-(1 << common::TESTS_BITLEN_SCALAR)..=(1 << common::TESTS_BITLEN_SCALAR));
        // run test with mode & scalar
        t_impl_scm_with_mode_and_scalar(mode, k);
    }
}

/// Implementation for fixed mode & scalar
fn t_impl_scm_with_mode_and_scalar(
    mode: EncrVsTriv,
    k: i32,
) {
    // generate random vector(s)
    let m1_vec = gen_rand_vec(common::TESTS_BITLEN_SCM);
    // convert to integer(s)
    let m1 = encryption::convert_from_vec(&m1_vec).expect("convert failed.");

    println!("  m = {} ({}-bit: {:?})\n  k = {}", m1, common::TESTS_BITLEN_SCM, m1_vec, k);

    // encrypt -> homomorphic eval -> decrypt
    let c1 = encrypt_with_mode(&m1_vec, mode);
    let c_he = ParmArithmetics::scalar_mul(&common::TEST_PC, k, &c1);
    let m_he = common::TEST_PU.decrypt(&c_he).expect("ParmesanUserovo::decrypt failed.");

    // plain eval
    let m_pl = ParmArithmetics::scalar_mul(&common::TEST_PC, k, &m1);

    println!("  scm = {} (exp. {})", m_he, m_pl);

    // compare results
    assert_eq!(m_he, m_pl);
}
