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
/// Multiplication of encrypted sub-samples only, aligned lengths.
fn t_mul_non_triv_aligned() {
    println!("Non-Triv Aligned ...");
    t_impl_mul_with_mode(EncrVsTriv::ENCR, true);
}

//FIXME make this work
#[test]
/// Multiplication of encrypted sub-samples only, different lengths.
fn t_mul_non_triv_difflen() {
    println!("Non-Triv Misaligned ...");
    t_impl_mul_with_mode(EncrVsTriv::ENCR, false);
}

#[test]
/// Multiplication of trivial sub-samples only, aligned lengths.
fn t_mul_all_triv_aligned() {
    println!("All-Triv Aligned ...");
    t_impl_mul_with_mode(EncrVsTriv::TRIV, true);
}

//FIXME this fails for some weird reason:
// thread 't_mul_some_triv_aligned' panicked at 'mul_uint_constant failed.:
// The integer representation has not enough precision to represent error samples from the normal law of variance 0 so the ciphertext does not contain any noise!
//~ #[test]
//~ /// Multiplication of mixed sub-samples, aligned lengths.
//~ fn t_mul_some_triv_aligned() {
    //~ println!("Mixed Aligned ...");
    //~ t_impl_mul_with_mode(EncrVsTriv::ENCRTRIV, true);
//~ }

// Special

#[test]
fn t_mul_case() {
    println!("Case ...");

    // setup specific vectors
    let m1_vec = vec![0, 0];
    let m2_vec = vec![0, -1];
    // convert to integer(s)
    let m1 = encryption::convert(&m1_vec).expect("convert failed.");
    let m2 = encryption::convert(&m2_vec).expect("convert failed.");

    println!("  m1 = {} ({}-bit: {:?})\n  m2 = {} ({}-bit: {:?})", m1, m1_vec.len(), m1_vec, m2, m2_vec.len(), m2_vec);

    // encrypt -> homomorphic eval -> decrypt
    let c1 = encrypt_with_mode(&m1_vec, EncrVsTriv::TRIV);
    let c2 = encrypt_with_mode(&m2_vec, EncrVsTriv::ENCR);

    let c_he = ParmArithmetics::mul(&common::TEST_PC, &c1, &c2);

    let m_he = common::TEST_PU.decrypt(&c_he).expect("ParmesanUserovo::decrypt failed.");

    // plain eval
    let m_pl = ParmArithmetics::mul(&common::TEST_PC, &m1, &m2);

    println!("  mul = {} (exp. {})", m_he, m_pl);

    // compare results
    assert_eq!(m_he, m_pl);
}


// -----------------------------------------------------------------------------
//  Test Implementations

/// Implementation for three variants of vector to be evaluated.
fn t_impl_mul_with_mode(
    mode: EncrVsTriv,
    aligned: bool,
) {
    // for mis-aligned length generation
    let mut rng = rand::thread_rng();

    // set up bit-lengths
    let mut range: Vec<_> = (0..=common::TESTS_BITLEN_MUL).collect();
    range.extend(common::TESTS_EXTRA_BITLEN_MUL);

    for bl in range {
        // generate random vector(s)
        let bl1 = if aligned {bl} else {rng.gen_range(0..=bl)};
        let bl2 = if aligned {bl} else {rng.gen_range(0..=bl)};
        let m1_vec = gen_rand_vec(bl1);
        let m2_vec = gen_rand_vec(bl2);
        // convert to integer(s)
        let m1 = encryption::convert(&m1_vec).expect("convert failed.");
        let m2 = encryption::convert(&m2_vec).expect("convert failed.");

        println!("  m1 = {} ({}-bit: {:?})\n  m2 = {} ({}-bit: {:?})", m1, bl1, m1_vec, m2, bl2, m2_vec);

        // encrypt -> homomorphic eval -> decrypt
        let c1 = encrypt_with_mode(&m1_vec, mode);
        let c2 = encrypt_with_mode(&m2_vec, mode);

        let c_he = ParmArithmetics::mul(&common::TEST_PC, &c1, &c2);

        let m_he = common::TEST_PU.decrypt(&c_he).expect("ParmesanUserovo::decrypt failed.");

        // plain eval
        let m_pl = ParmArithmetics::mul(&common::TEST_PC, &m1, &m2);

        println!("  mul = {} (exp. {})", m_he, m_pl);

        // compare results
        assert_eq!(m_he, m_pl);
    }
}



// #############################################################################

// pos x pos, pos x neg, neg x neg
// ... x 1, 0, -1
