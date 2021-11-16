#[macro_use]
extern crate lazy_static;

use parmesan::userovo::encryption;
use parmesan::arithmetics::ParmArithmetics;

#[allow(dead_code)]
mod common;
use common::*;


// -----------------------------------------------------------------------------
//  Test Cases

#[test]
/// Squaring of encrypted sub-samples only.
fn t_squ_non_triv_aligned() {
    println!("Non-Triv ...");
    t_impl_squ_with_mode(EncrVsTriv::ENCR);
}

#[test]
/// Squaring of trivial sub-samples only.
fn t_squ_all_triv() {
    println!("All-Triv ...");
    t_impl_squ_with_mode(EncrVsTriv::TRIV);
}

//FIXME same as for multiplication
//~ #[test]
//~ /// Squaring of mixed sub-samples.
//~ fn t_squ_some_triv() {
    //~ println!("Mixed ...");
    //~ t_impl_squ_with_mode(EncrVsTriv::ENCRTRIV);
//~ }


// -----------------------------------------------------------------------------
//  Test Implementations

/// Implementation for three variants of vector to be evaluated.
fn t_impl_squ_with_mode(mode: EncrVsTriv) {
    // set up bit-lengths
    let mut range: Vec<_> = (0..=common::TESTS_BITLEN_SQU).collect();
    range.extend(common::TESTS_EXTRA_BITLEN_SQU);

    for bl in range {
        // generate random vector(s)
        let m1_vec = gen_rand_vec(bl);
        // convert to integer(s)
        let m1 = encryption::convert(&m1_vec).expect("convert failed.");

        println!("  m1 = {} ({}-bit)", m1, bl);

        // encrypt -> homomorphic eval -> decrypt
        let c1 = encrypt_with_mode(&m1_vec, mode);
        let c_he = ParmArithmetics::squ(&common::TEST_PC, &c1);
        let m_he = common::TEST_PU.decrypt(&c_he).expect("ParmesanUserovo::decrypt failed.");

        // plain eval
        let m_pl = ParmArithmetics::squ(&common::TEST_PC, &m1);

        println!("  squ = {} (exp. {})", m_he, m_pl);

        // compare results
        assert_eq!(m_he, m_pl);
    }
}
