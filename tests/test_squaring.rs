#[macro_use]
extern crate lazy_static;

use parmesan::userovo::encryption::{self,*};
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

#[test]
/// Squaring of mixed sub-samples.
fn t_squ_some_triv() {
    println!("Mixed ...");
    t_impl_squ_with_mode(EncrVsTriv::ENCRTRIV);
}

#[test]
/// Squaring 2,3-bit.
fn t_squ_2_3() {
    println!("2, 3-bit ...");

    let vecs = vec![
        vec![0,0,],
        vec![1,0,],
        vec![0,1,],
        vec![1,1,],
        vec![0,0,1,],
        vec![1,0,1,],
        vec![0,1,1,],
        vec![1,1,1,],
    ];

    for m_vec in vecs {
        t_impl_squ_2_3(&m_vec);

        // negated variant
        let m_vec_neg = m_vec.iter().map(|mi| -mi ).collect();
        t_impl_squ_2_3(&m_vec_neg);
    }
}


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
        let m1 = encryption::convert_from_vec(&m1_vec).expect("convert failed.");

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

/// Implementation for short vectors.
fn t_impl_squ_2_3(m_vec: &Vec<i32>) {
    // convert to integer(s)
    let m = encryption::convert_from_vec(&m_vec).expect("convert failed.");

    println!("  m = {} ({}-bit)", m, m_vec.len());

    // encrypt -> homomorphic eval -> decrypt
    let c = encrypt_with_mode(&m_vec, EncrVsTriv::ENCR);
    let c_he = ParmArithmetics::squ(&common::TEST_PC, &c);
    let m_vec_he = parm_decrypt_to_vec(common::TEST_PARAMS, &common::TEST_PRIV_KEYS, &c_he).expect("parm_decrypt_to_vec failed.");
    let m_he = common::TEST_PU.decrypt(&c_he).expect("ParmesanUserovo::decrypt failed.");

    // plain eval
    let m_pl = ParmArithmetics::squ(&common::TEST_PC, &m);

    println!("  squ = {} as {:?} (exp. {})", m_he, m_vec_he, m_pl);

    // compare results
    assert_eq!(m_he, m_pl);
}
