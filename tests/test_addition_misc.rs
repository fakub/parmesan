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

// Add Const

#[test]
/// Addition of a constant to encrypted sub-samples only.
fn t_add_const_non_triv() {
    println!("Non-Triv ...");
    t_impl_add_const_with_mode(EncrVsTriv::ENCR);
}

#[test]
/// Addition of a constant to trivial sub-samples only.
fn t_add_const_all_triv() {
    println!("All-Triv ...");
    t_impl_add_const_with_mode(EncrVsTriv::TRIV);
}

#[test]
/// Addition of a constant to mixed sub-samples.
fn t_add_const_some_triv() {
    println!("Mixed ...");
    t_impl_add_const_with_mode(EncrVsTriv::ENCRTRIV);
}

// Corner Cases
//TODO add others

#[test]
/// Corner cases with trivial zeros, encrypted sub-samples only.
fn t_add_triv_0() {
    println!("Non-Triv ...");
    //        00███00
    //  000██00000000
    t_impl_add_triv_zeros_with_mode(
        2, 3, 2,
        EncrVsTriv::ENCR,
        3, 2, 8,
    )
}


// -----------------------------------------------------------------------------
//  Test Implementations

/// Implementation for three variants of vector to be evaluated.
fn t_impl_add_const_with_mode(
    mode: EncrVsTriv,
) {
    // for mis-aligned length generation
    let mut rng = rand::thread_rng();

    for _ in 0..common::TESTS_REPEAT_ADD_CONST {
        // generate random vector(s)
        let bl_e = rng.gen_range(0..=common::TESTS_BITLEN_ADD_CONST);
        let bl_c = rng.gen_range(0..=common::TESTS_BITLEN_ADD_CONST);
        let me_vec = gen_rand_vec(bl_e);
        let mc_vec = gen_rand_vec(bl_c);
        // convert to integer(s)
        let me = encryption::convert(&me_vec).expect("convert failed.");
        let mc = encryption::convert(&mc_vec).expect("convert failed.");

        println!("  m = {} ({}-bit: {:?}), const = {} ({}-bit: {:?})", me, bl_e, me_vec, mc, bl_c, mc_vec);

        // encrypt -> homomorphic eval -> decrypt
        let c = encrypt_with_mode(&me_vec, mode);
        let c_he = ParmArithmetics::add_const(&common::TEST_PC, &c, mc);
        let m_he = common::TEST_PU.decrypt(&c_he).expect("ParmesanUserovo::decrypt failed.");

        // plain eval
        let m_pl = ParmArithmetics::add_const(&common::TEST_PC, &me, mc);

        println!("  add const = {} (exp. {})", m_he, m_pl);

        // compare results
        assert_eq!(m_he, m_pl);
    }
}

/// Implementation for manually provided cases of triv zeros.
fn t_impl_add_triv_zeros_with_mode(
    ltriv_x: usize,
    ct_len_x: usize,
    rtriv_x: usize,
    mode: EncrVsTriv,
    ltriv_y: usize,
    ct_len_y: usize,
    rtriv_y: usize,
) {
    for _ in 0..common::TESTS_REPEAT_ADD_TRIV_0 {
        // generate random vectors & respective ciphertexts with given number of trivial zeros
        let (m1_vec, c1) = t_gen_ct_with_triv_zeros(
            ltriv_x,
            ct_len_x,
            rtriv_x,
            mode,
        );
        let (m2_vec, c2) = t_gen_ct_with_triv_zeros(
            ltriv_y,
            ct_len_y,
            rtriv_y,
            mode,
        );
        // convert to integer(s)
        let m1 = encryption::convert(&m1_vec).expect("convert failed.");
        let m2 = encryption::convert(&m2_vec).expect("convert failed.");

        println!("  m1 = {} ({:?} |{}█{}|), m2 = {} ({:?} |{}█{}|)", m1, m1_vec, ltriv_x, rtriv_x, m2, m2_vec, ltriv_y, rtriv_y);

        // homomorphic eval -> decrypt
        let c_he_a = ParmArithmetics::add(&common::TEST_PC, &c1, &c2);
        let c_he_s = ParmArithmetics::sub(&common::TEST_PC, &c1, &c2);

        let m_he_a = common::TEST_PU.decrypt(&c_he_a).expect("ParmesanUserovo::decrypt failed.");
        let m_he_s = common::TEST_PU.decrypt(&c_he_s).expect("ParmesanUserovo::decrypt failed.");

        // plain eval
        let m_pl_a = ParmArithmetics::add(&common::TEST_PC, &m1, &m2);
        let m_pl_s = ParmArithmetics::sub(&common::TEST_PC, &m1, &m2);

        println!("  add = {} (exp. {})", m_he_a, m_pl_a);
        println!("  sub = {} (exp. {})", m_he_s, m_pl_s);

        // compare results
        assert_eq!(m_he_a, m_pl_a);
        assert_eq!(m_he_s, m_pl_s);
    }
}


// -----------------------------------------------------------------------------
//  Aux Functions

/// Generation of ciphertexts with left/right triv zeros
fn t_gen_ct_with_triv_zeros(
    ltriv: usize,
    ct_len: usize,
    rtriv: usize,
    mode: EncrVsTriv,
) -> (Vec<i32>, ParmCiphertext) {
    // right triv zeros
    let mut m_vec = vec![0; rtriv];
    // generate random vector (for inner ciphertext)
    let mut i_vec = gen_rand_vec(ct_len);
    // left triv zeros
    let mut l_vec = vec![0; ltriv];

    // stick ciphertext together
    let mut c = ParmCiphertext::triv(rtriv, &common::TEST_PUB_K.encoder).expect("ParmCiphertext::triv failed.");
    let mut ci = encrypt_with_mode(&i_vec, mode);
    c.append(&mut ci);
    let mut cl = ParmCiphertext::triv(ltriv, &common::TEST_PUB_K.encoder).expect("ParmCiphertext::triv failed.");
    c.append(&mut cl);

    // stick plaintext together
    m_vec.append(&mut i_vec);
    m_vec.append(&mut l_vec);

    (m_vec, c)
}




// #############################################################################



//~ #[test]
//~ fn add_cc_1() {
    //~ // =================================
    //~ // test : addition of two elements x and y such as x and y generated randomly
    //~ //         {      wlen      }
    //~ // x : |0|0|.. -|-|-|-|1|1|0|1
    //~ // y :  0|0|0|..|-|1|0|0|1|0|1
    //~ //==================================
    //~ for _i in 0..10 {
        //~ let mut rng = rand::thread_rng();
        //~ let x_len = rng.gen_range(6..32);
        //~ let x_wlen = rng.gen_range(4..x_len);
        //~ let x_triv_len = rng.gen_range(2..x_wlen);
        //~ let y_len = rng.gen_range(6..32);
        //~ let y_wlen = rng.gen_range(4..y_len);
        //~ let y_triv_len = rng.gen_range(2..y_wlen);
        //~ add_cc_nz(x_len, x_wlen, x_triv_len, y_len, y_wlen, y_triv_len).unwrap();
    //~ }
//~ }

//~ #[test]
//~ fn add_cc_2() {
    //~ // =================================
    //~ // test : addition of two elements x and y such as : |x|> wlen > |y|
    //~ //         {      wlen      }
    //~ // x : |0|0|.. -|-|-|-|1|0|0
    //~ // y :        0|0|..|-|1|0|0
    //~ //==================================
    //~ for _i in 0..10 {
        //~ let mut rng = rand::thread_rng();
        //~ let x_len = rng.gen_range(10..32);
        //~ let x_wlen = rng.gen_range(8..x_len);
        //~ let x_triv_len = rng.gen_range(2..x_wlen);
        //~ let y_len = rng.gen_range(6..x_wlen);
        //~ let y_wlen = rng.gen_range(4..y_len);
        //~ let y_triv_len = rng.gen_range(2..y_wlen);
        //~ add_cc(x_len, x_wlen, x_triv_len, y_len, y_wlen, y_triv_len).unwrap();
    //~ }
//~ }
//~ #[test]
//~ fn add_cc_3() {
    //~ // =================================
    //~ // Addition corner case 3 : |y| > |x| > wlen
    //~ // test : addition of two elements x and y such as : |y|> |x| >wlen
    //~ //            {       wlen    }
    //~ // x :    |0|0|... -|-|-|-|1|0|0
    //~ // y : 0|0|0|0|0|-..|-|-|-|1|0|0
    //~ //==================================
    //~ let mut rng = rand::thread_rng();
    //~ // generate 10 random ciphertexts for x and y and call add_cc to test them
    //~ for _i in 0..10 {
        //~ let x_len = rng.gen_range(8..32);
        //~ let x_wlen = rng.gen_range(6..x_len);
        //~ let x_triv_len = rng.gen_range(2..x_wlen);
        //~ let y_len = rng.gen_range(x_len - 1..32);
        //~ let y_wlen = rng.gen_range(4..x_wlen);
        //~ let y_triv_len = rng.gen_range(2..y_wlen);
        //~ add_cc(x_len, x_wlen, x_triv_len, y_len, y_wlen, y_triv_len).unwrap();
    //~ }
//~ }

//~ #[test]
//~ fn add_cc_4() {
    //~ // =================================
    //~ // test : addition of two elements x and y such as : |x|> |y|> wlen
    //~ //            {      wlen      }
    //~ // x :|0|0|0|0|0|-|-|-|-|1|0|0
    //~ // y :     0|0|-..|-|-|-|1|0|0
    //~ //==================================
    //~ let mut rng = rand::thread_rng();
    //~ // generate 10 random ciphertexts for x and y and call add_cc to test them
    //~ for _i in 0..10 {
        //~ let x_len = rng.gen_range(10..12);
        //~ let y_len = rng.gen_range(8..x_len);
        //~ let y_wlen = rng.gen_range(6..y_len);
        //~ let x_wlen = rng.gen_range(4..y_wlen);
        //~ let x_triv_len = rng.gen_range(2..x_wlen);
        //~ let y_triv_len = rng.gen_range(2..y_wlen);
        //~ add_cc(x_len, x_wlen, x_triv_len, y_len, y_wlen, y_triv_len).unwrap();
    //~ }
//~ }

//~ #[test]
//~ fn add_cc_5() {
    //~ // =================================
    //~ // Addition corner case 4 : |y| > wlen > |x|
    //~ // test : addition of two elements x and y such as : |y|> wlen > |x|
    //~ //        {      wlen      }
    //~ // x :      |0|0|-|-|1|0|0|0
    //~ // y :|0|0|-...|-|-|-|1|0|1
    //~ //==================================
    //~ let mut rng = rand::thread_rng();
    //~ // generate 10 random ciphertexts for x and y and call add_cc to test them
    //~ for _i in 0..10 {
        //~ let x_len = rng.gen_range(6..31);
        //~ let y_len = rng.gen_range(x_len..32);
        //~ let y_wlen = rng.gen_range(x_len..y_len);
        //~ let x_wlen = rng.gen_range(3..x_len);
        //~ let x_triv_len = rng.gen_range(2..x_wlen);
        //~ let y_triv_len = rng.gen_range(2..y_wlen);
        //~ add_cc(x_len, x_wlen, x_triv_len, y_len, y_wlen, y_triv_len).unwrap();
    //~ }
//~ }
