use crate::tests::{self,*};
use crate::userovo::encryption;
use crate::arithmetics::ParmArithmetics;

#[test]
/// Scalar multiplication of encrypted sub-samples only.
fn t_scm_non_triv() {
    println!("Non-Triv ...");
    t_impl_scm_with_mode(EncrVsTriv::ENCR);
}

//WISH
//~ #[test]
//~ /// Scalar multiplication of trivial sub-samples only.
//~ fn t_scm_all_triv() {
    //~ println!("All-Triv ...");
    //~ t_impl_scm_with_mode(EncrVsTriv::TRIV);
//~ }

//~ #[test]
//~ /// Scalar multiplication of mixed sub-samples.
//~ fn t_scm_some_triv() {
    //~ println!("Mixed ...");
    //~ t_impl_scm_with_mode(EncrVsTriv::ENCRTRIV);
//~ }


// -----------------------------------------------------------------------------
//  Test Implementations

/// Implementation for three variants of vector to be evaluated.
fn t_impl_scm_with_mode(mode: EncrVsTriv) {
    // for random scalar generation
    let mut rng = rand::thread_rng();

    for _ in 0..TESTS_REPEAT_SCM {
        // generate random vector(s)
        let m1_vec = gen_rand_vec(TESTS_BITLEN_SCM);
        // convert to integer(s)
        let m1 = encryption::convert(&m1_vec).expect("convert failed.");
        // generate random scalar
        let k: i32 = rng.gen_range(-(1 << TESTS_BITLEN_SCALAR)..=(1 << TESTS_BITLEN_SCALAR));

        println!("  m = {} ({}-bit: {:?}), k = {}", m1, TESTS_BITLEN_SCM, m1_vec, k);

        // encrypt -> homomorphic eval -> decrypt
        let c1 = encrypt_with_mode(&m1_vec, mode);
        let c_he = ParmArithmetics::scalar_mul(&tests::PC, k, &c1);
        let m_he = PU.decrypt(&c_he).expect("ParmesanUserovo::decrypt failed.");

        // plain eval
        let m_pl = ParmArithmetics::scalar_mul(&tests::PC, k, &m1);

        println!("  scm = {} (exp. {})", m_he, m_pl);

        // compare results
        assert_eq!(m_he, m_pl);
    }
}





// #############################################################################



//TODO
//  k = 0, 1, -1
//  k = 2^n
