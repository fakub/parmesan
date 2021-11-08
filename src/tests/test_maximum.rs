use crate::tests::{self,*};
use crate::userovo::encryption;
use crate::arithmetics::ParmArithmetics;

#[test]
/// Maximum of encrypted sub-samples only.
fn t_max_non_triv() {
    //DBG
    println!("Non-Triv ...");

    t_impl_max_with_mode(EncrVsTriv::ENCR);
}

//WISH
//~ #[test]
//~ /// Maximum of trivial sub-samples only.
//~ fn t_max_all_triv() {
    //~ //DBG
    //~ println!("All-Triv ...");

    //~ t_impl_max_with_mode(EncrVsTriv::TRIV);
//~ }

//~ #[test]
//~ /// Maximum of mixed sub-samples.
//~ fn t_max_some_triv() {
    //~ //DBG
    //~ println!("Mixed ...");

    //~ t_impl_max_with_mode(EncrVsTriv::ENCRTRIV);
//~ }


// -----------------------------------------------------------------------------
//  Test Implementations

/// Implementation for three variants of vector to be evaluated.
fn t_impl_max_with_mode(mode: EncrVsTriv) {
    for _ in 0..TESTS_REPEAT_MAX {
        // generate random vector(s)
        let m1_vec = gen_rand_vec(TESTS_PLAIN_BITLEN_MED);
        let m2_vec = gen_rand_vec(TESTS_PLAIN_BITLEN_MED);
        // convert to integer(s)
        let m1 = encryption::convert(&m1_vec).expect("convert failed.");
        let m2 = encryption::convert(&m2_vec).expect("convert failed.");

        // encrypt -> homomorphic eval -> decrypt
        let c1 = encrypt_with_mode(&m1_vec, mode);
        let c2 = encrypt_with_mode(&m2_vec, mode);

        //DBG
        println!("  m1 = {}, m2 = {}", m1, m2);

        let c_he = ParmArithmetics::max(&tests::PC, &c1, &c2);

        let m_he = PU.decrypt(&c_he).expect("ParmesanUserovo::decrypt failed.");

        // plain eval
        let m_pl = ParmArithmetics::max(&tests::PC, &m1, &m2);

        //DBG
        println!("  max = {} (exp. {})", m_he, m_pl);

        // compare results
        assert_eq!(m_he, m_pl);
    }
}
