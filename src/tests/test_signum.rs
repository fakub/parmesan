use crate::tests::{self,*};
use crate::userovo::encryption;
use crate::arithmetics::ParmArithmetics;

#[test]
/// Signum of encrypted sub-samples only.
fn t_sgn_non_triv() {
    //DBG
    println!("Non-Triv ...");

    t_impl_sgn_with_mode(EncrVsTriv::ENCR);
}

//WISH
//~ #[test]
//~ /// Signum of trivial sub-samples only.
//~ fn t_sgn_all_triv() {
    //~ //DBG
    //~ println!("All-Triv ...");

    //~ t_impl_sgn_with_mode(EncrVsTriv::TRIV);
//~ }

//~ #[test]
//~ /// Signum of mixed sub-samples.
//~ fn t_sgn_some_triv() {
    //~ //DBG
    //~ println!("Mixed ...");

    //~ t_impl_sgn_with_mode(EncrVsTriv::ENCRTRIV);
//~ }


// -----------------------------------------------------------------------------
//  Test Implementations

/// Implementation for three variants of vector to be evaluated.
fn t_impl_sgn_with_mode(mode: EncrVsTriv) {
    for _ in 0..TESTS_REPEAT_SGN {
        // generate random vector(s)
        let m1_vec = gen_rand_vec(TESTS_PLAIN_BITLEN_MED);
        // convert to integer(s)
        let m1 = encryption::convert(&m1_vec).expect("convert failed.");

        // encrypt -> homomorphic eval -> decrypt
        let c1 = encrypt_with_mode(&m1_vec, mode);
        let c_he = ParmArithmetics::sgn(&tests::PC, &c1);
        let m_he = PU.decrypt(&c_he).expect("ParmesanUserovo::decrypt failed.");

        // plain eval
        let m_pl = ParmArithmetics::sgn(&tests::PC, &m1);

        // compare results
        assert_eq!(m_he, m_pl);
    }
}
