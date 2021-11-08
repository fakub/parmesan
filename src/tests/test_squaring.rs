use crate::tests::{self,*};
use crate::userovo::encryption;
use crate::arithmetics::ParmArithmetics;

#[test]
/// Squaring of encrypted sub-samples only.
fn t_squ_non_triv_aligned() {
    //DBG
    println!("Non-Triv ...");

    t_impl_squ_with_mode(EncrVsTriv::ENCR);
}

//WISH
//~ #[test]
//~ /// Squaring of trivial sub-samples only.
//~ fn t_squ_all_triv() {
    //~ //DBG
    //~ println!("All-Triv ...");

    //~ t_impl_squ_with_mode(EncrVsTriv::TRIV);
//~ }

//~ #[test]
//~ /// Squaring of mixed sub-samples.
//~ fn t_squ_some_triv() {
    //~ //DBG
    //~ println!("Mixed ...");

    //~ t_impl_squ_with_mode(EncrVsTriv::ENCRTRIV);
//~ }


// -----------------------------------------------------------------------------
//  Test Implementations

/// Implementation for three variants of vector to be evaluated.
fn t_impl_squ_with_mode(mode: EncrVsTriv) {
    // set up bit-lengths
    let mut range: Vec<_> = (0..=TESTS_BITLEN_SQU).collect();
    range.extend(TESTS_EXTRA_BITLEN_SQU);

    for bl in range {
        // generate random vector(s)
        let m1_vec = gen_rand_vec(bl);
        // convert to integer(s)
        let m1 = encryption::convert(&m1_vec).expect("convert failed.");

        //DBG
        println!("  m1 = {} ({}-bit)", m1, bl);

        // encrypt -> homomorphic eval -> decrypt
        let c1 = encrypt_with_mode(&m1_vec, mode);
        let c_he = ParmArithmetics::squ(&tests::PC, &c1);
        let m_he = PU.decrypt(&c_he).expect("ParmesanUserovo::decrypt failed.");

        // plain eval
        let m_pl = ParmArithmetics::squ(&tests::PC, &m1);

        //DBG
        println!("  squ = {} (exp. {})", m_he, m_pl);

        // compare results
        assert_eq!(m_he, m_pl);
    }
}
