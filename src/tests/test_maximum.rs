use crate::tests::{self,*};
use crate::userovo::encryption;
use crate::arithmetics::ParmArithmetics;

#[test]
/// Maximum of encrypted sub-samples only, aligned lengths.
fn t_max_non_triv_aligned() {
    println!("Non-Triv Aligned ...");
    t_impl_max_with_mode(EncrVsTriv::ENCR, true);
}

#[test]
/// Maximum of encrypted sub-samples only, different lengths.
fn t_max_non_triv_difflen() {
    println!("Non-Triv Misaligned ...");
    t_impl_max_with_mode(EncrVsTriv::ENCR, false);
}

//WISH
//~ #[test]
//~ /// Maximum of trivial sub-samples only.
//~ fn t_max_all_triv() {
    //~ println!("All-Triv ...");
    //~ t_impl_max_with_mode(EncrVsTriv::TRIV);
//~ }

//~ #[test]
//~ /// Maximum of mixed sub-samples.
//~ fn t_max_some_triv() {
    //~ println!("Mixed ...");
    //~ t_impl_max_with_mode(EncrVsTriv::ENCRTRIV);
//~ }


// -----------------------------------------------------------------------------
//  Test Implementations

/// Implementation for three variants of vector to be evaluated.
fn t_impl_max_with_mode(
    mode: EncrVsTriv,
    aligned: bool,
) {
    // for mis-aligned length generation
    let mut rng = rand::thread_rng();

    for _ in 0..TESTS_REPEAT_MAX {
        // generate random vector(s)
        let bl1 = if aligned {TESTS_BITLEN_MAX} else {rng.gen_range(0..=TESTS_BITLEN_MAX)};
        let bl2 = if aligned {TESTS_BITLEN_MAX} else {rng.gen_range(0..=TESTS_BITLEN_MAX)};
        let m1_vec = gen_rand_vec(bl1);
        let m2_vec = gen_rand_vec(bl2);
        // convert to integer(s)
        let m1 = encryption::convert(&m1_vec).expect("convert failed.");
        let m2 = encryption::convert(&m2_vec).expect("convert failed.");

        println!("  m1 = {}, m2 = {}", m1, m2);

        // encrypt -> homomorphic eval -> decrypt
        let c1 = encrypt_with_mode(&m1_vec, mode);
        let c2 = encrypt_with_mode(&m2_vec, mode);

        let c_he = ParmArithmetics::max(&tests::PC, &c1, &c2);

        let m_he = PU.decrypt(&c_he).expect("ParmesanUserovo::decrypt failed.");

        // plain eval
        let m_pl = ParmArithmetics::max(&tests::PC, &m1, &m2);

        println!("  max = {} (exp. {})", m_he, m_pl);

        // compare results
        assert_eq!(m_he, m_pl);
    }
}
