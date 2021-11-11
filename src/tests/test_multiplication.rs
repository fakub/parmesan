use crate::tests::{self,*};
use crate::userovo::encryption;
use crate::arithmetics::ParmArithmetics;

#[test]
/// Multiplication of encrypted sub-samples only, aligned lengths.
fn t_mul_non_triv_aligned() {
    println!("Non-Triv Aligned ...");
    t_impl_mul_with_mode(EncrVsTriv::ENCR, true);
}

//WISH
//~ #[test]
//~ /// Multiplication of encrypted sub-samples only, different lengths.
//~ fn t_mul_non_triv_difflen() {
    //~ println!("Non-Triv Misaligned ...");
    //~ t_impl_mul_with_mode(EncrVsTriv::ENCR, false);
//~ }

//WISH
//~ #[test]
//~ /// Multiplication of trivial sub-samples only.
//~ fn t_mul_all_triv() {
    //~ println!("All-Triv ...");
    //~ t_impl_mul_with_mode(EncrVsTriv::TRIV);
//~ }

//~ #[test]
//~ /// Multiplication of mixed sub-samples.
//~ fn t_mul_some_triv() {
    //~ println!("Mixed ...");
    //~ t_impl_mul_with_mode(EncrVsTriv::ENCRTRIV);
//~ }


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
    let mut range: Vec<_> = (0..=TESTS_BITLEN_MUL).collect();
    range.extend(TESTS_EXTRA_BITLEN_MUL);

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

        let c_he = ParmArithmetics::mul(&tests::PC, &c1, &c2);

        let m_he = PU.decrypt(&c_he).expect("ParmesanUserovo::decrypt failed.");

        // plain eval
        let m_pl = ParmArithmetics::mul(&tests::PC, &m1, &m2);

        println!("  mul = {} (exp. {})", m_he, m_pl);

        // compare results
        assert_eq!(m_he, m_pl);
    }
}



// #############################################################################

// pos x pos, pos x neg, neg x neg
// ... x 1, 0, -1
