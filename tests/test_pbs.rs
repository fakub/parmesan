#[macro_use]
extern crate lazy_static;

use rand::Rng;

use parmesan::ciphertexts::ParmEncrWord;
use parmesan::cloudovo::pbs;

#[allow(dead_code)]
mod common;
use common::*;


// -----------------------------------------------------------------------------
//  Test Cases

// Basic operations all-in

#[test]
/// PBS of Triv
fn t_pbs_triv() {
    println!("PBS triv ...");
    t_impl_pbs_with_mode(EncrVsTriv::TRIV);
}

#[test]
/// PBS of Non-Triv
fn t_pbs_non_triv() {
    println!("PBS non-triv ...");
    t_impl_pbs_with_mode(EncrVsTriv::ENCR);
}


// -----------------------------------------------------------------------------
//  Test Implementations

fn t_impl_pbs_with_mode(
    mode: EncrVsTriv,
) {
    // for message generation
    let mut rng = rand::thread_rng();
    // plaintext size
    let ps_mod = common::TEST_PARAMS.plaintext_space_size();

    for _ in 0..common::TESTS_REPEAT_PBS {
        // generate random message
        let m: i32 = rng.gen_range(-(common::TEST_PARAMS.plaintext_pos_max() as i32)..common::TEST_PARAMS.plaintext_pos_max() as i32);
        let m_usize = m.rem_euclid(ps_mod) as usize;

        println!("  m = {}", m);

        // encrypt
        let c = match mode {
            EncrVsTriv::ENCR     => ParmEncrWord::encrypt_word(     &common::TEST_PRIV_KEYS,   m),
            EncrVsTriv::TRIV     => ParmEncrWord::encrypt_word_triv(&common::TEST_PC.pub_keys, m),
            EncrVsTriv::ENCRTRIV => panic!("Not called"),
        };

        // verify PBS
        let lut: [u64; 1 << (5-1)] = [0,1,2,3,4,5,6,7,8,7,6,5,4,3,2,1];   // 5-bit identity
        let cpbs = pbs::eval_LUT_5_uint(&common::TEST_PC, &c, lut);
        let dpbs = cpbs.decrypt_mu(Some(&common::TEST_PRIV_KEYS)).expect("ParmEncrWord::decrypt_word_pos failed.");
        let epbs = (if m_usize < ps_mod as usize / 2 {lut[m_usize] as i32} else {-(lut[m_usize - ps_mod as usize / 2] as i32)}).rem_euclid(ps_mod) as u64;
        println!("  dpbs = {} (exp. {})", dpbs, epbs);
        assert_eq!(dpbs, epbs);
    }
}
