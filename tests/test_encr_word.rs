#[macro_use]
extern crate lazy_static;

use rand::Rng;

use parmesan::ciphertexts::ParmEncrWord;

#[allow(dead_code)]
mod common;
use common::*;


// -----------------------------------------------------------------------------
//  Test Cases

// Basic operations all-in

#[test]
/// Both Triv
fn t_encr_word_tt() {
    println!("EncrWord: both triv ...");
    t_impl_encr_word_with_modes(EncrVsTriv::TRIV, EncrVsTriv::TRIV);
}

#[test]
/// Self Triv, Other Non-Triv
fn t_encr_word_te() {
    println!("EncrWord: triv non-triv ...");
    t_impl_encr_word_with_modes(EncrVsTriv::TRIV, EncrVsTriv::ENCR);
}

#[test]
/// Self Non-Triv, Other Triv
fn t_encr_word_et() {
    println!("EncrWord: non-triv triv ...");
    t_impl_encr_word_with_modes(EncrVsTriv::ENCR, EncrVsTriv::TRIV);
}

#[test]
/// Both Non-Triv
fn t_encr_word_ee() {
    println!("EncrWord: both non-triv ...");
    t_impl_encr_word_with_modes(EncrVsTriv::ENCR, EncrVsTriv::ENCR);
}

// finally, just verify ENCRTRIV
#[test]
/// Both Triv
fn t_encr_word_etet() {
    println!("EncrWord: both triv ...");
    t_impl_encr_word_with_modes(EncrVsTriv::ENCRTRIV, EncrVsTriv::ENCRTRIV);
}


// -----------------------------------------------------------------------------
//  Test Implementations

fn t_impl_encr_word_with_modes(
    s_mode: EncrVsTriv,
    o_mode: EncrVsTriv,
) {
    // for message generation
    let mut rng = rand::thread_rng();
    // plaintext size
    let ps_mod = common::TEST_PARAMS.plaintext_space_size();

    for _ in 0..common::TESTS_REPEAT_ENCR_WORD {
        // generate random message
        let ms: i32 = rng.gen_range(-(common::TEST_PARAMS.plaintext_pos_max() as i32)..common::TEST_PARAMS.plaintext_pos_max() as i32);
        let mo: i32 = rng.gen_range(-(common::TEST_PARAMS.plaintext_pos_max() as i32)..common::TEST_PARAMS.plaintext_pos_max() as i32);

        println!("  ms = {}", ms);
        println!("  mo = {}", mo);

        // encrypt
        let cs = match s_mode {
            EncrVsTriv::ENCR     => ParmEncrWord::encrypt_word(     &common::TEST_PRIV_KEYS,   ms),
            EncrVsTriv::TRIV     => ParmEncrWord::encrypt_word_triv(&common::TEST_PC.pub_keys, ms),
            //TODO what is this supposed to do??
            EncrVsTriv::ENCRTRIV => ParmEncrWord::encrypt_word_triv(&common::TEST_PC.pub_keys, ms),
        };
        let co = match o_mode {
            EncrVsTriv::ENCR     => ParmEncrWord::encrypt_word(     &common::TEST_PRIV_KEYS,   mo),
            EncrVsTriv::TRIV     => ParmEncrWord::encrypt_word_triv(&common::TEST_PC.pub_keys, mo),
            EncrVsTriv::ENCRTRIV => ParmEncrWord::encrypt_word_triv(&common::TEST_PC.pub_keys, mo),
        };

        // test is_triv
        match s_mode {
            EncrVsTriv::ENCR => assert!(!cs.is_triv()),
            EncrVsTriv::TRIV => assert!(cs.is_triv()),
            EncrVsTriv::ENCRTRIV => assert!(cs.is_triv()),
        }

        // verify inputs (also check the case with None)
        let ds:  u64 = if s_mode == EncrVsTriv::ENCRTRIV {
            cs.decrypt_mu(None).expect("ParmEncrWord::decrypt_mu failed.")
        } else {
            cs.decrypt_mu(Some(&common::TEST_PRIV_KEYS)).expect("ParmEncrWord::decrypt_mu failed.")
        };
        let d_o: u64 = co.decrypt_mu(Some(&common::TEST_PRIV_KEYS)).expect("ParmEncrWord::decrypt_mu failed.");
        println!("  ds = {} (exp. {})", ds,  ms.rem_euclid(ps_mod));
        println!("  do = {} (exp. {})", d_o, mo.rem_euclid(ps_mod));
        assert_eq!(ds  as i32, ms.rem_euclid(ps_mod));
        assert_eq!(d_o as i32, mo.rem_euclid(ps_mod));

        // verify addition/subtraction
        let cadd = cs.add(&co);
        let csub = cs.sub(&co);
        let dadd: u64 = cadd.decrypt_mu(Some(&common::TEST_PRIV_KEYS)).expect("ParmEncrWord::decrypt_mu failed.");
        let dsub: u64 = csub.decrypt_mu(Some(&common::TEST_PRIV_KEYS)).expect("ParmEncrWord::decrypt_mu failed.");
        println!("  dadd = {} (exp. {})", dadd,  (ms + mo).rem_euclid(ps_mod));
        println!("  dsub = {} (exp. {})", dsub,  (ms - mo).rem_euclid(ps_mod));
        assert_eq!(dadd as i32, (ms + mo).rem_euclid(ps_mod));
        assert_eq!(dsub as i32, (ms - mo).rem_euclid(ps_mod));

        // verify mul_const
        let k: i32 = rng.gen_range(-(common::TESTS_EW_MAX_SCALAR as i32)..=common::TESTS_EW_MAX_SCALAR as i32);
        let cscm = cs.mul_const(k);
        let dscm: u64 = cscm.decrypt_mu(Some(&common::TEST_PRIV_KEYS)).expect("ParmEncrWord::decrypt_mu failed.");
        println!("  dscm = {} (exp. {})", dscm,  (k * ms).rem_euclid(ps_mod));
        assert_eq!(dscm as i32, (k * ms).rem_euclid(ps_mod));

        // verify add_half_inplace
        let mut cah = cs.clone();
        cah.add_half_inplace();
        cah.mul_const_inplace(2);
        let dah: u64 = cah.decrypt_mu(Some(&common::TEST_PRIV_KEYS)).expect("ParmEncrWord::decrypt_mu failed.");
        println!("  dah = {} (exp. {})", dah,  (ms * 2 + 1).rem_euclid(ps_mod));
        assert_eq!(dah as i32, (ms * 2 + 1).rem_euclid(ps_mod));
    }
}
