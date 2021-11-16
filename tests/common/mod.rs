use rand::Rng;

use concrete::LWE;

use parmesan::params::{self,Params};
use parmesan::ciphertexts::{ParmCiphertext,ParmCiphertextExt};
use parmesan::userovo::keys::{PrivKeySet,PubKeySet};
use parmesan::ParmesanUserovo;
use parmesan::ParmesanCloudovo;


// =============================================================================
//
//  Test Suite Initialization
//
// to evaluate code in static declaration, lazy_static must be used
// cf. https://stackoverflow.com/questions/46378637/how-to-make-a-variable-with-a-scope-lifecycle-for-all-test-functions-in-a-rust-t
pub static TEST_PARAMS: &Params = &params::PARM90__PI_5__D_20__F;   //     PARM90__PI_5__D_20__F      PARMXX__TRIVIAL
lazy_static! {
    pub static ref TEST_PRIV_KEYS: PrivKeySet = PrivKeySet::new(TEST_PARAMS).expect("PrivKeySet::new failed.");
}
lazy_static! {
    pub static ref TEST_PU: ParmesanUserovo<'static> = ParmesanUserovo::new(TEST_PARAMS).expect("ParmesanUserovo::new failed.");
}
lazy_static! {
    pub static ref TEST_PUB_K: PubKeySet<'static> = TEST_PU.export_pub_keys();
}
lazy_static! {
    pub static ref TEST_PC: ParmesanCloudovo<'static> = ParmesanCloudovo::new(TEST_PARAMS, &TEST_PUB_K);
}


// =============================================================================
//
//  Constants, Enums, ...
//
pub static TESTS_BITLEN_FULL:       usize     =  62;
pub static TESTS_BITLEN_MAX:        usize     =   7;
pub static TESTS_BITLEN_SGN:        usize     =   7;
pub static TESTS_BITLEN_MUL:        usize     =   5;
pub static TESTS_EXTRA_BITLEN_MUL: [usize; 2] =  [8,9];
pub static TESTS_BITLEN_SQU:        usize     =   7;
pub static TESTS_EXTRA_BITLEN_SQU: [usize; 2] =  [8,9];
pub static TESTS_BITLEN_ADD:        usize     =   2;
pub static TESTS_EXTRA_BITLEN_ADD: [usize; 2] = [15,TESTS_BITLEN_FULL-1];
pub static TESTS_BITLEN_ADD_CONST:  usize     =   8;
pub static TESTS_BITLEN_SCM:        usize     =   9;
pub static TESTS_BITLEN_SCALAR:     usize     =   5;
pub static TESTS_BITLEN_NNE:        usize     =   5;

// NN-specific
pub static TESTS_NNE_DEPTH:         usize     =   3;
pub static TESTS_NNE_LAYER_SIZE:    usize     =   5;
pub static TESTS_NNE_B_ABS_MAX:     i64       =  15;

pub static TESTS_REPEAT_ENCR:       usize     = 100;
pub static TESTS_REPEAT_MAX:        usize     =   3;
pub static TESTS_REPEAT_SGN:        usize     =   3;
//~ pub static TESTS_REPEAT_MUL:        usize     = 1;
//~ pub static TESTS_REPEAT_SQU:        usize     = 1;
pub static TESTS_REPEAT_ADD_CONST:  usize     =   3;
pub static TESTS_REPEAT_ADD_TRIV_0: usize     =   3;
pub static TESTS_REPEAT_SCM:        usize     =   3;
pub static TESTS_REPEAT_NNE:        usize     =   3;

#[derive(Clone,Copy)]
pub enum EncrVsTriv {
    // all words encrypted
    ENCR,
    // all words trivial
    TRIV,
    // randomly mixed trivial & encrypted
    ENCRTRIV,
}


// =============================================================================
//
//  Auxiliary Functions
//

/// Generate random vector of {-1,0,1}
pub fn gen_rand_vec(len: usize) -> Vec<i32> {
    let mut rng = rand::thread_rng();
    let mut res: Vec<i32>  = Vec::new();
    for _ in 0..len {res.push(rng.gen_range(-1..=1));}
    res
}

/// Encrypt input vector `m_vec`. According to `mode`, some samples might be trivial.
pub fn encrypt_with_mode(
    m_vec: &Vec<i32>,
    mode: EncrVsTriv,
) -> ParmCiphertext {
    let mut m_flg: Vec<bool> = Vec::new();

    // gen vector of true/false/random flags
    for _ in 0..m_vec.len() {
        match mode {
            EncrVsTriv::ENCR => m_flg.push(true),
            EncrVsTriv::TRIV => m_flg.push(false),
            EncrVsTriv::ENCRTRIV => m_flg.push(rand::random()),
        }
    }

    // return encrypted
    encrypt_with_flags(
        TEST_PARAMS,
        &TEST_PRIV_KEYS,
        &m_vec,
        &m_flg,
    )
}

/// Encrypt input vector `m_vec` at positions given by `m_flags` vector (other samples trivial).
pub fn encrypt_with_flags(
    par: &Params,
    priv_keys: &PrivKeySet,
    m_vec: &Vec<i32>,
    m_flags: &Vec<bool>,
) -> ParmCiphertext {
    let mut res = ParmCiphertext::triv(m_vec.len(), &priv_keys.encoder).expect("ParmCiphertext::triv failed.");

    res.iter_mut().zip(m_vec.iter().zip(m_flags.iter())).for_each(| (ri, (mi, fi)) | {
        let mi_pos = (mi & par.plaintext_mask()) as u32;
        *ri = if *fi {
            LWE::encrypt_uint(&priv_keys.sk, mi_pos, &priv_keys.encoder).expect("LWE::encrypt_uint failed.")
        } else {
            LWE::encrypt_uint_triv(mi_pos, &priv_keys.encoder).expect("LWE::encrypt_uint_triv failed.")
        };
    });

    res
}
