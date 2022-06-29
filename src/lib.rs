
////////////////////////////////////////////////////////////////////////////////
//!
//! # PARMESAN: Parallel-ARithMEticS-on-tfhe-ENcrypted-data
//!
//! *A library for fast parallel arithmetics on TFHE-encrypted data.*
//!
//!  ╭─────────╮
//!  │  P.M.S  │
//!  ╰─────────╯
//!
//! Employs the Concrete Library.
//!
//!  •        •
//!    ▂█████
//!    ██
//!    ██
//!    ▀█████
//!  •        •
//!
////////////////////////////////////////////////////////////////////////////////



use std::error::Error;

//TODO check whether needed
pub use std::fs::{self,File,OpenOptions};
pub use std::path::Path;
pub use std::io::Write;
pub use std::collections::BTreeMap;

#[allow(unused_imports)]
use colored::Colorize;

extern crate chrono;
//~ use chrono::Utc;

extern crate lazy_static;

#[allow(unused_imports)]
use concrete::LWE;

/// Keeps log level for nested time measurements
pub static mut LOG_LVL: u8 = 0;

pub const LOGFILE: &str = "./operations.log";
pub static mut LOG_INITED: bool = false;


// =============================================================================
//
//  Parmesan Modules & Paths
//

// Global modules
#[macro_use]
pub mod misc;
pub mod params;
pub use params::Params;
pub mod ciphertexts;
pub use ciphertexts::{ParmCiphertext, ParmCiphertextExt};
pub mod arithmetics;
pub use arithmetics::ParmArithmetics;

// Userovo modules
pub mod userovo;
pub use userovo::*;
pub use userovo::keys::{PrivKeySet,PubKeySet};

// Cloudovo modules
pub mod cloudovo;
pub use cloudovo::*;
pub use cloudovo::neural_network::{Perceptron, PercType, NeuralNetwork};
pub use cloudovo::scalar_multiplication::*;


// =============================================================================
//
//  Parmesan Structs
//

// -----------------------------------------------------------------------------
//  Userovo

/// # User-side Parmesan
pub struct ParmesanUserovo<'a> {
    pub params: &'a Params,
    priv_keys: PrivKeySet,
}

impl ParmesanUserovo<'_> {
    /// Create an instance of `ParmesanUserovo`
    /// * save immutable reference to params
    /// * generate keys
    pub fn new(params: &Params) -> Result<ParmesanUserovo, Box<dyn Error>> {
        Ok(ParmesanUserovo {
            params,
            priv_keys: PrivKeySet::new(params)?,
        })
    }

    /// Get the Public Key Set
    pub fn export_pub_keys(&self) -> PubKeySet {
        PubKeySet {
            bsk:     &self.priv_keys.bsk,
            ksk:     &self.priv_keys.ksk,
            encoder: &self.priv_keys.encoder,
        }
    }

    /// Encrypt a 64-bit signed integer
    /// * `bits` states how many bits of input `m` are to be encrypted, since this will be public
    /// * least significant bits, including sign, are taken
    pub fn encrypt(
        &self,
        m: i64,
        words: usize,
    ) -> Result<ParmCiphertext, Box<dyn Error>> {   //WISH change to a template for other integer types/lengths, too
        Ok(encryption::parm_encrypt(self.params, &self.priv_keys, m, words)?)
    }

    /// Encrypt a vector of words from alphabet `{-1,0,1}`
    pub fn encrypt_vec(
        &self,
        mv: &Vec<i32>,
    ) -> Result<ParmCiphertext, Box<dyn Error>> {   //WISH change to a template for other integer types/lengths, too
        Ok(encryption::parm_encrypt_vec(self.params, &self.priv_keys, mv)?)
    }

    /// Decrypt ciphertext into a 64-bit signed integer
    pub fn decrypt(&self, c: &ParmCiphertext) -> Result<i64, Box<dyn Error>> {   //WISH change to a template for other integer types/lengths, too
        Ok(encryption::parm_decrypt(self.params, &self.priv_keys, c)?)
    }
}

// -----------------------------------------------------------------------------
//  Cloudovo

/// # Cloud-side Parmesan
pub struct ParmesanCloudovo<'a> {
    pub params: &'a Params,
    pub pub_keys: &'a PubKeySet<'a>,
}

impl ParmesanCloudovo<'_> {

    /// Create an instance of `ParmesanCloudovo`
    pub fn new<'a>(
        params: &'a Params,
        pub_keys: &'a PubKeySet,
    ) -> ParmesanCloudovo<'a> {
        ParmesanCloudovo {
            params,
            pub_keys,
        }
    }
}


// =============================================================================
//
//  Global Variables
//

//TODO this file must be present in project dir, not in lib dir !!
static ASC_12_FILE: &str = "asc-12.yaml";

lazy_static::lazy_static! {
/// Addition-Subtraction Chains for Scalar Multiplication
pub static ref ASC_12: BTreeMap<usize, Vec<AddShift>> = scalar_multiplication::Asc::map_from_yaml(ASC_12_FILE).expect("Asc::map_from_yaml failed.");
}


// =============================================================================
//
//  DEMO Functions
//

// -----------------------------------------------------------------------------
//  Arithmetics Demo

pub fn arith_demo() -> Result<(), Box<dyn Error>> {

    // not used at the moment
    #[cfg(not(feature = "sequential"))]
    infobox!("Parallel Arithmetics DEMO ({} threads)", rayon::current_num_threads());
    #[cfg(feature = "sequential")]
    infobox!("Sequential Arithmetics DEMO");


    // =================================
    //  Initialization

    // ---------------------------------
    //  Global Scope
    let par = &params::PARM80__PI_5__D_20;   //  80    112    128

    // ---------------------------------
    //  Userovo Scope
    let pu = ParmesanUserovo::new(par)?;
    let pub_k = pu.export_pub_keys();

    const DEMO_BITLEN: usize =  28;
    const DEMO_N_MSGS: usize =   3;
    const DEMO_ADC:    i64   = -20;

    // ---------------------------------
    //  Cloudovo Scope
    let pc = ParmesanCloudovo::new(
        par,
        &pub_k,
    );


    // =================================
    //  U: Encryption

    // for most operations
    let m: [i64; DEMO_N_MSGS] = [
         0b01111110110010010011100110111011,
         0b00110010001111100110111100100000,
        -0b01000100001010010111100000010101,
    ];
    let mut m_as: [i64; DEMO_N_MSGS] = [0,0,0];
    // for multiplication
    let m_x1 : i64 =  0b1;
    let m_y1 : i64 = -0b1;
    let m_x4 : i64 =  0b1110;                   //    14
    let m_y4 : i64 =  0b1001;                   //     9    ->               126
    let m_x8 : i64 =  0b10010111;               //   151
    let m_y8 : i64 =  0b10111010;               //   186    ->             28086
    let m_x16: i64 =  0b1110000101101011;        // 57707
    let m_y16: i64 =  0b1100011010100001;        // 50849    ->       2934343243
    let m_x17: i64 =  0b11111011001001001;       // 128585
    let m_y17: i64 =  0b11001000111110011;       // 102899    ->     13231267915
    let m_x32: i64 =  0b01100110010010111011011001100110;   // 1716237926
    let m_y32: i64 =  0b01001011100111010100110001010100;   // 1268599892   ->  2177219247569903992 which fits 63 bits (i64)
                                                            //                  AND it does not happen that some 1 would be at such a position due to redundant repre

    // encrypt all values
    let mut c: [ParmCiphertext; DEMO_N_MSGS] = [
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
    ];
    for (ci, (mi, mi_as)) in c.iter_mut().zip(m.iter().zip(m_as.iter_mut())) {
        *ci = pu.encrypt(*mi, DEMO_BITLEN)?;
        *mi_as = (*mi).signum() * ((*mi).abs() % (1 << DEMO_BITLEN));
    }
    let cx1 = pu.encrypt(m_x1,   1)?;
    let cy1 = pu.encrypt(m_y1,   1)?;
    let cx4 = pu.encrypt(m_x4,   4)?;
    let cy4 = pu.encrypt(m_y4,   4)?;
    let cx8 = pu.encrypt(m_x8,   8)?;
    let cy8 = pu.encrypt(m_y8,   8)?;
    let cx16= pu.encrypt(m_x16, 16)?;
    let cy16= pu.encrypt(m_y16, 16)?;
    let cx17= pu.encrypt(m_x17, 17)?;
    let cy17= pu.encrypt(m_y17, 17)?;
    let cx32= pu.encrypt(m_x32, 32)?;
    let cy32= pu.encrypt(m_y32, 32)?;

    // print message
    let mut intro_text = format!("{} messages ({} bits taken)", String::from("User:").bold().yellow(), DEMO_BITLEN);
    for (i, (mi, mi_as)) in m.iter().zip(m_as.iter()).enumerate() {
        intro_text = format!("{}\nm_{}  = {}{:032b} ({})", intro_text, i, if *mi >= 0 {" "} else {"-"}, mi.abs(), mi_as);
    }
    intro_text = format!("{}\nx_1  = {}{:01b} ({})",  intro_text, if m_x1  >= 0 {" "} else {"-"}, m_x1.abs(),  m_x1 );
    intro_text = format!("{}\ny_1  = {}{:01b} ({})",  intro_text, if m_y1  >= 0 {" "} else {"-"}, m_y1.abs(),  m_y1 );
    intro_text = format!("{}\nx_4  = {}{:04b} ({})",  intro_text, if m_x4  >= 0 {" "} else {"-"}, m_x4.abs(),  m_x4 );
    intro_text = format!("{}\ny_4  = {}{:04b} ({})",  intro_text, if m_y4  >= 0 {" "} else {"-"}, m_y4.abs(),  m_y4 );
    intro_text = format!("{}\nx_8  = {}{:08b} ({})",  intro_text, if m_x8  >= 0 {" "} else {"-"}, m_x8.abs(),  m_x8 );
    intro_text = format!("{}\ny_8  = {}{:08b} ({})",  intro_text, if m_y8  >= 0 {" "} else {"-"}, m_y8.abs(),  m_y8 );
    intro_text = format!("{}\nx_16 = {}{:016b} ({})", intro_text, if m_x16 >= 0 {" "} else {"-"}, m_x16.abs(), m_x16);
    intro_text = format!("{}\ny_16 = {}{:016b} ({})", intro_text, if m_y16 >= 0 {" "} else {"-"}, m_y16.abs(), m_y16);
    intro_text = format!("{}\nx_17 = {}{:017b} ({})", intro_text, if m_x17 >= 0 {" "} else {"-"}, m_x17.abs(), m_x17);
    intro_text = format!("{}\ny_17 = {}{:017b} ({})", intro_text, if m_y17 >= 0 {" "} else {"-"}, m_y17.abs(), m_y17);
    intro_text = format!("{}\nx_32 = {}{:032b} ({})", intro_text, if m_x32 >= 0 {" "} else {"-"}, m_x32.abs(), m_x32);
    intro_text = format!("{}\ny_32 = {}{:032b} ({})", intro_text, if m_y32 >= 0 {" "} else {"-"}, m_y32.abs(), m_y32);
    infoln!("{}", intro_text);


    // =================================
    //  C: Evaluation

    //~ // BS only
    //~ for _ in 0..10 {
        //~ simple_duration!(
            //~ ["Programmable bootstrapping"],
            //~ [
                //~ // positive identity is defined for any pi
                //~ let _c = pbs::pos_id(&pc.pub_keys, &c[0][0])?;
            //~ ]
        //~ );
    //~ }                                                  .

    //~ // testing PBS
    //~ for m_triv in 0 .. ((1 << 5) + 1) {
        //~ let c_triv = LWE::encrypt_uint_triv(m_triv, pc.pub_keys.encoder)?;
        //~ let c_triv_sq1 = pbs::a_2__pi_5(pc.pub_keys, &c_triv)?;
        //~ let m_triv_sq1 = c_triv_sq1.decrypt_uint_triv()?;
        //~ println!("|X| ≥ 2\n\t  X = {}\n\tres = {}", m_triv, m_triv_sq1);
    //~ }
    //~ return Ok(());

    //~ //DBG BEGIN
    //~ for pos in 0..10 {
        //~ let cr = ParmArithmetics::round_at(&pc, &c[0], pos);
        //~ let mr = ParmArithmetics::round_at(&pc, &m[0], pos);
        //~ let dr = pu.decrypt(&cr)?;
        //~ println!("Round  0b{:032b} at {}:\nplain: 0b{:032b}\n decr: 0b{:032b}\n---", m[0], pos, mr, dr);
    //~ }
    //~ return Ok(());
    //~ //DBG END

    let c_add  = ParmArithmetics::add(&pc, &c[0], &c[1]);
    let c_sub  = ParmArithmetics::sub(&pc, &c[1], &c[0]);
    let c_adc  = ParmArithmetics::add_const(&pc,  &c[0], DEMO_ADC);
    let c_sgn  = ParmArithmetics::sgn(&pc, &c[2]       );
    let c_max  = ParmArithmetics::max(&pc, &c[1], &c[0]);

    let c_xy1  = ParmArithmetics::mul(&pc, &cx1,  &cy1 );
    let c_xy4  = ParmArithmetics::mul(&pc, &cx4,  &cy4 );
    let c_xy8  = ParmArithmetics::mul(&pc, &cx8,  &cy8 );
    let c_xy16 = ParmArithmetics::mul(&pc, &cx16, &cy16);
    let c_xy17 = ParmArithmetics::mul(&pc, &cx17, &cy17);
    let c_xy32 = ParmArithmetics::mul(&pc, &cx32, &cy32);

    let c_xx4  = ParmArithmetics::squ(&pc, &cx4 );
    let c_xx8  = ParmArithmetics::squ(&pc, &cx8 );
    let c_xx16 = ParmArithmetics::squ(&pc, &cx16);
    let c_xx17 = ParmArithmetics::squ(&pc, &cx17);
    let c_xx32 = ParmArithmetics::squ(&pc, &cx32);

    let c_n121x16 = ParmArithmetics::scalar_mul(&pc, -121, &cx16);
    let c_n128x16 = ParmArithmetics::scalar_mul(&pc, -128, &cx16);
    let c_p3x16   = ParmArithmetics::scalar_mul(&pc,    3, &cx16);


    // =================================
    //  U: Decryption

    let m_add  = pu.decrypt(&c_add )?;
    let m_sub  = pu.decrypt(&c_sub )?;
    let m_adc  = pu.decrypt(&c_adc )?;
    let m_sgn  = pu.decrypt(&c_sgn )?;
    let m_max  = pu.decrypt(&c_max )?;

    let m_xy1  = pu.decrypt(&c_xy1 )?;
    let m_xy4  = pu.decrypt(&c_xy4 )?;
    let m_xy8  = pu.decrypt(&c_xy8 )?;
    let m_xy16 = pu.decrypt(&c_xy16)?;
    let m_xy17 = pu.decrypt(&c_xy17)?;
    let m_xy32 = pu.decrypt(&c_xy32)?;

    let m_xx4  = pu.decrypt(&c_xx4 )?;
    let m_xx8  = pu.decrypt(&c_xx8 )?;
    let m_xx16 = pu.decrypt(&c_xx16)?;
    let m_xx17 = pu.decrypt(&c_xx17)?;
    let m_xx32 = pu.decrypt(&c_xx32)?;

    let m_n121x16 = pu.decrypt(&c_n121x16)?;
    let m_n128x16 = pu.decrypt(&c_n128x16)?;
    let m_p3x16   = pu.decrypt(&c_p3x16  )?;

    let mut summary_text = format!("{} results", String::from("User:").bold().yellow());

    summary_text = format!("{}\nm_0 + m_1     = {:12} :: {} (exp. {})", summary_text,
                            m_add,
                            if m_as[0] + m_as[1] == m_add {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            m_as[0] + m_as[1]
    );
    summary_text = format!("{}\nm_1 - m_0     = {:12} :: {} (exp. {})", summary_text,
                            m_sub,
                            if m_as[1] - m_as[0] == m_sub {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            m_as[1] - m_as[0]
    );
    summary_text = format!("{}\nm_0 + {:3}     = {:12} :: {} (exp. {})", summary_text,
                            DEMO_ADC, m_adc,
                            if m_as[0] + (DEMO_ADC as i64) == m_adc {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            m_as[0] + (DEMO_ADC as i64)
    );
    summary_text = format!("{}\nsgn(m_2)      = {:12} :: {}", summary_text,
                            m_sgn,
                            if m_as[2].signum() == m_sgn {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
    );
    summary_text = format!("{}\nmax{{m_1, m_0}} = {:12} :: {} (exp. {})", summary_text,
                            m_max,
                            if std::cmp::max(m_as[1], m_as[0]) == m_max {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            std::cmp::max(m_as[1], m_as[0])
    );

    summary_text = format!("{}\nx_1 × y_1     = {:12} :: {} (exp. {})", summary_text,
                            m_xy1,
                            if m_x1 * m_y1 == m_xy1 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            m_x1 * m_y1
    );
    summary_text = format!("{}\nx_4 × y_4     = {:12} :: {} (exp. {})", summary_text,
                            m_xy4,
                            if m_x4 * m_y4 == m_xy4 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            m_x4 * m_y4
    );
    summary_text = format!("{}\nx_8 × y_8     = {:12} :: {} (exp. {})", summary_text,
                            m_xy8,
                            if m_x8 * m_y8 == m_xy8 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            m_x8 * m_y8
    );
    summary_text = format!("{}\nx_16 × y_16   = {:12} :: {} (exp. {})", summary_text,
                            m_xy16,
                            if m_x16 * m_y16 == m_xy16 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            m_x16 * m_y16
    );
    summary_text = format!("{}\nx_17 × y_17   = {:12} :: {} (exp. {})", summary_text,
                            m_xy17,
                            if m_x17 * m_y17 == m_xy17 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            m_x17 * m_y17
    );
    summary_text = format!("{}\nx_32 × y_32   = {:24} :: {} (exp. {})", summary_text,
                            m_xy32,
                            if m_x32 * m_y32 == m_xy32 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            m_x32 * m_y32
    );

    summary_text = format!("{}\nx_4  ^ 2      = {:12} :: {} (exp. {})", summary_text,
                            m_xx4,
                            if m_xx4 == m_x4 * m_x4 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            m_x4 * m_x4
    );
    summary_text = format!("{}\nx_8  ^ 2      = {:12} :: {} (exp. {})", summary_text,
                            m_xx8,
                            if m_xx8 == m_x8 * m_x8 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            m_x8 * m_x8
    );
    summary_text = format!("{}\nx_16 ^ 2      = {:12} :: {} (exp. {})", summary_text,
                            m_xx16,
                            if m_xx16 == m_x16 * m_x16 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            m_x16 * m_x16
    );
    summary_text = format!("{}\nx_17 ^ 2      = {:12} :: {} (exp. {})", summary_text,
                            m_xx17,
                            if m_xx17 == m_x17 * m_x17 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            m_x17 * m_x17
    );
    summary_text = format!("{}\nx_32 ^ 2      = {:24} :: {} (exp. {})", summary_text,
                            m_xx32,
                            if m_xx32 == m_x32 * m_x32 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            m_x32 * m_x32
    );

    summary_text = format!("{}\n-121 × x_16   = {:12} :: {} (exp. {})", summary_text,
                            m_n121x16,
                            if -121 * m_x16 == m_n121x16 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            -121 * m_x16
    );
    summary_text = format!("{}\n-128 × x_16   = {:12} :: {} (exp. {})", summary_text,
                            m_n128x16,
                            if -128 * m_x16 == m_n128x16 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            -128 * m_x16
    );
    summary_text = format!("{}\n 3 × x_16     = {:12} :: {} (exp. {})", summary_text,
                            m_p3x16,
                            if 3 * m_x16 == m_p3x16 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            3 * m_x16
    );

    infoln!("{}", summary_text);


    // =================================
    infobox!("Finished Arithmetics DEMO");
    // =================================

    Ok(())
}

// -----------------------------------------------------------------------------
//  NN Eval Demo

pub fn nn_demo() -> Result<(), Box<dyn Error>> {

    // not used at the moment
    #[cfg(not(feature = "sequential"))]
    infobox!("Parallel Neural Network DEMO ({} threads)", rayon::current_num_threads());
    #[cfg(feature = "sequential")]
    infobox!("Sequential Neural Network DEMO");


    // =================================
    //  Initialization

    // ---------------------------------
    //  Global Scope
    let par = &params::PARM80__PI_5__D_20;   //  80    112    128

    // ---------------------------------
    //  Userovo Scope
    let pu = ParmesanUserovo::new(par)?;
    let pub_k = pu.export_pub_keys();

    const INPUT_BITLEN: usize =   11;

    // ---------------------------------
    //  Cloudovo Scope
    let pc = ParmesanCloudovo::new(
        par,
        &pub_k,
    );


    // =================================
    //  U: Encryption

    // NN input layer
    let m_in: Vec<i64> = vec![
        -0b1000110000,
         0b100000001,
         0b10000111110,
        -0b111010100,
        -0b1000111110,
        -0b1100101110,
         0b111001,
        -0b101000011,
         0b1001,
        -0b100111101,
         0b10000110,
        -0b1101010,
        -0b11001,
         0b100100,
        -0b11000,
        -0b10001110,
    ];

    // encrypt all values
    let mut c_in: Vec<ParmCiphertext> = vec![
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
    ];
    for (ci, mi) in c_in.iter_mut().zip(m_in.iter()) {
        *ci = pu.encrypt(*mi, INPUT_BITLEN)?;
    }

    // print input layer
    let mut intro_text = format!("{}: input layer ({} elements)", String::from("User").bold().yellow(), m_in.len());
    for (i, mi) in m_in.iter().enumerate() {
        intro_text = format!("{}\nIN[{}] = {}{:08b} ({:4})", intro_text, i, if *mi >= 0 {" "} else {"-"}, (*mi).abs(), mi);
    }
    infoln!("{}", intro_text);


    // =================================
    //  C: Evaluation

        simple_duration!(
            ["NN eval"],
            [
    let c_out       = arrhythmia_nn().eval(&pc, &c_in);   // demo_nn   arrhythmia_nn
            ]
        );
    //DBG
    println!("In plain domain:");
        simple_duration!(
            ["NN eval (plain)"],
            [
    let m_out_plain = arrhythmia_nn().eval(&pc, &m_in);
            ]
        );


    // =================================
    //  U: Decryption

    let mut m_out_homo = Vec::new();
    for ci in c_out {
        m_out_homo.push(pu.decrypt(&ci)?);
    }

    let mut summary_text = format!("{}: output layer ({} elements)", String::from("User").bold().yellow(), m_out_plain.len());

    //~ for (i, mpi) in m_out_plain.iter().enumerate() {
        //~ summary_text = format!("{}\nOUT[{}] = {:6}", summary_text,
                                //~ i, mpi
        //~ );
    //~ }
    for (i, (mhi, mpi)) in m_out_homo.iter().zip(m_out_plain.iter()).enumerate() {
        summary_text = format!("{}\nOUT[{}] = {:6} :: {} (exp. {})", summary_text,
                                i, mhi,
                                if mhi == mpi {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                                mpi
        );
    }

    infoln!("{}", summary_text);


    // =================================
    infobox!("Finished Neural Network DEMO");
    // =================================

    Ok(())
}

/// Get a demo neural network
///
/// * n.b., since Vec is an allocated structure, it cannot be in const/static.
pub fn demo_nn() -> NeuralNetwork {
    NeuralNetwork {
        layers: vec![
            vec![
                Perceptron {
                    t: PercType::MAX,
                    w: vec![1,-2,-2,],
                    b: 2,
                },
                Perceptron {
                    t: PercType::LIN,
                    w: vec![1,3,-1,],
                    b: -5,
                },
                Perceptron {
                    t: PercType::ACT,
                    w: vec![1,3,-1,],
                    b: 3,
                },
            ],
        ],
        n_inputs: 3,
    }
}

/// Get a real-world neural network for arrhythmia classification
pub fn arrhythmia_nn() -> NeuralNetwork {
    NeuralNetwork {
        layers: vec![
            vec![
                Perceptron {t: PercType::ACT, w: vec![-294, -209, -53, -79, -176, -53, -105, -87, -157, -356, -71, -324, -300, 194, 403, -39], b: 183296},
                Perceptron {t: PercType::ACT, w: vec![-53, -274, 34, 201, 331, 203, 114, 19, -123, 13, -212, -247, -64, 303, -176, -210], b: 405504},
                Perceptron {t: PercType::ACT, w: vec![-1, -106, 287, 45, -166, 33, 392, 226, 83, 111, 151, -170, 527, 116, 216, 382], b: -1064960},
                Perceptron {t: PercType::ACT, w: vec![177, 183, 247, -195, -243, 10, 106, 476, 296, -344, -20, -394, -445, -48, 378, -58], b: 148480},
                Perceptron {t: PercType::ACT, w: vec![382, 149, -201, -241, 255, 386, 76, 57, -458, -77, -170, 10, -558, -807, 32, -46], b: -286720},
                Perceptron {t: PercType::ACT, w: vec![-219, 538, -1077, -281, -129, 347, -173, 537, 448, -83, -482, -264, 206, -127, 222, -237], b: 712704},
                Perceptron {t: PercType::ACT, w: vec![-230, -102, 308, -117, -838, 445, -614, -88, 391, 14, -1033, -59, 427, 466, 203, -4], b: 626688},
                Perceptron {t: PercType::ACT, w: vec![-9, 547, -37, 779, -298, 343, 116, 429, -1226, -339, 66, -276, -137, -484, 143, -514], b: 1720320},
                Perceptron {t: PercType::ACT, w: vec![-483, 996, -610, -795, -1020, 1251, -389, 793, 64, 270, -924, 145, -328, 363, 612, -562], b: 114688},
                Perceptron {t: PercType::ACT, w: vec![217, -570, -442, -789, 343, -415, 697, 138, 395, -195, -210, -377, 617, -651, 391, -1001], b: -436224},
                Perceptron {t: PercType::ACT, w: vec![225, -18, 427, 97, 151, -394, -724, -66, -405, -655, 23, 77, -122, -795, -1002, 286], b: -462848},
                Perceptron {t: PercType::ACT, w: vec![297, 533, -588, 637, -364, -138, 757, 413, 102, 440, -499, -339, 361, -469, 183, 133], b: -405504},
                Perceptron {t: PercType::ACT, w: vec![-376, 812, 150, -269, 476, -459, 431, -121, 797, 77, 161, 547, -298, -362, -370, 9], b: -1957888},
                Perceptron {t: PercType::ACT, w: vec![-330, -143, -123, -815, -433, -73, -174, 50, 223, 185, 233, 338, 241, 42, 29, 706], b: 92672},
                Perceptron {t: PercType::ACT, w: vec![-469, -470, -11, -495, 322, -262, 499, -103, 183, 1144, -112, 565, 768, -1038, -348, 332], b: 2916352},
                Perceptron {t: PercType::ACT, w: vec![517, -562, 92, 322, 16, -209, -821, -412, -139, 402, 566, 203, -951, -809, 791, -162], b: -823296},
                Perceptron {t: PercType::ACT, w: vec![691, -245, 315, -416, -273, 802, -174, -908, 89, -84, -747, -638, -660, 535, 950, 110], b: -501760},
                Perceptron {t: PercType::ACT, w: vec![216, -603, -2054, -96, 1062, 137, -94, 0, -161, -59, -306, -372, -267, -681, -230, -357], b: -278528},
                Perceptron {t: PercType::ACT, w: vec![-626, -693, 494, -283, 1140, -177, -103, 447, 476, -150, -745, -654, 151, -758, 1081, 246], b: 1253376},
                Perceptron {t: PercType::ACT, w: vec![971, -882, 1381, -459, -430, -77, -805, -456, -11, 187, 893, -629, -130, -1585, 725, 188], b: 1089536},
                Perceptron {t: PercType::ACT, w: vec![10, 320, 530, 518, -991, 60, -1144, 719, -98, -434, -685, 1196, -1505, 984, 175, -1026], b: -733184},
                Perceptron {t: PercType::ACT, w: vec![-759, -194, -1284, 994, -759, 784, -342, -504, -316, 532, 2104, -1107, 821, -1525, 851, -79], b: 473088},
                Perceptron {t: PercType::ACT, w: vec![-1211, -523, 854, -922, 363, 406, 741, -647, 791, -1325, 388, 214, 52, 764, -605, 773], b: 1114112},
                Perceptron {t: PercType::ACT, w: vec![712, -739, -213, -655, -908, 133, -307, -836, -893, 634, 521, -164, 570, -202, -1519, -198], b: -362496},
                Perceptron {t: PercType::ACT, w: vec![665, 701, -703, -418, -1229, 520, 399, 101, 187, 870, 799, -314, 597, 382, 104, 719], b: 978944},
                Perceptron {t: PercType::ACT, w: vec![115, -17, 685, -150, -762, -74, 579, 478, -300, 1814, 1082, -1974, 1287, -992, -1367, 711], b: -103424},
                Perceptron {t: PercType::ACT, w: vec![-1389, -1088, 129, 521, 501, -671, 298, -1276, 221, 788, 295, -1453, 976, 827, -101, 1947], b: 720896},
                Perceptron {t: PercType::ACT, w: vec![-22, 483, 1104, 700, -324, 1281, 541, -1453, -424, -1890, 837, 1251, -137, -523, -430, -474], b: -1523712},
                Perceptron {t: PercType::ACT, w: vec![682, 170, -722, 980, 476, -65, 731, 1081, 527, -361, -272, 944, 414, -539, 671, 858], b: 286720},
                Perceptron {t: PercType::ACT, w: vec![-1550, 13, -367, 682, -843, -927, -374, -1753, 306, -904, 628, 77, -74, 696, 23, 2092], b: 1507328},
                Perceptron {t: PercType::ACT, w: vec![593, 636, 299, 939, 637, 96, 564, -661, 112, 475, 426, -1055, 196, 44, 809, -366], b: -81920},
                Perceptron {t: PercType::ACT, w: vec![-219, 1366, -26, 81, 522, -127, -359, -749, -852, 329, 418, 1293, 173, 592, 382, 134], b: 86528},
                Perceptron {t: PercType::ACT, w: vec![-6, -138, 46, -538, -205, 1593, 419, 348, -712, -575, 377, 426, -448, 515, -263, 1371], b: -815104},
                Perceptron {t: PercType::ACT, w: vec![-511, 56, -152, 715, 503, 2273, 1568, 408, 763, 1563, -477, -223, 314, -643, -776, 838], b: 397312},
                Perceptron {t: PercType::ACT, w: vec![-588, -287, 430, 847, -1679, -142, 39, 123, -971, -841, 597, -567, 584, -1204, 885, 782], b: 544768},
                Perceptron {t: PercType::ACT, w: vec![-64, 29, 150, 1, 1977, 1459, -613, -972, -144, -955, 201, 1217, 620, 1, 81, 1355], b: 364544},
                Perceptron {t: PercType::ACT, w: vec![-677, -414, -400, -278, -656, 404, -6, -52, -186, 1456, 667, 313, -796, -1124, 808, -34], b: 4192},
                Perceptron {t: PercType::ACT, w: vec![-891, 1180, -686, 795, -126, 674, -826, 599, 616, 439, -337, 733, 1356, 1182, -333, -178], b: -897024},
            ],
            vec![
                Perceptron {t: PercType::LIN, w: vec![-615, 263, 580, -177, 465, 577, -527, -336, -460, 295, 736, -981, -838, 484, -72, -738, -604, -741, 10, 300, 293, 215, -1064, 15, -1007, -188, -1061, -261, 225, 123, 680, 397, 179, 307, -246, -192, -814, 448], b: 12549357568},
                Perceptron {t: PercType::LIN, w: vec![404, -1123, -124, -388, 154, -240, 206, 13, 57, -667, 212, -368, -10, -530, -2444, 269, 400, 140, 166, 25, -651, -328, -4, -98, -4093, -1958, 434, 399, -89, 217, -539, -547, -103, 345, -692, -231, -527, 820], b: 457179136},
                Perceptron {t: PercType::LIN, w: vec![-226, -223, 418, -482, -84, 118, -47, 276, 902, 695, -423, -785, 688, 908, 136, -601, -211, 28, -872, -3186, -608, 177, 147, 727, -53, -339, 2, 197, -814, -1400, 81, -2926, 241, 111, -590, 613, 194, 78], b: -6878658560},
                Perceptron {t: PercType::LIN, w: vec![-519, -2467, -404, -1478, -2932, 127, 465, -1091, -375, 93, 680, -875, 324, 104, 188, 220, 193, -999, -1704, 404, 374, -1, -2183, -539, 388, 409, -2485, 258, -1245, -906, -7, 251, 360, -732, -1633, -141, -984, 360], b: -12683575296},
                Perceptron {t: PercType::LIN, w: vec![-25, -177, -342, 481, -1381, 100, -318, 132, -334, 235, 124, -1344, -946, 223, -48, -1292, -1793, 248, 516, -925, -1107, 280, -752, -1690, 456, -263, -43, 687, -758, 25, -106, -93, 434, -299, -1354, 255, 307, 182], b: -10603200512},
                Perceptron {t: PercType::LIN, w: vec![-1671, -1853, 11, -573, -154, -128, 604, -2860, -3195, 172, -398, 924, -268, 51, -8, -1396, -1284, -71, 145, -414, 136, -2041, 220, 243, 513, -205, -606, -311, 26, -452, -1624, 8, -565, -176, 211, 168, 284, -649], b: -13555990528},
                Perceptron {t: PercType::LIN, w: vec![-792, -7717, -681, 362, -265, -386, 382, 286, 195, -2614, -533, 259, -270, 534, -122, 597, 392, -312, 616, 368, 632, -384, -79, 0, 778, 40, -408, -412, -40, -1077, -93, 1236, -479, 217, 678, 27, -840, 144], b: -2852126720},
                Perceptron {t: PercType::LIN, w: vec![377, -2930, -809, 427, 767, 267, 332, 187, 408, -23, -574, -838, -275, 319, -515, -369, 41, -3256, -541, 346, 934, -1248, 295, -77, -293, -1621, 65, 602, -55, -402, -197, -1001, -406, 132, 1014, 300, -126, -125], b: -24024973312},
                Perceptron {t: PercType::LIN, w: vec![315, -888, -4, 1160, 778, -288, -136, 55, 425, -217, -1, -162, -1346, 372, -708, -1792, -1, 0, -429, -610, -511, 428, 189, -386, 25, 205, 342, 53, 218, 73, 307, -357, -109, 149, -478, 875, -1597, 365], b: 26038239232},
                Perceptron {t: PercType::LIN, w: vec![-206, 169, -1167, -30, 154, 223, -1750, -11, -2434, 122, 120, 40, -231, -295, 115, -186, -133, 52, 127, 467, -495, 770, -100, -1737, -1095, -311, -91, 325, -49, -470, -1336, 418, 697, -210, -1576, -988, -124, 917], b: 9126805504},
                Perceptron {t: PercType::LIN, w: vec![-2574, 150, -1189, -816, -963, -31, 249, 27, -307, 657, -470, -948, -1000, 196, 249, -2730, 540, 165, 538, -1110, -464, -734, -521, 157, 859, 287, 919, 2, -324, 599, -165, -1025, 834, -328, 316, 1540, 154, 117], b: 12482248704},
                Perceptron {t: PercType::LIN, w: vec![127, -2362, -732, -461, -361, -404, 254, 445, 261, -987, -841, -197, -608, -1459, 437, 456, -240, -1632, 549, -2202, -1136, 141, 427, 106, -111, 145, -609, -1530, -1269, 837, 138, -5, -207, -459, 311, -121, -474, 336], b: -20401094656},
                Perceptron {t: PercType::LIN, w: vec![-686, 570, 362, 532, -777, 188, 374, -467, -313, 292, -111, -376, 965, -1389, -1414, -435, 810, 491, -449, 82, 56, -194, 108, 455, 266, -283, 45, 278, 326, -170, 235, 104, -690, 736, -259, -118, -2024, 337], b: 5402263552},
                Perceptron {t: PercType::LIN, w: vec![116, -229, -170, 419, -143, 163, -4, -321, -1494, -60, -673, 173, -1761, 297, 1584, 220, -573, 206, 217, -726, 98, -564, -582, 711, 47, -143, -1705, -317, -354, -3498, -366, 514, 537, -3374, -160, 143, 35, 839], b: -19327352832},
                Perceptron {t: PercType::LIN, w: vec![917, 140, 79, 73, -95, -836, -425, 463, -2951, -108, 606, 515, -604, -264, 10, 1089, 323, -698, 291, 270, 92, 398, -857, -511, -687, 228, 116, 162, 129, -751, 578, -773, 1093, 139, -393, 427, 117, -649], b: 9261023232},
                Perceptron {t: PercType::LIN, w: vec![189, -772, 434, 314, -39, -487, -175, -225, 264, -1336, -861, -157, -119, 361, 403, -112, 134, -58, 66, -113, 136, -776, 300, -1854, 193, 387, 400, 190, -111, 63, -937, 193, -1, -839, -34, -173, -221, -1085], b: -2097152000},
            ],
        ],
        n_inputs: 16,
    }
}
