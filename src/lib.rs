
////////////////////////////////////////////////////////////////////////////////
//!
//! # PARMESAN: Parallel-ARithMEticS-on-tfhe-ENcrypted-data
//!
//! *A library for fast parallel arithmetics on TFHE-encrypted data.*
//!
////////////////////////////////////////////////////////////////////////////////



use std::error::Error;

#[allow(unused_imports)]
use colored::Colorize;
use concrete::LWE;

/// Keeps log level for nested time measurements
static mut LOG_LVL: u8 = 0;


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
pub use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};

// Userovo modules
pub mod userovo;
pub use userovo::*;
pub use userovo::keys::{PrivKeySet,PubKeySet};

// Cloudovo modules
pub mod cloudovo;
pub use cloudovo::*;


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
        bits: usize,
    ) -> Result<ParmCiphertext, Box<dyn Error>> {   //WISH change to a template for other integer types/lengths, too
        Ok(encryption::parm_encrypt(self.params, &self.priv_keys, m, bits)?)
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
    pub_keys: &'a PubKeySet<'a>,
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
//  Parmesan Arithmetics
//

/// Parmesan Arithmetic Trait
pub trait ParmArithmetic {
    /// Addition: `X + Y`
    fn add(
        pc: &ParmesanCloudovo,
        x: &Self,
        y: &Self,
    ) -> Self;

    /// Subtraction: `X - Y`
    fn sub(
        pc: &ParmesanCloudovo,
        x: &Self,
        y: &Self,
    ) -> Self;

    /// Scalar multiplication (by an integer): `k·X`
    fn scalar_mul(
        pc: &ParmesanCloudovo,
        k: i32,
        x: &Self,
    ) -> Self;

    /// Signum: `sgn(X)`
    fn sgn(
        pc: &ParmesanCloudovo,
        x: &Self,
    ) -> Self;

    /// Maximum: `max{X, Y}`
    fn max(
        pc: &ParmesanCloudovo,
        x: &Self,
        y: &Self,
    ) -> Self;

    /// Multiplication: `X × Y`
    fn mul(
        pc: &ParmesanCloudovo,
        x: &Self,
        y: &Self,
    ) -> Self;
}

impl ParmArithmetic for i32 {
    fn add(
        pc: &ParmesanCloudovo,
        x: &i32,
        y: &i32,
    ) -> i32 {x + y}

    fn sub(
        pc: &ParmesanCloudovo,
        x: &i32,
        y: &i32,
    ) -> i32 {x - y}

    fn scalar_mul(
        pc: &ParmesanCloudovo,
        k: i32,
        x: &i32,
    ) -> i32 {k * x}

    fn sgn(
        pc: &ParmesanCloudovo,
        x: &i32,
    ) -> i32 {x.signum()}

    fn max(
        pc: &ParmesanCloudovo,
        x: &i32,
        y: &i32,
    ) -> i32 {std::cmp::max(*x, *y)}

    fn mul(
        pc: &ParmesanCloudovo,
        x: &i32,
        y: &i32,
    ) -> i32 {x * y}
}

impl ParmArithmetic for ParmCiphertext {
    fn add(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
        y: &ParmCiphertext,
    ) -> ParmCiphertext {
        addition::add_sub_impl(
            true,
            pc.pub_keys,
            x,
            y,
        ).expect("ParmArithmetic::add failed.")
    }

    fn sub(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
        y: &ParmCiphertext,
    ) -> ParmCiphertext {
        addition::add_sub_impl(
            false,
            pc.pub_keys,
            x,
            y,
        ).expect("ParmArithmetic::sub failed.")
    }

    fn scalar_mul(
        pc: &ParmesanCloudovo,
        k: i32,
        x: &ParmCiphertext,
    ) -> ParmCiphertext {
        scalar_multiplication::scalar_mul_impl(
            pc.params,
            pc.pub_keys,
            k,
            x,
        ).expect("ParmArithmetic::scalar_mul failed.")
    }

    fn sgn(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
    ) -> ParmCiphertext {
        signum::sgn_impl(
            pc.params,
            pc.pub_keys,
            x,
        ).expect("ParmArithmetic::sgn failed.")
    }

    fn max(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
        y: &ParmCiphertext,
    ) -> ParmCiphertext {
        maximum::max_impl(
            pc.params,
            pc.pub_keys,
            x,
            y,
        ).expect("ParmArithmetic::max failed.")
    }

    fn mul(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
        y: &ParmCiphertext,
    ) -> ParmCiphertext {
        multiplication::mul_impl(
            pc.pub_keys,
            x,
            y,
        ).expect("ParmArithmetic::mul failed.")
    }
}


// =============================================================================
//
//  Global Functions
//

// -----------------------------------------------------------------------------
//  Arithmetics Demo

pub fn arith_demo() -> Result<(), Box<dyn Error>> {

    // move to Cloudovo initialization (makes no sense at user, but now I want to have it on the top)
    #[cfg(not(feature = "sequential"))]
    infobox!("Parallel ({} threads)", rayon::current_num_threads());
    #[cfg(feature = "sequential")]
    infobox!("Sequential");


    // =================================
    //  Initialization

    // ---------------------------------
    //  Global Scope
    let par = &params::PARM90__PI_5__D_20__LEN_32;   //     PARM90__PI_5__D_20__LEN_32      PARMXX__TRIVIAL

    // ---------------------------------
    //  Userovo Scope
    let pu = ParmesanUserovo::new(par)?;
    let pub_k = pu.export_pub_keys();

    const DEMO_BITLEN: usize = 12;
    const DEMO_N_MSGS: usize = 3;

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
    let m_y4 : i64 =  0b1001;                   //     9    ->         126
    let m_x8 : i64 =  0b10010111;               //   151
    let m_y8 : i64 =  0b10111010;               //   186    ->       28086
    let m_x16: i64 =  0b110000101101011;        // 24939
    let m_y16: i64 =  0b100011010100001;        // 18081    ->   450922059
    let m_x17: i64 =  0b1111011001001001;       // 63049
    let m_y17: i64 =  0b1001000111110011;       // 37363    ->  2355699787 which is more than 2^31 - 1
    let m_x32: i64 =  0b01100110010010111011011001100110;   // 1716237926
    let m_y32: i64 =  0b01001011100111010100110001010100;   // 1268599892   ->  2177219247569903992 which fits 63 bits (i64)

    // encrypt all values
    let mut c: [ParmCiphertext; DEMO_N_MSGS] = [
        ParmCiphertext::triv(DEMO_BITLEN)?,
        ParmCiphertext::triv(DEMO_BITLEN)?,
        ParmCiphertext::triv(DEMO_BITLEN)?,
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

    let c_add  = ParmArithmetic::add(&pc, &c[0], &c[1]);
    let c_sub  = ParmArithmetic::sub(&pc, &c[1], &c[0]);
    let c_sgn  = ParmArithmetic::sgn(&pc, &c[2]       );
    let c_max  = ParmArithmetic::max(&pc, &c[1], &c[0]);
    let c_xy1  = ParmArithmetic::mul(&pc, &cx1,  &cy1 );
    let c_xy4  = ParmArithmetic::mul(&pc, &cx4,  &cy4 );
    let c_xy8  = ParmArithmetic::mul(&pc, &cx8,  &cy8 );
    let c_xy16 = ParmArithmetic::mul(&pc, &cx16, &cy16);
    let c_xy17 = ParmArithmetic::mul(&pc, &cx17, &cy17);
    let c_xy32 = ParmArithmetic::mul(&pc, &cx32, &cy32);

    let c_n161x16 = ParmArithmetic::scalar_mul(&pc, -161, &cx16);
    let c_n128x16 = ParmArithmetic::scalar_mul(&pc, -128, &cx16);
    let c_p3x16   = ParmArithmetic::scalar_mul(&pc,    3, &cx16);


    // =================================
    //  U: Decryption

    let m_add  = pu.decrypt(&c_add )?;
    let m_sub  = pu.decrypt(&c_sub )?;
    let m_sgn  = pu.decrypt(&c_sgn )?;
    let m_max  = pu.decrypt(&c_max )?;
    let m_xy1  = pu.decrypt(&c_xy1 )?;
    let m_xy4  = pu.decrypt(&c_xy4 )?;
    let m_xy8  = pu.decrypt(&c_xy8 )?;
    let m_xy16 = pu.decrypt(&c_xy16)?;
    let m_xy17 = pu.decrypt(&c_xy17)?;
    let m_xy32 = pu.decrypt(&c_xy32)?;

    let m_n161x16 = pu.decrypt(&c_n161x16)?;
    let m_n128x16 = pu.decrypt(&c_n128x16)?;
    let m_p3x16   = pu.decrypt(&c_p3x16  )?;

    let mut summary_text = format!("{} results", String::from("User:").bold().yellow());

    summary_text = format!("{}\nm_0 + m_1     = {:12} :: {} (exp. {} % {})", summary_text,
                            m_add,
                            if (m[0] + m[1] - m_add) % (1 << DEMO_BITLEN) == 0 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            (m_as[0] + m_as[1]) % (1 << DEMO_BITLEN), 1 << DEMO_BITLEN
    );
    summary_text = format!("{}\nm_1 - m_0     = {:12} :: {} (exp. {} % {})", summary_text,
                            m_sub,
                            if (m[1] - m[0] - m_sub) % (1 << DEMO_BITLEN) == 0 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            (m_as[1] - m_as[0]) % (1 << DEMO_BITLEN), 1 << DEMO_BITLEN
    );
    summary_text = format!("{}\nsgn(m_2)      = {:12} :: {}", summary_text,
                            m_sgn,
                            if m_sgn == m[2].signum() {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
    );
    summary_text = format!("{}\nmax{{m_1, m_0}} = {:12} :: {} (exp. {} % {})", summary_text,
                            m_max,
                            if (std::cmp::max(m_as[1], m_as[0]) - m_max) % (1 << DEMO_BITLEN) == 0 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            std::cmp::max(m_as[1], m_as[0]), 1 << DEMO_BITLEN
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
    summary_text = format!("{}\n-161 × x_16   = {:12} :: {} (exp. {})", summary_text,
                            m_n161x16,
                            if -161 * m_x16 == m_n161x16 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            -161 * m_x16
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
    infobox!("Demo END");
    // =================================

    Ok(())
}

pub fn nn_demo() -> Result<(), Box<dyn Error>> {

    //~ let nn_struct: NeuralNetwork;

    Ok(())
}
