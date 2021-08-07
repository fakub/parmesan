
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
pub use ciphertexts::ParmCiphertext;

// Userovo modules
pub mod userovo;
pub use userovo::keys::{PrivKeySet,PubKeySet};
pub use userovo::encryption;

// Cloudovo modules
pub mod cloudovo;
pub use cloudovo::addition;
pub use cloudovo::signum;
pub use cloudovo::maximum;
pub use cloudovo::multiplication;


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

    /// Encrypt a 32-bit signed integer
    /// * `bits` states how many bits of input `m` are to be encrypted, since this will be public
    /// * least significant bits, including sign, are taken
    pub fn encrypt(
        &self,
        m: i32,
        bits: usize,
    ) -> Result<ParmCiphertext, Box<dyn Error>> {   //WISH change to a template for other integer types/lengths, too
        Ok(encryption::parm_encrypt(self.params, &self.priv_keys, m, bits)?)
    }

    /// Decrypt a 32-bit signed integer
    pub fn decrypt(&self, c: &ParmCiphertext) -> Result<i32, Box<dyn Error>> {   //WISH change to a template for other integer types/lengths, too
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

    /// Add two ciphertexts in parallel
    pub fn add(
        &self,
        x: &ParmCiphertext,
        y: &ParmCiphertext,
    ) -> Result<ParmCiphertext, Box<dyn Error>> {
        Ok(addition::add_sub_impl(
            true,
            self.pub_keys,
            x,
            y,
        )?)
    }

    /// Subtract two ciphertexts in parallel
    pub fn sub(
        &self,
        x: &ParmCiphertext,
        y: &ParmCiphertext,
    ) -> Result<ParmCiphertext, Box<dyn Error>> {
        Ok(addition::add_sub_impl(
            false,
            self.pub_keys,
            x,
            y,
        )?)
    }

    /// Signum of a ciphertext by parallel reduction
    pub fn sgn(
        &self,
        x: &ParmCiphertext,
    ) -> Result<ParmCiphertext, Box<dyn Error>> {
        Ok(signum::sgn_impl(
            self.params,
            self.pub_keys,
            x,
        )?)
    }

    /// Maximum of two ciphertexts in parallel using signum
    pub fn max(
        &self,
        x: &ParmCiphertext,
        y: &ParmCiphertext,
    ) -> Result<ParmCiphertext, Box<dyn Error>> {
        Ok(maximum::max_impl(
            self.params,
            self.pub_keys,
            x,
            y,
        )?)
    }

    /// Product of two 1-word ciphertexts
    pub fn mult_oneword(
        &self,
        x: &ParmCiphertext,
        y: &ParmCiphertext,
    ) -> Result<ParmCiphertext, Box<dyn Error>> {
        if x.len() != 1 || y.len() != 1 {
            //TODO this does not do anything itself (only halts program, no error message)
            return Err("One-word Parmesan ciphertexts expected.".into());
        }

        Ok(vec![multiplication::mult_lwe(
            self.pub_keys,
            &x[0],
            &y[0],
        )?])
    }
}


// =============================================================================
//
//  Global Functions
//

// -----------------------------------------------------------------------------
//  Dev

pub fn parmesan_demo() -> Result<(), Box<dyn Error>> {

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
    let m: [i32; DEMO_N_MSGS] = [
         0b01111110110010010011100110111011,
         0b00110010001111100110111100100000,
        -0b01000100001010010111100000010101,
    ];
    let mut m_as: [i32; DEMO_N_MSGS] = [0,0,0];
    let mut c: [ParmCiphertext; DEMO_N_MSGS] = [
        vec![LWE::zero(0)?; DEMO_BITLEN],
        vec![LWE::zero(0)?; DEMO_BITLEN],
        vec![LWE::zero(0)?; DEMO_BITLEN],
    ];
    for (ci, (mi, mi_as)) in c.iter_mut().zip(m.iter().zip(m_as.iter_mut())) {
        *ci = pu.encrypt(*mi, DEMO_BITLEN)?;
        *mi_as = (*mi).signum() * ((*mi).abs() % (1 << DEMO_BITLEN));
    }

    let mut intro_text = format!("{} messages ({} bits taken)", String::from("User:").bold().yellow(), DEMO_BITLEN);
    for (i, (mi, mi_as)) in m.iter().zip(m_as.iter()).enumerate() {
        intro_text = format!("{}\nm_{} = {}{:032b} ({})", intro_text, i, if *mi >= 0 {""} else {"-"}, mi.abs(), mi_as);
    }
    infoln!("{}", intro_text);


    // =================================
    //  C: Evaluation

    //DBG BEGIN
    let pos_1 = pu.encrypt( 1,1)?;
    let neg_1 = pu.encrypt(-1,1)?;
    let zer_0 = pu.encrypt( 0,1)?;

    let pp = pc.mult_oneword(&pos_1, &pos_1)?;
    let pz = pc.mult_oneword(&pos_1, &zer_0)?;
    let pn = pc.mult_oneword(&pos_1, &neg_1)?;

    let zp = pc.mult_oneword(&zer_0, &pos_1)?;
    let zz = pc.mult_oneword(&zer_0, &zer_0)?;
    let zn = pc.mult_oneword(&zer_0, &neg_1)?;

    let np = pc.mult_oneword(&neg_1, &pos_1)?;
    let nz = pc.mult_oneword(&neg_1, &zer_0)?;
    let nn = pc.mult_oneword(&neg_1, &neg_1)?;

    let pp_p = pu.decrypt(&pp)?;
    let pz_p = pu.decrypt(&pz)?;
    let pn_p = pu.decrypt(&pn)?;

    let zp_p = pu.decrypt(&zp)?;
    let zz_p = pu.decrypt(&zz)?;
    let zn_p = pu.decrypt(&zn)?;

    let np_p = pu.decrypt(&np)?;
    let nz_p = pu.decrypt(&nz)?;
    let nn_p = pu.decrypt(&nn)?;

    infoln!(" 1 ×  1 = {}", pp_p);
    infoln!(" 1 ×  0 = {}", pz_p);
    infoln!(" 1 × -1 = {}", pn_p);

    infoln!(" 0 ×  1 = {}", zp_p);
    infoln!(" 0 ×  0 = {}", zz_p);
    infoln!(" 0 × -1 = {}", zn_p);

    infoln!("-1 ×  1 = {}", np_p);
    infoln!("-1 ×  0 = {}", nz_p);
    infoln!("-1 × -1 = {}", nn_p);

    return Ok(());
    //DBG END

    let c_add = pc.add(&c[0], &c[1])?;
    let c_sub = pc.sub(&c[1], &c[0])?;
    let c_sgn = pc.sgn(&c[2])?;
    let c_max = pc.max(&c[1], &c[0])?;


    // =================================
    //  U: Decryption
    let m_add  = pu.decrypt(&c_add)?;
    let m_sub  = pu.decrypt(&c_sub)?;
    let m_sgn  = pu.decrypt(&c_sgn)?;
    let m_max  = pu.decrypt(&c_max)?;

    let mut summary_text = format!("{} results", String::from("User:").bold().yellow(),);
    summary_text = format!("{}\nm_0 + m_1 = {} :: {} (exp. {} % {})", summary_text,
                            m_add,
                            if (m[0] as i64 + m[1] as i64 - m_add as i64) % (1 << DEMO_BITLEN) == 0 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            (m_as[0] as i64 + m_as[1] as i64) % (1 << DEMO_BITLEN), 1 << DEMO_BITLEN
    );
    summary_text = format!("{}\nm_1 - m_0 = {} :: {} (exp. {} % {})", summary_text,
                            m_sub,
                            if (m[1] as i64 - m[0] as i64 - m_sub as i64) % (1 << DEMO_BITLEN) == 0 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            (m_as[1] as i64 - m_as[0] as i64) % (1 << DEMO_BITLEN), 1 << DEMO_BITLEN
    );
    summary_text = format!("{}\nsgn(m_2) = {} :: {}", summary_text,
                            m_sgn,
                            if m_sgn == m[2].signum() {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
    );
    summary_text = format!("{}\nmax{{m_1, m_0}} = {} :: {} (exp. {} % {})", summary_text,
                            m_max,
                            if (std::cmp::max(m_as[1], m_as[0]) as i64 - m_max as i64) % (1 << DEMO_BITLEN) == 0 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            std::cmp::max(m_as[1], m_as[0]), 1 << DEMO_BITLEN
    );
    infoln!("{}", summary_text);


    // =================================
    infobox!("Demo END");
    // =================================

    Ok(())
}
