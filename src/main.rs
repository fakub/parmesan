//!
//! PARMESAN: Parallel-ARithMEticS-on-tfhe-ENcrypted-data
//!
//! A library for fast parallel arithmetics on TFHE-encrypted data.
//!

use concrete::*;
use colored::Colorize;
use std::io::{self,Write};

fn main() -> Result<(), CryptoAPIError> {
    println!("Hi, I am {}, using local {} with custom patches & an unsafe PRNG.", String::from("Parmesan").yellow().bold(), String::from("Concrete").blue().bold());

    // encoders
    let encoder_input = Encoder::new_rounding_context(0., 15., 2, 1)?;          // input message can be in the interval [0,16)
    let encoder_output = Encoder::new_rounding_context(0., 31., 3, 0)?;

    // keys
    print!("> loading keys ... "); io::stdout().flush().unwrap();
    //TODO generate if they do not exist; cf. zqz/keys.rs:28 in demo_z8z
    let  sk = LWESecretKey::load("rlwe_1024_1_bbs_6_lbs_4_secret_key.json").expect("Failed to load SK file" );
    let bsk = LWEBSK::load("rlwe_1024_1_bbs_6_lbs_4_bootstrapping_key.txt");
    let ksk = LWEKSK::load("rlwe_1024_1_bbs_6_lbs_4_keyswitching_key.txt" );
    println!("DONE");

    // messages
    let m: f64 = 15.999;

    // encode and encrypt
    let c = LWE::encode_encrypt(&sk, m, &encoder_input)?;

    // bootstrap
    let fc_r = c.bootstrap_with_function(&bsk, |x| x * x, &encoder_output)?;
    let fc = fc_r.keyswitch(&ksk)?;

    // try LUT
    //~ let lut = |x| [1, 2, 3, 4, 5][x];
    //~ let var = 3;
    //~ println!("LUT({}) = {}", var, lut(var));

    // decrypt
    let fm = fc.decrypt_decode(&sk)?;

    println!("before bootstrap: {}, after bootstrap: {}", m, fm);

    Ok(())
}

//TODO
//
//  pub fn bootstrap_with_lut: reimplement completely
