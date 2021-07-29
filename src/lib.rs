// auto-generated:
//~ #[cfg(test)]
//~ mod tests {
    //~ #[test]
    //~ fn it_works() {
        //~ assert_eq!(2 + 2, 4);
    //~ }
//~ }

//!
//! PARMESAN: Parallel-ARithMEticS-on-tfhe-ENcrypted-data
//!
//! A library for fast parallel arithmetics on TFHE-encrypted data.
//!

use std::io::{self,Write};
use colored::Colorize;
use concrete::*;

mod params;
mod key_set;
mod misc;

use key_set::KeySet;

pub fn parmesan_hello() {
    infoln!("Hi, I am {}, using local {} with custom patches & an unsafe PRNG.", String::from("Parmesan").yellow().bold(), String::from("Concrete").blue().bold());
}

pub fn parmesan_main() -> Result<(), CryptoAPIError> {
    // say hello
    parmesan_hello();

    // parameters
    let prms = params::Params {
         lwe_params: LWE80_256,
        rlwe_params: RLWE80_256_1,
        bs_base_log: 3,
           bs_level: 2,
        ks_base_log: 1,
           ks_level: 3,
    };

    // encoders
    let encoder_input  = Encoder::new_rounding_context(0., 15., 2, 1)?;          // input message can be in the interval [0,16)
    let encoder_output = Encoder::new_rounding_context(0., 31., 3, 0)?;

    // keys
    measure_duration!(
        "Load / generate the Key set",
        [
            let keys = KeySet::load_gen(&prms);
            //~ let keys = KeySet::load_gen(&params::PARM90__PI_5__D_20);
        ]
    );

    // messages
    let m: f64 = 15.999;

    // encode and encrypt
    let c = LWE::encode_encrypt(&keys.sk, m, &encoder_input)?;

    // bootstrap
    let fc_r =    c.bootstrap_with_function(&keys.bsk, |x| x * x, &encoder_output)?;
    let fc   = fc_r.keyswitch(&keys.ksk)?;

    // try LUT
    //~ let lut = |x| [1, 2, 3, 4, 5][x];
    //~ let var = 3;
    //~ println!("LUT({}) = {}", var, lut(var));

    // decrypt
    let fm = fc.decrypt_decode(&keys.sk)?;

    println!("before bootstrap: {}, after bootstrap: {}", m, fm);

    Ok(())
}

// a list of modules goes here:
