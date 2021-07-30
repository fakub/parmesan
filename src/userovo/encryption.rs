use concrete::LWE;
use colored::Colorize;
use crate::params::Params;
use crate::userovo::keys::PrivKeySet;
use crate::ciphertexts::ParmCiphertext;

pub fn encrypt(
    params: &Params,
    priv_keys: &PrivKeySet,
    m: i32,
    bits: usize,
) -> ParmCiphertext {
    //WISH some warning if bits is more than given type (-1 for signed)
    let mut ctv: Vec<LWE> = Vec::new();

    for i in 0..bits {
        let mi = if (m.abs() >> i) & 1 == 0 {
            0i32
        } else {
            if m >= 0 {1i32} else {params.minus_1()}
        };
        ctv.push(
            LWE::encode_encrypt(
                &priv_keys.sk,
                mi as f64,
                &priv_keys.encoder,
            ).expect("LWE encryption failed.")
        );
    }

    ParmCiphertext {
        ctv,
        maxlen: 32,
    }
}

pub fn decrypt (
    params: &Params,
    priv_keys: &PrivKeySet,
    pc: &ParmCiphertext,
) -> i32 {
    let mut m = 0i32;
    let minus_1 = params.minus_1();
    infoln!("-1 ~ {}", minus_1);

    measure_duration!(
        "Decrypt",
        [
            for (i, ct) in pc.ctv.iter().enumerate() {
                let mi = ct.decrypt_decode(&priv_keys.sk)
                           .expect("LWE decryption failed.") as i32;   // rounding included in Encoder
                infoln!("Decrypted {}. element: {}", i, mi);
                m += match mi {
                    1 => {eprintln!("    mi ~ 1"); 1i32 << i},
                    0 => {eprintln!("    mi ~ 0"); 0i32},
                    _ if mi == minus_1 => {eprintln!("    mi ~ {}", minus_1); -(1i32 << i)},
                    _ => {eprintln!("    mi ~ _"); 0i32},   //WISH fail
                };
            }
        ]
    );

    m
}
