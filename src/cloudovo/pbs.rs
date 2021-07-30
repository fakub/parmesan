use concrete::LWE;
use colored::Colorize;
use crate::userovo::keys::PubKeySet;

pub fn id(
    pub_keys: &PubKeySet,
    c: &LWE,
) -> LWE {
    crate::measure_duration!(
        "PBS: Identity",
        [let res = c.bootstrap_with_function(pub_keys.bsk, |x| x, pub_keys.encoder)
                    .expect("Identity PBS failed.")
                    .keyswitch(pub_keys.ksk)
                    .expect("KS failed (in identity).");]
    );

    res
}

// try LUT
//~ let lut = |x| [1, 2, 3, 4, 5][x];
//~ let var = 3;
//~ println!("LUT({}) = {}", var, lut(var));
