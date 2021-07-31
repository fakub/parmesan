use concrete::LWE;
use colored::Colorize;
//~ use crate::params::Params;
use crate::ciphertexts::ParmCiphertext;
use crate::userovo::keys::PubKeySet;
use super::pbs;

/// Implementation of parallel addition
pub fn add_impl(
    //~ params: &Params,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> ParmCiphertext {
    // run parallel addition algorithm
    let mut z: ParmCiphertext = Vec::new();

    measure_duration!(
        "Parallel addition",
        [
            let dim = x[0].dimension;
            let encoder = &x[0].encoder;
            let mut wi_1:   LWE = LWE::zero_with_encoder(dim, encoder).expect("LWE::zero_with_encoder failed.");
            let mut qi_1:   LWE = LWE::zero_with_encoder(dim, encoder).expect("LWE::zero_with_encoder failed.");

            for (xi, yi) in x.iter().zip(y.iter()) {
                let     wi_0    = xi.add_uint(&yi).expect("Addition (uint) failed.");
                let mut wi_0_3  = wi_0.mul_uint_constant(3).expect("Multiplication (uint) by const failed.");
                                  wi_0_3.add_uint_inplace(&wi_1).expect("Addition (uint) inplace failed.");

                let     qi_0    = pbs::f_4__pi_5(pub_keys, &wi_0_3);
                let     qi_0_2  = qi_0.mul_uint_constant(2).expect("Multiplication (uint) by const failed.");

                let mut zi      = wi_0.clone();
                                zi.sub_uint_inplace(&qi_0_2).expect("Subtraction (uint) inplace failed.");
                                zi.add_uint_inplace(&qi_1).expect("Addition (uint) inplace failed.");

                z.push(zi);

                // update for next round:
                wi_1    = wi_0.clone();
                qi_1    = qi_0.clone();
            }
            //TODO add one more round if < maxlen
        ]
    );

    z
}
