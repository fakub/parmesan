use std::error::Error;

use concrete::LWE;
#[allow(unused_imports)]
use colored::Colorize;
//~ use crate::params::Params;
use crate::ciphertexts::ParmCiphertext;
use crate::userovo::keys::PubKeySet;
use super::pbs;

/// Implementation of parallel addition/subtraction
pub fn add_sub_impl(
    is_add: bool,
    //~ params: &Params,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    let mut z: ParmCiphertext = Vec::new();
    let dim = x[0].dimension;   //WISH fix this, was: x.first()?.dimension
    let encoder = &x[0].encoder;
    let mut wi_1:   LWE = LWE::zero_with_encoder(dim, encoder)?;
    let mut qi_1:   LWE = LWE::zero_with_encoder(dim, encoder)?;

    measure_duration!(
        "Parallel addition/subtraction",
        [
            for (xi, yi) in x.iter().zip(y.iter()) {
                let mut wi_0    = xi.clone();
                if is_add {
                    wi_0.add_uint_inplace(&yi)?;
                } else {
                    wi_0.sub_uint_inplace(&yi)?;
                }
                let mut wi_0_3  = wi_0.mul_uint_constant(3)?;
                                  wi_0_3.add_uint_inplace(&wi_1)?;

                let     qi_0    = pbs::f_4__pi_5(pub_keys, &wi_0_3)?;
                let     qi_0_2  = qi_0.mul_uint_constant(2)?;

                let mut zi      = wi_0.clone();
                                zi.sub_uint_inplace(&qi_0_2)?;
                                zi.add_uint_inplace(&qi_1)?;

                //TODO add one more bootstrap with identity (or leave it for user? in some cases BS could be saved)
                // call sth like add_impl_no_final_bs(); /this now/ and then bootstrap the result s.t. add_impl implicitly bootstraps the result
                z.push(zi);

                // update for next round:
                wi_1    = wi_0.clone();
                qi_1    = qi_0.clone();
            }
            //TODO add one more round if < maxlen
        ]
    );

    Ok(z)
}
