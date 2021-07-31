use std::error::Error;

use rayon::prelude::*;
use concrete::LWE;
#[allow(unused_imports)]
use colored::Colorize;
use crate::ciphertexts::ParmCiphertext;
use crate::userovo::keys::PubKeySet;
use super::pbs;

/// Implementation of parallel addition/subtraction
pub fn add_sub_impl(
    is_add: bool,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    let dim = x[0].dimension;   //WISH fix this, was: x.first()?.dimension
    let encoder = &x[0].encoder;

    let mut w = x.clone();
    let mut q = vec![LWE::zero_with_encoder(dim, encoder)?; x.len()];

    //~ let mut z: ParmCiphertext = Vec::new();

    //~ let mut wi_1:   LWE = LWE::zero_with_encoder(dim, encoder)?;
    //~ let mut qi_1:   LWE = LWE::zero_with_encoder(dim, encoder)?;

    measure_duration!(
        "Parallel addition/subtraction",
        [
            //WISH add ciphertexts with different lengths (fill with zeros)

            infoln!("current_num_threads = {}", rayon::current_num_threads());

            // -----------------------------------------------------------------
            // sequential approach (6-bit: 50-70 us)
            measure_duration!(
            "w = x + y (seq)",
            [
                if is_add {
                    for (wi, yi) in w.iter_mut().zip(y.iter()) {
                        wi.add_uint_inplace(&yi)?;
                    }
                } else {
                    for (wi, yi) in w.iter_mut().zip(y.iter()) {
                        wi.sub_uint_inplace(&yi)?;
                    }
                }
            ]);
            // -----------------------------------------------------------------
            // parallel approach (6-bit: 110-130 us)
            //~ measure_duration!(
            //~ "w = x + y (par)",
            //~ [
                //~ if is_add {
                    //~ w.par_iter_mut().zip(y.par_iter()).for_each(|(wi,yi)| wi.add_uint_inplace(&yi).expect("add_uint_inplace failed.") );
                //~ } else {
                    //~ w.par_iter_mut().zip(y.par_iter()).for_each(|(wi,yi)| wi.sub_uint_inplace(&yi).expect("sub_uint_inplace failed.") );
                //~ }
            //~ ]);
            // -----------------------------------------------------------------

            let mut z = w.clone();

            // -----------------------------------------------------------------
            // parallel approach
            q.par_iter_mut().zip(w.par_iter().enumerate()).for_each(| (qi, (i, wi)) | {
                // calc   3 w_i + w_i-1
                let mut wi_3 = wi.mul_uint_constant(3).expect("mul_uint_constant failed.");
                if i > 0 { wi_3.add_uint_inplace(&w[i-1]).expect("add_uint_inplace failed."); }
                *qi = pbs::f_4__pi_5(pub_keys, &wi_3).expect("f_4__pi_5 failed.");
            });

            z.par_iter_mut().zip(q.par_iter().enumerate()).for_each(| (zi, (i, qi)) | {
                // calc   2 q_i
                let qi_2 = qi.mul_uint_constant(2).expect("mul_uint_constant failed.");
                zi.sub_uint_inplace(&qi_2).expect("sub_uint_inplace failed.");
                if i > 0 { zi.add_uint_inplace(&q[i-1]).expect("add_uint_inplace failed."); }
                //TODO add one more bootstrap with identity (or leave it for user? in some cases BS could be saved)
                //TODO add one more thread if < maxlen
            });

            // -----------------------------------------------------------------
            // sequential approach
            //~ for wi_0 in w {
                //~ let mut wi_0_3  = wi_0.mul_uint_constant(3)?;
                                  //~ wi_0_3.add_uint_inplace(&wi_1)?;

                //~ let     qi_0    = pbs::f_4__pi_5(pub_keys, &wi_0_3)?;
                //~ let     qi_0_2  = qi_0.mul_uint_constant(2)?;

                //~ let mut zi      = wi_0.clone();
                                //~ zi.sub_uint_inplace(&qi_0_2)?;
                                //~ zi.add_uint_inplace(&qi_1)?;

                //~ // call sth like add_impl_no_final_bs(); /this now/ and then bootstrap the result s.t. add_impl implicitly bootstraps the result
                //~ z.push(zi);

                //~ // update for next round:
                //~ wi_1    = wi_0.clone();
                //~ qi_1    = qi_0.clone();
            //~ }
        ]
    );

    Ok(z)
}
