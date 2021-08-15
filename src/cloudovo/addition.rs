use std::error::Error;

#[cfg(not(feature = "sequential"))]
use rayon::prelude::*;
use concrete::LWE;
#[allow(unused_imports)]
use colored::Colorize;
use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};
use crate::userovo::keys::PubKeySet;
use crate::params::Params;
use super::pbs;

/// Parallel addition/subtraction followed by noise refreshal
pub fn add_sub_noise_refresh(
    is_add: bool,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    let z_noisy = add_sub_impl(
        is_add,
        pub_keys,
        x,
        y,
    )?;

    let mut z = ParmCiphertext::triv(x.len())?;

    z_noisy.par_iter().zip(z.par_iter_mut()).for_each(| (zni, zi) | {
        *zi = pbs::id(pub_keys, zni).expect("pbs::id failed.");
    });

    Ok(z)
}

/// Implementation of parallel addition/subtraction
pub fn add_sub_impl(
    is_add: bool,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    // calculate right overlap of trivial zero samples
    let mut x_triv = 0usize;
    let mut y_triv = 0usize;
    for xi in x {
        if xi.dimension == 0 && xi.ciphertext.get_body().0 == 0 {x_triv += 1;} else {break;}
    }
    for yi in y {
        if yi.dimension == 0 && yi.ciphertext.get_body().0 == 0 {y_triv += 1;} else {break;}
    }
    let triv = std::cmp::max(x_triv, y_triv);

    //TODO fill with preceeding zeros

    let mut z: ParmCiphertext;

    // Parallel
    #[cfg(not(feature = "sequential"))]
    {
        measure_duration!(
            ["Parallel {} ({}-bit)", if is_add {"addition"} else {"subtraction"}, x.len()],
            [
                let mut w = x.clone();

                // w = x + y
                // -----------------------------------------------------------------
                // sequential approach (6-bit: 50-70 us)
                //~ measure_duration!(
                //~ ["w = x + y (seq)"],
                //~ [
                    if is_add {
                        for (wi, yi) in w.iter_mut().zip(y.iter()) {
                            wi.add_uint_inplace(&yi)?;
                        }
                    } else {
                        for (wi, yi) in w.iter_mut().zip(y.iter()) {
                            wi.sub_uint_inplace(&yi)?;
                        }
                    }
                //~ ]);
                // parallel approach (6-bit: 110-130 us)
                //~ measure_duration!(
                //~ ["w = x + y (par)"],
                //~ [
                    //~ if is_add {
                        //~ w.par_iter_mut().zip(y.par_iter()).for_each(|(wi,yi)| wi.add_uint_inplace(&yi).expect("add_uint_inplace failed.") );
                    //~ } else {
                        //~ w.par_iter_mut().zip(y.par_iter()).for_each(|(wi,yi)| wi.sub_uint_inplace(&yi).expect("sub_uint_inplace failed.") );
                    //~ }
                //~ ]);
                // -----------------------------------------------------------------

                let mut q = ParmCiphertext::triv(x.len())?;
                z = w.clone();

                q[triv..].par_iter_mut().zip(w[triv..].par_iter().enumerate()).for_each(| (qi, (i0, wi)) | {
                    let i = i0 + triv;
                    // calc   3 w_i + w_i-1
                    let mut wi_3 = wi.mul_uint_constant(3).expect("mul_uint_constant failed.");
                    if i0 > 0 { wi_3.add_uint_inplace(&w[i-1]).expect("add_uint_inplace failed."); }
                    *qi = pbs::f_4__pi_5(pub_keys, &wi_3).expect("f_4__pi_5 failed.");
                });

                z.par_iter_mut().zip(q.par_iter().enumerate()).for_each(| (zi, (i, qi)) | {
                    // calc   2 q_i
                    let qi_2 = qi.mul_uint_constant(2).expect("mul_uint_constant failed.");
                    zi.sub_uint_inplace(&qi_2).expect("sub_uint_inplace failed.");
                    if i > 0 { zi.add_uint_inplace(&q[i-1]).expect("add_uint_inplace failed."); }
                });
                //TODO add one more bootstrap with identity (or leave it for user? in some cases BS could be saved)
                //TODO add one more thread if < maxlen
            ]
        );
    }

    // Sequential
    #[cfg(feature = "sequential")]
    {
        let dim = x[0].dimension;
        let encoder = &x[0].encoder;

        measure_duration!(
            ["Sequential {} ({}-bit; in redundant representation)", if is_add {"addition"} else {"subtraction"}, x.len()],
            [
                let mut wi_1:   LWE = LWE::zero_with_encoder(dim, encoder)?;
                let mut qi_1:   LWE = LWE::zero_with_encoder(dim, encoder)?;
                z = ParmCiphertext::empty();

                //TODO apply triv
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
            ]
        );
    }

    Ok(z)
}

pub fn opposite_impl(
    x: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    let mut nx = ParmCiphertext::empty();

    for xi in x {
        nx.push(xi.opposite_uint()?);
    }

    Ok(nx)
}

pub fn add_const_impl(
    params: &Params,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    k: i32,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    // resolve k == 0
    if k == 0 {
        return Ok(x.clone());
    }

    let k_abs = (k as i64).abs() as u32;   // deal with -2^31, for which abs() panics, because it does not fit i32
    let k_pos = k >= 0;

    let mut k_len = 0usize;
    for i in 0..31 {if k_abs & (1 << i) != 0 {k_len = i + 1;}}

    let mut ck = ParmCiphertext::empty();

    for i in 0..k_len {
        // calculate i-th bit with sign
        let mut ki = if ((k_abs >> i) & 1) == 0 {
            0u32
        } else {
            if k_pos {1u32} else {params.plaintext_mask() as u32}
        };

        // encrypt as trivial sample
        let cti = LWE::encrypt_uint_triv(
            ki,
            &pub_keys.encoder,
        )?;

        ck.push(cti);
    }

    Ok(add_sub_impl(
        true,
        pub_keys,
        x,
        &ck,
    )?)
}
