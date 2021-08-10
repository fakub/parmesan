use std::error::Error;

#[allow(unused_imports)]   //WISH only use when sequential feature is OFF
use rayon::prelude::*;
use concrete::LWE;
#[allow(unused_imports)]
use colored::Colorize;
use crate::ciphertexts::ParmCiphertext;
use crate::userovo::keys::PubKeySet;
use super::pbs;

/// Implementation of one-word multiplication
pub fn mul_lwe(
    pub_keys: &PubKeySet,
    x: &LWE,
    y: &LWE,
) -> Result<LWE, Box<dyn Error>> {

    let mut z: LWE;
    //~ let mut pos_neg = vec![LWE::zero(0)?; 2];
    //~ let mut pos = &pos_neg[0];
    //~ let mut neg = &pos_neg[1];

    measure_duration!(
        "Multiplication one-word (LWE × LWE)",
        [
            //TODO these can be done in parallel
            // tmp = x + y
            let mut tmp: LWE = x.clone();
            tmp.add_uint_inplace(y)?;
            let pos: LWE = pbs::a_2__pi_5(
                pub_keys,
                &tmp,
            )?;

            // tmp = x - y
            tmp = x.clone();
            tmp.sub_uint_inplace(y)?;
            let neg: LWE = pbs::a_2__pi_5(
                pub_keys,
                &tmp,
            )?;

            // z = pos - neg
            z = pos.clone();
            z.sub_uint_inplace(&neg)?;

            //TODO additional identity bootstrapping .. needed?
            //~ z = pbs::id(
                //~ pub_keys,
                //~ &tmp,   // pos - neg
            //~ )?;
        ]
    );

    Ok(z)
}

/// Implementation of product of two ciphertexts using Karatsuba algorithm
pub fn mul_impl(
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    let p: ParmCiphertext;

    measure_duration!(
        "Multiplication",
        [
            //TODO
            //  General bit-len:
            //      Karatsuba for == 14 or >= 16, otherwise schoolbook (< 14 or 15)
            //
            //  32-bit:
            //                /  8
            //          16  ---  8
            //        /       \  9
            //       /
            //      /         /  8
            //  32  --- 16  ---  8
            //      \         \  9
            //       \
            //        \       /  8
            //          17  ---  9
            //                \ 10
            //

            p = match x.len() {
                l if l == 1 => mul_1word(
                        pub_keys,
                        x,
                        y,
                )?,
                l if l > 1 => mul_multiword(
                        l,
                        pub_keys,
                        x,
                        y,
                )?,
                _ => return Err(format!("Multiplication for {}-word integers not implemented.", x.len()).into()),
            };
        ]
    );

    Ok(p)
}

/// Implementation of product of two 4-word ciphertexts using O(n^2) schoolbook multiplication
fn mul_multiword(
    len: usize,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    // calc multiplication array
    let mulary_main = fill_mulary(
        len,
        pub_keys,
        x,
        y,
    )?;

    // reduce multiplication array
    let mut intmd = vec![vec![LWE::zero(0)?; 2*len]; 2];
    let mut idx = 0usize;
    intmd[idx] = super::addition::add_sub_noise_refresh(
        true,
        pub_keys,
        &mulary_main[0],
        &mulary_main[1],
    )?;

    for i in 2..len {
        idx ^= 1;
        intmd[idx] = super::addition::add_sub_noise_refresh(
            true,
            pub_keys,
            &intmd[idx ^ 1],
            &mulary_main[i],
        )?;
    }

    Ok(intmd[idx].clone())
}

/// Product of two 1-word ciphertexts
fn mul_1word(
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    // set word-length
    const L: usize = 1;

    // calc multiplication array
    let mulary_main = fill_mulary(
        L,
        pub_keys,
        x,
        y,
    )?;

    Ok(mulary_main[0].clone())
}

/// Fill multiplication array (in schoolbook multiplication)
fn fill_mulary(
    exp_len: usize,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<Vec<ParmCiphertext>, Box<dyn Error>> {

    // check lengths
    if x.len() != exp_len || y.len() != exp_len {
        //TODO ...
        return Err(format!("Two {}-word integers expected.", exp_len).into());
    }

    // fill multiplication array
    //TODO check the size, it might grow outsite due to redundant representation
    //TODO try different approaches and compare
    let mut mulary = vec![vec![LWE::zero(0)?; 2*exp_len]; exp_len];

    mulary.par_iter_mut().zip(y.par_iter().enumerate()).for_each(| (x_yj, (j, yj)) | {
        &x_yj[j..j+exp_len].par_iter_mut().zip(x.par_iter()).for_each(| (xi_yj, xi) | {
            *xi_yj = mul_lwe(pub_keys, &xi, &yj).expect("mul_lwe failed.");
        });
    });

    Ok(mulary)
}
