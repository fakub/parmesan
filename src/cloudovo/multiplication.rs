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
            p = if x.len() == 4 {
                mul_4word(
                        pub_keys,
                        x,
                        y,
                )?
            } else {
                mul_8word(
                        pub_keys,
                        x,
                        y,
                )?
            };
        ]
    );

    Ok(p)
}

/// Implementation of product of two 8-word ciphertexts using O(n^2) schoolbook multiplication
fn mul_8word(
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    // set word-length
    const L: usize = 8;

    // check lengths
    if x.len() != L || y.len() != L {
        //TODO ...
        return Err(format!("Two {}-word integers expected.", L).into());
    }

    // fill multiplication array   //TODO check the size, it might grow outsite due to redundant representation
    let mut mulary_main = vec![vec![LWE::zero(0)?; 2*L]; L];
    mulary_main.par_iter_mut().zip(y.par_iter().enumerate()).for_each(| (x_yj, (j, yj)) | {
        &x_yj[j..j+L].par_iter_mut().zip(x.par_iter()).for_each(| (xi_yj, xi) | {
            *xi_yj = mul_lwe(pub_keys, &xi, &yj).expect("mul_lwe failed.");
        });
    });

    // reduce multiplication array
    let mut mulary_half = vec![vec![LWE::zero(0)?; 2*L]; L >> 1];   // L / 2
    mulary_half[0] = super::addition::add_sub_noise_refresh(
        true,
        pub_keys,
        &mulary_main[0],
        &mulary_main[1],
    )?;
    mulary_half[1] = super::addition::add_sub_noise_refresh(
        true,
        pub_keys,
        &mulary_main[2],
        &mulary_main[3],
    )?;
    mulary_half[2] = super::addition::add_sub_noise_refresh(
        true,
        pub_keys,
        &mulary_main[4],
        &mulary_main[5],
    )?;
    mulary_half[3] = super::addition::add_sub_noise_refresh(
        true,
        pub_keys,
        &mulary_main[6],
        &mulary_main[7],
    )?;
    let mut mulary_quater = vec![vec![LWE::zero(0)?; 2*L]; L >> 2];   // L / 4
    mulary_quater[0] = super::addition::add_sub_noise_refresh(
        true,
        pub_keys,
        &mulary_half[0],
        &mulary_half[1],
    )?;
    mulary_quater[1] = super::addition::add_sub_noise_refresh(
        true,
        pub_keys,
        &mulary_half[2],
        &mulary_half[3],
    )?;

    // final step & return
    Ok(super::addition::add_sub_impl(
        true,
        pub_keys,
        &mulary_quater[0],
        &mulary_quater[1],
    )?)
}

/// Implementation of product of two 4-word ciphertexts using O(n^2) schoolbook multiplication
fn mul_4word(
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    // set word-length
    const L: usize = 4;

    // check lengths
    if x.len() != L || y.len() != L {
        //TODO ...
        return Err(format!("Two {}-word integers expected.", L).into());
    }

    // fill multiplication array   //TODO check the size, it might grow outsite due to redundant representation
    //TODO try different approaches and compare
    let mut mulary_main = vec![vec![LWE::zero(0)?; 2*L]; L];
    mulary_main.par_iter_mut().zip(y.par_iter().enumerate()).for_each(| (x_yj, (j, yj)) | {
        &x_yj[j..j+L].par_iter_mut().zip(x.par_iter()).for_each(| (xi_yj, xi) | {
            *xi_yj = mul_lwe(pub_keys, &xi, &yj).expect("mul_lwe failed.");
        });
    });

    // reduce multiplication array
    //TODO in parallel
    // mulary_half.par_iter_mut()
    let mut mulary_half = vec![vec![LWE::zero(0)?; 2*L]; L >> 1];   // L / 2
    mulary_half[0] = super::addition::add_sub_noise_refresh(
        true,
        pub_keys,
        &mulary_main[0],
        &mulary_main[1],
    )?;
    mulary_half[1] = super::addition::add_sub_noise_refresh(
        true,
        pub_keys,
        &mulary_main[2],
        &mulary_main[3],
    )?;

    // final step & return
    Ok(super::addition::add_sub_impl(
        true,
        pub_keys,
        &mulary_half[0],
        &mulary_half[1],
    )?)
}
