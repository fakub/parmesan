use std::error::Error;

#[allow(unused_imports)]   //WISH only use when sequential feature is OFF
use rayon::prelude::*;
use concrete::LWE;
#[allow(unused_imports)]
use colored::Colorize;
use crate::ciphertexts::ParmCiphertext;
//DBG
use crate::userovo::keys::PrivKeySet;
//DBG
use crate::params::Params;
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
            // x + y
            let mut add_sub: LWE = x.clone();
            add_sub.add_uint_inplace(y)?;
            let pos: LWE = pbs::a_2__pi_5(
                pub_keys,
                &add_sub,
            )?;

            // x - y
            add_sub = x.clone();
            add_sub.sub_uint_inplace(y)?;
            let neg: LWE = pbs::a_2__pi_5(
                pub_keys,
                &add_sub,
            )?;

            z = pos.clone();
            z.sub_uint_inplace(&neg)?;
            //TODO additional identity bootstrapping?
        ]
    );

    Ok(z)
}

/// Implementation of product of two ciphertexts using Karatsuba algorithm
pub fn mul_impl(
    //DBG
    priv_keys: &PrivKeySet,
    //DBG
    params: &Params,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    //TODO Karatsuba
    Ok(mul_schoolbook_4word(
            //DBG
            priv_keys,
            //DBG
            params,
            pub_keys,
            x,
            y,
    )?)
}

/// Implementation of product of two ciphertexts using O(n^2) schoolbook multiplication
fn mul_schoolbook_4word(
    //DBG
    priv_keys: &PrivKeySet,
    //DBG
    params: &Params,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    if x.len() != 4 || y.len() != 4 {
        //TODO ...
        return Err("Multiplication: schoolbook multiplication is only intended for two 4-word integers.".into());
    }

    let mut mulary_4 = vec![vec![LWE::zero(0)?; 8]; 4];

    //TODO try different approaches and compare
    mulary_4.par_iter_mut().zip(y.par_iter().enumerate()).for_each(| (x_yj, (j, yj)) | {
        &x_yj[j..j+4].par_iter_mut().zip(x.par_iter()).for_each(| (xi_yj, xi) | {
            *xi_yj = mul_lwe(pub_keys, &xi, &yj).expect("mul_lwe failed.");
        });
    });

    dbgln!("mulary_4 filled:");
    mulary_4.iter().for_each(|x_yj| {
        x_yj.iter().for_each(|xi_yj| {
            let p = crate::userovo::encryption::parm_decr_nibble(params, priv_keys, &xi_yj).expect("parm_decr_nibble failed.");
            dbgln!("    {}", p);
        });
        dbgln!("----");
    });

    let mut mulary_2 = vec![vec![LWE::zero(0)?; 8]; 2];

    //TODO in parallel
    // mulary_2.par_iter_mut()

    mulary_2[0] = super::addition::add_sub_impl(
        true,
        pub_keys,
        &mulary_4[0],
        &mulary_4[1],
    )?;
    mulary_2[1] = super::addition::add_sub_impl(
        true,
        pub_keys,
        &mulary_4[2],
        &mulary_4[3],
    )?;

    dbgln!("mulary_2 filled:");
    mulary_2.iter().for_each(|x_yj| {
        x_yj.iter().for_each(|xi_yj| {
            let p = crate::userovo::encryption::parm_decr_nibble(params, priv_keys, &xi_yj).expect("parm_decr_nibble failed.");
            dbgln!("    {}", p);
        });
        dbgln!("----");
    });

    //~ Ok(super::addition::add_sub_impl(
        //~ true,
        //~ pub_keys,
        //~ &mulary_2[0],
        //~ &mulary_2[1],
    //~ )?)

    let m = super::addition::add_sub_impl(
        true,
        pub_keys,
        &mulary_2[0],
        &mulary_2[1],
    )?;

    dbgln!("result:");
    m.iter().for_each(|mi| {
        let p = crate::userovo::encryption::parm_decr_nibble(params, priv_keys, &mi).expect("parm_decr_nibble failed.");
        dbgln!("    {}", p);
    });

    Ok(m)
}
