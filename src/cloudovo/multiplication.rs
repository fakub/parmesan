use std::error::Error;

#[cfg(not(feature = "sequential"))]
use rayon::prelude::*;
use concrete::LWE;
#[allow(unused_imports)]
use colored::Colorize;

use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};
use crate::userovo::keys::PubKeySet;
use super::pbs;


// =============================================================================
//
//  Multiplication
//

/// Implementation of product of two ciphertexts using Karatsuba algorithm
pub fn mul_impl(
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    //  Karatsuba for lengths 14 or >= 16, otherwise schoolbook (i.e., lengths < 14 or 15)
    //
    //  e.g., 32-bit:
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

    if x.len() != y.len() {
        return Err(format!("Multiplication for integers of different lengths not implemented ({}- and {}-bit supplied).", x.len(), y.len()).into())
    }

    let p = match x.len() {
        l if l == 1 => mul_1word(
            pub_keys,
            x,
            y,
        )?,
        l if l < 14 || l == 15 => mul_schoolbook(
            pub_keys,
            x,
            y,
        )?,
        l if l <= 32 => mul_karatsuba(
            pub_keys,
            x,
            y,
        )?,
        _ => return Err(format!("Multiplication for {}-word integers not implemented.", x.len()).into()),
    };

    Ok(p)
}

/// Karatsuba multiplication
fn mul_karatsuba(
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    //WISH  be able to calculate n and n-1 bit numbers (useful for squaring of non-power of two lengths)
    //      in the end, it will be needed in schoolbook, too
    assert_eq!(x.len(), y.len());

    // not needed: let len1 = x.len() / 2;
    let len0 = (x.len() + 1) / 2;

    //       len1  len0
    //  x = | x_1 | x_0 |
    //  y = | y_1 | y_0 |
    let mut x0 = ParmCiphertext::empty();
    let mut x1 = ParmCiphertext::empty();
    let mut y0 = ParmCiphertext::empty();
    let mut y1 = ParmCiphertext::empty();

    for (i, (xi, yi)) in x.iter().zip(y.iter()).enumerate() {
        if i < len0 {
            x0.push(xi.clone());
            y0.push(yi.clone());
        } else {
            x1.push(xi.clone());
            y1.push(yi.clone());
        }
    }

    measure_duration!(
        ["Multiplication Karatsuba ({}-bit)", x.len()],
        [
            //  A = x_1 * y_1                   .. len1-bit
            let mut a = mul_impl(
                pub_keys,
                &x1,
                &y1,
            )?;

            //  B = x_0 * y_0                   .. len0-bit
            let mut b = mul_impl(
                pub_keys,
                &x0,
                &y0,
            )?;

            //  C = (x_0 + x_1) * (y_0 + y_1)   .. (len0 + 1)-bit
            let x01 = super::addition::add_sub_noise_refresh(
                true,
                pub_keys,
                &x0,
                &x1,
            )?;
            let y01 = super::addition::add_sub_noise_refresh(
                true,
                pub_keys,
                &y0,
                &y1,
            )?;
            let mut c = ParmCiphertext::triv(len0)?;
            let mut c_plain = mul_impl(
                pub_keys,
                &x01,
                &y01,
            )?;
            c.append(&mut c_plain);

            //  A + B .. -A - B
            let papb = super::addition::add_sub_noise_refresh(
                true,
                pub_keys,
                &a,
                &b,
            )?;
            let mut nanb = ParmCiphertext::triv(len0)?;
            for abi in papb {
                nanb.push(abi.opposite_uint()?);
            }

            //  B <- | A | B |
            b.append(&mut a);

            //  |   A   |   B   |   in b
            //     |    C   |       in c
            //      |  -A   |       in nanb
            //      |  -B   |       -- " --

            //  | A | B |   +   |  C |..
            let mut abc = super::addition::add_sub_noise_refresh(
                true,
                pub_keys,
                &b,
                &c,
            )?;
            // remove last element (guaranteed to be zero)
            abc.pop();

            let mut res = super::addition::add_sub_impl(
                true,
                pub_keys,
                &abc,
                &nanb,
            )?;
            // remove last element (guaranteed to be zero)
            res.pop();
        ]
    );

    Ok(res)
}

/// Schoolbook multiplication `O(n^2)`
fn mul_schoolbook(
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    measure_duration!(
        ["Multiplication schoolbook ({}-bit)", x.len()],
        [
            // calc multiplication array
            let mulary = fill_mulary(
                pub_keys,
                x,
                y,
            )?;

            // reduce multiplication array
            //TODO write a function that will be common with scalar_multiplication (if this is possible with strategies 2+)
            let mut intmd = vec![ParmCiphertext::empty(); 2];
            let mut idx = 0usize;
            intmd[idx] = super::addition::add_sub_noise_refresh(
                true,
                pub_keys,
                &mulary[0],
                &mulary[1],
            )?;

            for i in 2..x.len() {
                idx ^= 1;
                intmd[idx] = super::addition::add_sub_noise_refresh(
                    true,
                    pub_keys,
                    &intmd[idx ^ 1],
                    &mulary[i],
                )?;
            }
        ]
    );

    Ok(intmd[idx].clone())
}

/// Product of two 1-word ciphertexts
fn mul_1word(
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    measure_duration!(
        ["Multiplication 1-word"],
        [
            // calc multiplication array
            let mulary = fill_mulary(
                pub_keys,
                x,
                y,
            )?;
        ]
    );

    Ok(mulary[0].clone())
}

/// Fill multiplication array (for schoolbook multiplication)
fn fill_mulary(
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<Vec<ParmCiphertext>, Box<dyn Error>> {

    assert_eq!(x.len(), y.len());

    let len = x.len();

    // fill multiplication array
    //TODO check the size, it might grow outsite due to redundant representation
    //TODO try different approaches and compare
    let mut mulary = vec![ParmCiphertext::triv(2*len)?; len];

    mulary.par_iter_mut().zip(y.par_iter().enumerate()).for_each(| (x_yj, (j, yj)) | {
        &x_yj[j..j+len].par_iter_mut().zip(x.par_iter()).for_each(| (xi_yj, xi) | {
            *xi_yj = mul_lwe(pub_keys, &xi, &yj).expect("mul_lwe failed.");
        });
    });

    Ok(mulary)
}

/// Implementation of LWE sample multiplication, where `x` and `y` encrypt
/// a plaintext in `{-1, 0, 1}`
fn mul_lwe(
    pub_keys: &PubKeySet,
    x: &LWE,
    y: &LWE,
) -> Result<LWE, Box<dyn Error>> {

    let mut z: LWE;

    //~ measure_duration!(
        //~ "Multiplication LWE × LWE",
        //~ [
            //TODO FIXME these can be done in parallel
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
        //~ ]
    //~ );

    Ok(z)
}


// =============================================================================
//
//  Squaring
//

pub fn squ_impl(
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    let s = match x.len() {
        l if l == 1 => squ_1word(
            pub_keys,
            x,
        )?,
        l if l < 4 => squ_schoolbook(
            pub_keys,
            x,
        )?,
        l if l <= 32 => squ_dnq(
            pub_keys,
            x,
        )?,
        _ => return Err(format!("Squaring for {}-word integer not implemented.", x.len()).into()),
    };

    Ok(s)
}

//TODO
fn squ_dnq(
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {
}

fn squ_schoolbook(
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {
}

fn squ_1word(
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {
}

fn fill_squary(
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
) -> Result<Vec<ParmCiphertext>, Box<dyn Error>> {
}

fn squ_lwe(
    pub_keys: &PubKeySet,
    x: &LWE,
) -> Result<LWE, Box<dyn Error>> {
}
