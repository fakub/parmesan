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
            //  A = x_1 * y_1                   .. len1-bit multiplication
            let mut a = mul_impl(
                pub_keys,
                &x1,
                &y1,
            )?;

            //  B = x_0 * y_0                   .. len0-bit multiplication
            let mut b = mul_impl(
                pub_keys,
                &x0,
                &y0,
            )?;

            //  C = (x_0 + x_1) * (y_0 + y_1)   .. (len0 + 1)-bit multiplication
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

            let mut ab_sh = ParmCiphertext::empty();
            //  AB <- | A | B |
            let ab = if b.len() == 2*len0 {
                //  | A | B |
                b.append(&mut a);
                &b
            } else {
                //  | A | 0 | + | B |   because of overlap
                let mut a_sh  = ParmCiphertext::triv(len0)?;
                a_sh.append(&mut a);
                ab_sh = super::addition::add_sub_noise_refresh(
                    true,
                    pub_keys,
                    &a_sh,
                    &b,
                )?;
                &ab_sh
            };

            //  |   A   |   B   |   in ab
            //     |    C   |       in c
            //      |  -A   |       in nanb
            //      |  -B   |       -- " --

            //  |  C | + | -A - B |..
            let cnanb = super::addition::add_sub_noise_refresh(
                true,
                pub_keys,
                &c,
                &nanb,
            )?;
            //FIXME last element is NOT guaranteed to be zero (in redundant representation)
            //      * in case A and B need to be added:
            //          * last thing to be added is A, then it should not grow more than 1 bit
            //          * short cases must be considered

            let res = super::addition::add_sub_impl(
                true,
                pub_keys,
                ab,
                &cnanb,
            )?;
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

    //FIXME check whether nested parallel iterators work as expected
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
        //TODO check for l = 3, fix odd lengths (now they do not work, even in recursion!)
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

fn squ_dnq(
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    let len0 = (x.len() + 1) / 2;

    //       len1  len0
    //  x = | x_1 | x_0 |
    let mut x0 = ParmCiphertext::empty();
    let mut x1 = ParmCiphertext::empty();

    // divide
    for (i, xi) in x.iter().enumerate() {
        if i < len0 {
            x0.push(xi.clone());
        } else {
            x1.push(xi.clone());
        }
    }

    measure_duration!(
        ["Squaring Divide & Conquer ({}-bit)", x.len()],
        [
            //  A = x_1 ^ 2                     .. len1-bit squaring
            let mut a = squ_impl(
                pub_keys,
                &x1,
            )?;

            //  B = x_0 ^2                      .. len0-bit squaring
            let mut b = squ_impl(
                pub_keys,
                &x0,
            )?;

            //  B <- | A | B |
            b.append(&mut a);

            //  C = x_0 * x_1                   .. len0- x len1-bit multiplication (to be shited len0 + 1 bits where 1 bit is for 2x AB)
            let mut c = ParmCiphertext::triv(len0 + 1)?;
            let mut c_plain = mul_impl(
                pub_keys,
                &x0,
                &x1,
            )?;
            c.append(&mut c_plain);

            //  |   A   |   B   |   in b
            //     |   C   |        in c
            let mut res = super::addition::add_sub_noise_refresh(
                true,
                pub_keys,
                &b,
                &c,
            )?;
            //FIXME same as for multiplication
            // remove last element (guaranteed to be zero)
            //~ res.pop();
        ]
    );

    Ok(res)
}

fn squ_schoolbook(
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    measure_duration!(
        ["Squaring schoolbook ({}-bit)", x.len()],
        [
            // calc multiplication array
            let squary = fill_squary(
                pub_keys,
                x,
            )?;

            // reduce squaring array
            //TODO write a function that will be common with scalar_multiplication (if this is possible with strategies 2+)
            let mut intmd = vec![ParmCiphertext::empty(); 2];
            let mut idx = 0usize;
            intmd[idx] = super::addition::add_sub_noise_refresh(
                true,
                pub_keys,
                &squary[0],
                &squary[1],
            )?;

            for i in 2..x.len() {
                idx ^= 1;
                intmd[idx] = super::addition::add_sub_noise_refresh(
                    true,
                    pub_keys,
                    &intmd[idx ^ 1],
                    &squary[i],
                )?;
            }
        ]
    );

    Ok(intmd[idx].clone())
}

fn squ_1word(
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    measure_duration!(
        ["Squaring 1-word"],
        [
            // calc squaring array
            let squary = fill_squary(
                pub_keys,
                x,
            )?;
        ]
    );

    Ok(squary[0].clone())
}

fn fill_squary(
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
) -> Result<Vec<ParmCiphertext>, Box<dyn Error>> {

    let len = x.len();
    let x2 = x.clone();   //TODO needed? intended for parallel addition to avoid concurrent memory access

    // fill temp squaring array
    let mut squary_tmp  = vec![ParmCiphertext::triv(2*len)?; len];
    let mut squary      = vec![ParmCiphertext::triv(2*len)?; len];

    squary_tmp.par_iter_mut().zip(x.par_iter().enumerate()).for_each(| (sqi, (i, xi)) | {
        &sqi[i..].par_iter_mut().zip(x2.par_iter().enumerate()).for_each(| (sqij, (j, x2j)) | {
            if j < i {
                *sqij = mul_lwe(pub_keys, &xi, &x2j).expect("mul_lwe failed.");
            } else if j == i {
                *sqij = squ_lwe(pub_keys, &xi).expect("squ_lwe failed.");
            }
        });
    });

    // copy values & identities
    for (i, sqi) in squary.iter_mut().enumerate() {
        for (j, sqij) in sqi[i..].iter_mut().enumerate() {
            if j <= i {
                *sqij = squary_tmp[i][i+j].clone();
            } else if j > i && j < len {
                *sqij = squary_tmp[j][i+j].clone();
            }
        }
    }

    Ok(squary)
}

fn squ_lwe(
    pub_keys: &PubKeySet,
    x: &LWE,
) -> Result<LWE, Box<dyn Error>> {
    Ok(pbs::a_1__pi_5(pub_keys, x)?)
}
