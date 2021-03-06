use std::error::Error;

pub use std::fs::{self,File,OpenOptions};
pub use std::path::Path;
pub use std::io::Write;
use crate::*;

// parallelization tools
use rayon::prelude::*;
use crossbeam_utils::thread;

#[allow(unused_imports)]
use colored::Colorize;

use concrete::LWE;

use crate::userovo::keys::PubKeySet;
use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};
use super::pbs;


// =============================================================================
//
//  Multiplication
//

/// Choose & call appropriate algorithm for a product of two ciphertexts (Karatsuba, or schoolbook multiplication)
pub fn mul_impl(
    pc: &ParmesanCloudovo,
    x:  &ParmCiphertext,
    y:  &ParmCiphertext,
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

    let mut x_in = x.clone();
    let mut y_in = y.clone();

    // align lengths of x & y
    if x_in.len() != y_in.len() {
        let len_diff = ((y_in.len() as i32) - (x_in.len() as i32)).abs();

        for _i in 0..len_diff {
            if x_in.len() < y_in.len() {
                x_in.push(LWE::encrypt_uint_triv(0, &pc.pub_keys.encoder)?);
            } else {
                y_in.push(LWE::encrypt_uint_triv(0, &pc.pub_keys.encoder)?);
            }
        }
    }

    //TODO FIXME recalc bounds for schoolbook as mul_lwe has changed (improved)
    match x_in.len() {
        l if l == 0 => Ok(ParmArithmetics::zero()),
        l if l == 1 => mul_1word(
            pc,
            &x_in,
            &y_in,
        ),
        l if l < 14 || l == 15 => mul_schoolbook(
            pc,
            &x_in,
            &y_in,
        ),
        l if l <= 32 => mul_karatsuba(
            pc,
            &x_in,
            &y_in,
        ),
        _ => Err(format!("Multiplication for {}-word integers not implemented.", x_in.len()).into()),
    }
}

/// Karatsuba multiplication
fn mul_karatsuba(
    pc: &ParmesanCloudovo,
    x:  &ParmCiphertext,
    y:  &ParmCiphertext,
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
            //WISH check if parallelism helps for short numbers: isn't there too much overhead?

            // init tmp variables in this scope, only references can be passed to threads
            let mut a       = ParmCiphertext::empty();
            let mut b       = ParmCiphertext::empty();
            let mut na_nb   = ParmCiphertext::triv(len0, &pc.pub_keys.encoder)?;
            let mut c       = ParmCiphertext::triv(len0, &pc.pub_keys.encoder)?;

            let ar      = &mut a;
            let br      = &mut b;
            let na_nbr  = &mut na_nb;
            let cr      = &mut c;

            // parallel pool: A, B, C
            thread::scope(|abc_scope| {
                // calc A, B, and -A - B
                abc_scope.spawn(|_| {
                    // parallel pool: A, B
                    thread::scope(|ab_scope| {
                        ab_scope.spawn(|_| {
                            // A = x_1 * y_1                   .. len1-bit multiplication
                            *ar  = ParmArithmetics::mul(pc, &x1, &y1);
                        });
                        ab_scope.spawn(|_| {
                            // B = x_0 * y_0                   .. len0-bit multiplication
                            *br  = ParmArithmetics::mul(pc, &x0, &y0);
                        });
                    }).expect("thread::scope ab_scope failed.");
                    //  A + B .. -A - B
                    let pa_pb = ParmArithmetics::add(pc, ar, br);
                    for abi in pa_pb {
                        na_nbr.push(abi.opposite_uint().expect("opposite_uint failed."));
                    }
                });

                // calc C
                abc_scope.spawn(|_| {
                    let mut x01 = ParmCiphertext::empty();
                    let mut y01 = ParmCiphertext::empty();
                    let x01r = &mut x01;
                    let y01r = &mut y01;
                    // parallel pool: (x_0 + x_1), (y_0 + y_1)
                    thread::scope(|c_scope| {
                        c_scope.spawn(|_| { *x01r = ParmArithmetics::add(pc, &x0, &x1); });
                        c_scope.spawn(|_| { *y01r = ParmArithmetics::add(pc, &y0, &y1); });
                    }).expect("thread::scope c_scope failed.");
                    // C = (x_0 + x_1) * (y_0 + y_1)   .. (len0 + 1)-bit multiplication
                    let mut c_plain = ParmArithmetics::mul(pc, &x01, &y01);
                    cr.append(&mut c_plain);
                });
            }).expect("thread::scope abc_scope failed.");

            //  |   A   |   B   |   TBD based on overlap
            //     |    C   | 0 |   in c
            //      | -A-B  | 0 |   in na_nb

            //  |  C | 0 | + | -A-B | 0 |
            let c_nanb = ParmArithmetics::add(pc, &c, &na_nb);

            //  add everything together
            let res = if b.len() == 2*len0 {
                //  | A | B |   simply concat
                b.append(&mut a);
                ParmArithmetics::add(pc, &b, &c_nanb)
            } else {
                //  first, add |c-a-b|0| to |b|
                let b_cnanb = ParmArithmetics::add(pc, &b, &c_nanb);
                //  second, add |c-a-b|0|+|b| to a|0|0|
                //  n.b., this way, the resulting ciphertext grows the least (1 bit only) and it also uses least BS inside additions
                    // was:
                    //~ let mut a_sh  = ParmCiphertext::triv(2*len0, &pc.pub_keys.encoder)?;
                    //~ a_sh.append(&mut a);
                    // now:
                let a_sh = ParmArithmetics::shift(pc, &a, 2*len0);
                ParmArithmetics::add(pc, &a_sh, &b_cnanb)
            };
        ]
    );

    Ok(res)
}

/// Schoolbook multiplication `O(n^2)`
fn mul_schoolbook(
    pc: &ParmesanCloudovo,
    x:  &ParmCiphertext,
    y:  &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    measure_duration!(
        ["Multiplication schoolbook ({}-bit)", x.len()],
        [
            // calc multiplication array
            let mulary = fill_mulary(
                &pc.pub_keys,
                x,
                y,
            )?;

            let res = reduce_mulsquary(pc, &mulary);
        ]
    );

    Ok(res)
}

/// Product of two 1-word ciphertexts
fn mul_1word(
    pc: &ParmesanCloudovo,
    x:  &ParmCiphertext,
    y:  &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    measure_duration!(
        ["Multiplication 1-word"],
        [
            // calc multiplication array
            let mulary = fill_mulary(
                &pc.pub_keys,
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
    //WISH try different approaches and compare
    let mut mulary = vec![ParmCiphertext::triv(2*len, &pub_keys.encoder)?; len];

    // nested parallel iterators work as expected: they indeed create nested pools
    mulary.par_iter_mut().zip(y.par_iter().enumerate()).for_each(| (x_yj, (j, yj)) | {
        x_yj[j..j+len].par_iter_mut().zip(x.par_iter()).for_each(| (xi_yj, xi) | {
            *xi_yj = mul_lwe(pub_keys, &xi, &yj).expect("mul_lwe failed.");
        });
    });

    Ok(mulary)
}

/// Implementation of LWE sample multiplication, where `x` and `y` encrypt
/// a plaintext in `{-1, 0, 1}`
pub fn mul_lwe(
    pub_keys: &PubKeySet,
    x: &LWE,
    y: &LWE,
) -> Result<LWE, Box<dyn Error>> {

    // resolve trivial cases
    //WISH check correctness
    let pi = x.encoder.nb_bit_precision;
    if x.dimension == 0 {
        let mut mx: i32 = x.decrypt_uint_triv()? as i32;
        // convert to signed domain
        if mx > 1 << (pi - 1) {mx -= 1 << pi}
        return Ok(y.mul_uint_constant(mx)?);
    } else if y.dimension == 0 {
        let mut my: i32 = y.decrypt_uint_triv()? as i32;
        // convert to signed domain
        if my > 1 << (pi - 1) {my -= 1 << pi}
        return Ok(x.mul_uint_constant(my)?);
    }

    //  X | -1 |  0 |  1 |
    //--------------------
    //  1 | -1 |  0 |  1 |
    //  0 |  0 |  0 |  0 |
    // -1 |  1 |  0 | -1 |
    //--------------------
    // => serialize this table (fits 32 cleartext size)

    // 3x + y
    let mut p3xpy = x.mul_uint_constant(3)?;
    p3xpy.add_uint_inplace(y)?;

    // LUT serialized table
    pbs::mul_bit__pi_5(pub_keys, &p3xpy)
}

pub fn reduce_mulsquary (
    pc: &ParmesanCloudovo,
    mulary: &Vec<ParmCiphertext>,
) -> ParmCiphertext {
    let mut intmd = vec![ParmCiphertext::empty(); 2];
    let mut idx = 0usize;
    intmd[idx] = ParmArithmetics::add(pc, &mulary[0], &mulary[1]);

    //TODO add parallelism except for the longest number (so that the result is as short as possible)
    for i in 2..mulary.len() {
        idx ^= 1;
        intmd[idx] = ParmArithmetics::add(pc, &intmd[idx ^ 1], &mulary[i]);
    }

    intmd[idx].clone()
}

////////////////////////////////////////////////////////////////////////////////

// for archiving purposes (also presenting author's stupidity)
#[allow(non_snake_case)]
pub fn deprecated__mul_lwe(
    pub_keys: &PubKeySet,
    x: &LWE,
    y: &LWE,
) -> Result<LWE, Box<dyn Error>> {
    let mut z: LWE;
    let pi = x.encoder.nb_bit_precision;
    if x.dimension == 0 {
        let mut mx: i32 = x.decrypt_uint_triv()? as i32;
        // convert to signed domain
        if mx > 1 << (pi - 1) {mx -= 1 << pi}
        return Ok(y.mul_uint_constant(mx)?);
    } else if y.dimension == 0 {
        let mut my: i32 = y.decrypt_uint_triv()? as i32;
        // convert to signed domain
        if my > 1 << (pi - 1) {my -= 1 << pi}
        return Ok(x.mul_uint_constant(my)?);
    }

    // x + y
    let mut pxpy: LWE = x.clone();
    pxpy.add_uint_inplace(y)?;
    // x - y
    let mut pxny: LWE = x.clone();
    pxny.sub_uint_inplace(y)?;

    // pos, neg (in parallel)
    // init tmp variables in this scope, only references can be passed to threads
    let mut pos = LWE::encrypt_uint_triv(0, &pub_keys.encoder).expect("LWE::encrypt_uint_triv failed.");
    let mut neg = LWE::encrypt_uint_triv(0, &pub_keys.encoder).expect("LWE::encrypt_uint_triv failed.");
    let posr = &mut pos;
    let negr = &mut neg;

    // parallel pool: pos, neg
    thread::scope(|pn_scope| {
        pn_scope.spawn(|_| {
            // pos = ...
            *posr  = pbs::a_2__pi_5(pub_keys, &pxpy).expect("pbs::a_2__pi_5 failed.");
        });
        pn_scope.spawn(|_| {
            // neg = ...
            *negr  = pbs::a_2__pi_5(pub_keys, &pxny).expect("pbs::a_2__pi_5 failed.");
        });
    }).expect("thread::scope pn_scope failed.");

    // z = pos - neg
    z = pos.clone();
    z.sub_uint_inplace(&neg)?;

    Ok(z)
}
