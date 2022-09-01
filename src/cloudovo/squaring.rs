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

use crate::ciphertexts::{ParmCiphertext,ParmCiphertextImpl,ParmEncrWord};
use super::pbs;


// =============================================================================
//
//  Squaring
//

/// Choose & call appropriate algorithm for a square of a ciphertexts (Divide'n'Conquer, or schoolbook multiplication)
pub fn squ_impl(
    pc: &ParmesanCloudovo,
    x:  &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    match x.len() {
        l if l == 0     => Ok(ParmArithmetics::zero()),
        l if l == 1     => squ_1word(pc, x),
        l if l == 2     => squ_2word(pc, x),
        l if l == 3     => squ_3word(pc, x),
        l if l <=32     => squ_dnq(pc, x),
        _ => return Err(format!("Squaring for {}-word integer not implemented.", x.len()).into()),
    }
}

/// Divide'n'Conquer squaring
fn squ_dnq(
    pc: &ParmesanCloudovo,
    x:  &ParmCiphertext,
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
            //WISH check if parallelism helps for short numbers: isn't there too much overhead?

            // init tmp variables in this scope, only references can be passed to threads
            let mut a = ParmCiphertext::empty();
            let mut b = ParmCiphertext::empty();
            let mut c = ParmCiphertext::empty();

            let ar = &mut a;
            let br = &mut b;
            let cr = &mut c;

            //PBS comment scopes out
            // parallel pool: A, B, C
            thread::scope(|abc_scope| {
                abc_scope.spawn(|_| {
                    //  A = x_1 ^ 2                     .. len1-bit squaring
                    *ar = ParmArithmetics::squ(pc, &x1);
                });
                abc_scope.spawn(|_| {
                    //  B = x_0 ^2                      .. len0-bit squaring
                    *br = ParmArithmetics::squ(pc, &x0);
                });
                abc_scope.spawn(|_| {
                    //  C = x_0 * x_1                   .. len0- x len1-bit multiplication (to be shifted len0 + 1 bits where 1 bit is for 2x AB)
                    let c_plain = ParmArithmetics::mul(pc, &x0, &x1);
                    *cr = ParmArithmetics::shift(pc, &c_plain, len0 + 1);
                });
            }).expect("thread::scope abc_scope failed.");

            //  |   A   |   B   |   TBD based on overlap
            //     |   C   |  0 |   in c
            //  add everything together
            let res = if b.len() == 2*len0 {
                //  | A | B |   simply concat
                b.append(&mut a);
                ParmArithmetics::add(pc, &b, &c)
            } else {
                //  first, add | C |0| to | B |
                let b_c = ParmArithmetics::add(pc, &b, &c);
                //  second, add | C |0|+| B | to | A |0|0|
                let a_sh = ParmArithmetics::shift(pc, &a, 2*len0);
                ParmArithmetics::add(pc, &a_sh, &b_c)
            };
        ]
    );

    //PBS unsafe { println!("(after DnQ {}-bit)    #BS = {}", x.len(), NBS); }

    Ok(res)
}

/// Square of a 1-bit ciphertext
fn squ_1word(
    pc: &ParmesanCloudovo,
    x:  &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    measure_duration!(
        ["Squaring 1-word"],
        [
            //
            let sqbit = pbs::a_1__pi_5(pc, &x[0])?;
        ]
    );

    Ok(ParmCiphertext::single(sqbit))
}

/// Square of a 2-bit ciphertext
fn squ_2word(
    pc: &ParmesanCloudovo,
    x:  &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    assert_eq!(x.len(), 2);
    let mut res = ParmCiphertext::triv(2*x.len(), &pc.params)?;

    //      x y
    //      x y
    // ---------
    //  a b c d   -> res (reversed endian)

    measure_duration!(
        ["Squaring 2-word"],
        [
            // get value of x
            let mut x_val = x[1].mul_const(2)?;
            x_val.add_inplace(&x[0])?;

            // calc the 4 bits in parallel
            //TODO create just 3 threads !! a^2 mod 4 in {0,1}
            res.par_iter_mut().enumerate().for_each(| (i, ri) | {
                *ri = pbs::squ_3_bit__pi_5(pc, &x_val, i).expect("pbs::squ_3_bit__pi_5 failed.");
            });
        ]
    );

    Ok(res)
}

/// Square of a 3-bit ciphertext
fn squ_3word(
    pc: &ParmesanCloudovo,
    x:  &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    assert_eq!(x.len(), 3);
    let mut res = ParmCiphertext::triv(2*x.len(), &pc.params)?;

    //      x y z
    //      x y z
    // -----------
    // a b c d ...   -> res (reversed endian)

    measure_duration!(
        ["Squaring 3-word"],
        [
            // get value of x
            let mut x_val = x[2].mul_const(2)?;
            x_val.add_inplace(&x[1])?;
            x_val.mul_const_inplace(2)?;
            x_val.add_inplace(&x[0])?;

            // calc the 6 bits in parallel
            //TODO create just 5 threads !! a^2 mod 4 in {0,1}
            res.par_iter_mut().enumerate().for_each(| (i, ri) | {
                *ri = pbs::squ_3_bit__pi_5(pc, &x_val, i).expect("pbs::squ_3_bit__pi_5 failed.");
            });
        ]
    );

    Ok(res)
}

/// Implementation of LWE sample squaring, where `x` encrypts a plaintext
/// in `{-1, 0, 1}`
pub fn squ_lwe(
    pc: &ParmesanCloudovo,
    x: &ParmEncrWord,
) -> Result<ParmEncrWord, Box<dyn Error>> {
    pbs::a_1__pi_5(pc, x)
}
