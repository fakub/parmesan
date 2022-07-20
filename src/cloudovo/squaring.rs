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
use super::{pbs, multiplication};


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
        l if l <  4     => squ_schoolbook(pc, x),
        //DBG
        //~ l if l <=32     => squ_dnq(pc, x),
        l if l <=34     => squ_dnq(pc, x),
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

            //DBG
            // parallel pool: A, B, C
            //~ thread::scope(|abc_scope| {
                //~ abc_scope.spawn(|_| {
                    //  A = x_1 ^ 2                     .. len1-bit squaring
                    *ar = ParmArithmetics::squ(pc, &x1);
                //~ });
                //~ abc_scope.spawn(|_| {
                    //  B = x_0 ^2                      .. len0-bit squaring
                    *br = ParmArithmetics::squ(pc, &x0);
                //~ });
                //~ abc_scope.spawn(|_| {
                    //  C = x_0 * x_1                   .. len0- x len1-bit multiplication (to be shifted len0 + 1 bits where 1 bit is for 2x AB)
                    let c_plain = ParmArithmetics::mul(pc, &x0, &x1);
                        // was:
                        //~ *cr = ParmCiphertext::triv(len0 + 1, &pc.pub_keys.encoder).expect("ParmCiphertext::triv failed.");
                        //~ cr.append(&mut c_plain);
                        // now:
                    *cr = ParmArithmetics::shift(pc, &c_plain, len0 + 1);
                //~ });
            //~ }).expect("thread::scope abc_scope failed.");

            //  |   A   |   B   |   TBD based on overlap
            //     |   C   |  0 |   in c
            //  add everything together
            let res = if b.len() == 2*len0 {
                //DBG
                println!(" >  concat A | B");
                //  | A | B |   simply concat
                b.append(&mut a);
                ParmArithmetics::add(pc, &b, &c)
            } else {
                //DBG
                println!(" >  c + b -> + a");
                //  first, add | C |0| to | B |
                let b_c = ParmArithmetics::add(pc, &b, &c);
                //  second, add | C |0|+| B | to | A |0|0|
                    // was:
                    //~ let mut a_sh  = ParmCiphertext::triv(2*len0, &pc.pub_keys.encoder)?;
                    //~ a_sh.append(&mut a);
                    // now:
                let a_sh = ParmArithmetics::shift(pc, &a, 2*len0);
                ParmArithmetics::add(pc, &a_sh, &b_c)
            };
        ]
    );
    //DBG
    unsafe { println!("(after DnQ {}-bit)    #BS = {}", x.len(), NBS); }

    Ok(res)
}

/// Schoolbook squaring `O(n^2)`
fn squ_schoolbook(
    pc: &ParmesanCloudovo,
    x:  &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    measure_duration!(
        ["Squaring schoolbook ({}-bit)", x.len()],
        [
            // calc multiplication array
            let squary = fill_squary(
                &pc.pub_keys,
                x,
            )?;
            //DBG
            unsafe { println!("(after fill squary {}-bit)    #BS = {}", x.len(), NBS); }

            let res = multiplication::reduce_mulsquary(pc, &squary);
        ]
    );
    //DBG
    unsafe { println!("(after rdc squary {}-bit)    #BS = {}", x.len(), NBS); }

    Ok(res)
}

/// Square of a 1-word ciphertext
fn squ_1word(
    pc: &ParmesanCloudovo,
    x:  &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    measure_duration!(
        ["Squaring 1-word"],
        [
            // calc squaring array
            let squary = fill_squary(
                &pc.pub_keys,
                x,
            )?;
        ]
    );

    Ok(squary[0].clone())
}

/// Fill squaring array (for schoolbook squaring)
fn fill_squary(
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
) -> Result<Vec<ParmCiphertext>, Box<dyn Error>> {

    let len = x.len();
    let x2 = x.clone();   //WISH needed? intended for parallel addition to avoid concurrent memory access

    // fill temp squaring array
    let mut squary_tmp  = vec![ParmCiphertext::triv(2*len, &pub_keys.encoder)?; len];
    let mut squary      = vec![ParmCiphertext::triv(2*len, &pub_keys.encoder)?; len];

    //WISH prepare designated arrays (one for diagonal, another for upper-diagonal; reorder them after calculations; would it help at all?)
    //DBG
    //~ squary_tmp.par_iter_mut().zip(x.par_iter().enumerate()).for_each(| (sqi, (i, xi)) | {
        //~ sqi[i..].par_iter_mut().zip(x2.par_iter().enumerate()).for_each(| (sqij, (j, x2j)) | {
    squary_tmp.iter_mut().zip(x.iter().enumerate()).for_each(| (sqi, (i, xi)) | {
        sqi[i..].iter_mut().zip(x2.iter().enumerate()).for_each(| (sqij, (j, x2j)) | {
            if j < i {
                *sqij = multiplication::mul_lwe(pub_keys, &xi, &x2j).expect("mul_lwe failed.");
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

/// Implementation of LWE sample squaring, where `x` encrypts a plaintext
/// in `{-1, 0, 1}`
pub fn squ_lwe(
    pub_keys: &PubKeySet,
    x: &LWE,
) -> Result<LWE, Box<dyn Error>> {
    pbs::a_1__pi_5(pub_keys, x)
}
