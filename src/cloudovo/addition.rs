use std::error::Error;

pub use std::fs::{self,File,OpenOptions};
pub use std::path::Path;
pub use std::io::Write;

use crate::*;

// parallelization tools
use rayon::prelude::*;

#[allow(unused_imports)]
use colored::Colorize;

use concrete::LWE;

use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};
use super::pbs;

/// Implementation of parallel addition/subtraction
pub fn add_sub_impl(
    is_add: bool,
    pc: &ParmesanCloudovo,
    x:  &ParmCiphertext,
    y:  &ParmCiphertext,
    refresh: bool,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    // calculate right overlap of trivial zero samples (any)
    //             ____
    //  001001███010000
    //     0010█████100
    //
    //WISH calc as in paper: i.e., whenever x_i + y_i is known to be in {-1,0,1} .. i.e., not only triv zeros
    //
    let mut x_rzero = 0usize;
    let mut y_rzero = 0usize;
    for xi in x {
        if xi.dimension == 0 && xi.ciphertext.get_body().0 == 0 {x_rzero += 1;} else {break;}
    }
    for yi in y {
        if yi.dimension == 0 && yi.ciphertext.get_body().0 == 0 {y_rzero += 1;} else {break;}
    }
    // resolve all-triv-zeros cases
    if x_rzero == x.len() { return if is_add {Ok(y.clone())} else {Ok(ParmArithmetics::opp(y))};}
    if y_rzero == y.len() { return Ok(x.clone());}
    // continue with non-trivial cases
    let r_triv = std::cmp::max(x_rzero, y_rzero);

    // calculate length of w that is to be calculated (incl. right zeros)
    //    _____________                                                           _________   wlen      \
    //  001001███010000         n.b.:   0000 .. wlen == 0, but r_triv == 4      001██000000              |  =>  apparently wlen <= r_triv iff wlen == 0,
    //     0010█████100                                                         000000001█0              |      in which case the result is zero
    //                                                                               ------   r_triv    /
    let mut x_lzero  = 0usize;
    let mut y_lzero  = 0usize;
    for xi in x.iter().rev() {
        if xi.dimension == 0 && xi.ciphertext.get_body().0 == 0 {x_lzero += 1;} else {break;}
    }
    for yi in y.iter().rev() {
        if yi.dimension == 0 && yi.ciphertext.get_body().0 == 0 {y_lzero += 1;} else {break;}
    }
    let wlen = std::cmp::max(x.len() - x_lzero, y.len() - y_lzero);

    let mut z: ParmCiphertext;

    // parallel addition/subtraction
    measure_duration!(
        ["Parallel {} ({}-bit, {} active)", if is_add {"addition"} else {"subtraction"}, wlen, wlen - r_triv],
        [
            let mut w = ParmCiphertext::empty();
            // fill w with x up to wlen (x might be shorter!)
            for (i, xi) in x.iter().enumerate() {
                if i == wlen {break;}
                w.push(xi.clone());
            }
            // if x is shorter than wlen, fill the rest with zeros
            for _ in 0..((wlen as i64) - (x.len() as i64)) {
                w.push(LWE::encrypt_uint_triv(0, &pc.pub_keys.encoder)?);
            }
            // now w has the correct length!

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

            let mut q = ParmCiphertext::triv(wlen, &pc.pub_keys.encoder)?;

            // this shall not happen
            if r_triv >= q.len() {
                println!(">>> add fail:");
                println!("\tx.len = {}", x.len());
                println!("\tx_rzero = {}", x_rzero);
                println!("\tx_lzero = {}", x_lzero);
                println!("\ty.len = {}", y.len());
                println!("\ty_rzero = {}", y_rzero);
                println!("\ty_lzero = {}", y_lzero);
                return Err("Unexpected fatal error!".into());
            }

            //PBS q[r_triv..].iter_mut().zip(w[r_triv..].iter().enumerate()).for_each(| (qi, (i0, wi)) | {
            q[r_triv..].par_iter_mut().zip(w[r_triv..].par_iter().enumerate()).for_each(| (qi, (i0, wi)) | {
                let i = i0 + r_triv;
                // calc   3 w_i + w_i-1
                let mut wi_3 = wi.mul_uint_constant(3).expect("mul_uint_constant failed.");
                if i0 > 0 { wi_3.add_uint_inplace(&w[i-1]).expect("add_uint_inplace failed."); }
                *qi = pbs::f_4__pi_5(&pc.pub_keys, &wi_3).expect("f_4__pi_5 failed.");
            });

            // w_i += -2 q_i + q_i-1
            //WISH also check this, if parallel is better? (there's no BS)
            w.iter_mut().zip(q.iter().enumerate()).for_each(| (wi, (i, qi)) | {
                // calc   2 q_i
                let qi_2 = qi.mul_uint_constant(2).expect("mul_uint_constant failed.");
                wi.sub_uint_inplace(&qi_2).expect("sub_uint_inplace failed.");
                if i > 0 { wi.add_uint_inplace(&q[i-1]).expect("add_uint_inplace failed."); }
            });

            // init z of zeros of wlen length, then clone / bootstrap ID from w, finally push carry q_i-1
            z = ParmCiphertext::triv(wlen, &pc.pub_keys.encoder)?;
            // MSB part of z is bootstrapped (if requested) ...
            if refresh {
                //PBS z[r_triv..].iter_mut().zip(w[r_triv..].iter()).for_each(| (zi, wi) | {
                z[r_triv..].par_iter_mut().zip(w[r_triv..].par_iter()).for_each(| (zi, wi) | {
                    *zi = pbs::id__pi_5(&pc.pub_keys, wi).expect("pbs::id__pi_5 failed.");
                });
            } else {
                z[r_triv..].iter_mut().zip(w[r_triv..].iter()).for_each(| (zi, wi) | {
                    *zi = wi.clone();
                });
            }
            // ... LSB part is simply copied
            z[..r_triv].iter_mut().zip(w[..r_triv].iter()).for_each(| (zi, wi) | {
                *zi = wi.clone();
            });
            // finally prepend local carry: z_n = 0 + 2*0 + q_n-1
            z.push(q.last().unwrap().clone());
        ]
    );

    //PBS unsafe { println!("(after add {}-bit actv)    #BS = {}", wlen - r_triv, NBS); }

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
    pc: &ParmesanCloudovo,
    x:  &ParmCiphertext,
    k:  i64,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    // resolve k == 0
    if k == 0 {
        return Ok(x.clone());
    }

    let k_abs = k.abs();   // deal with -2^63, for which abs() panics, because it does not fit i64
    let k_pos = k >= 0;

    let mut k_len = 0usize;
    for i in 0..63 {if k_abs & (1 << i) != 0 {k_len = i + 1;}}

    let mut ck = ParmCiphertext::empty();

    //TODO put into ParmArithmetics::const (check!)
    for i in 0..k_len {
        // calculate i-th bit with sign
        let ki = if ((k_abs >> i) & 1) == 0 {
            0u32
        } else {
            if k_pos {1u32} else {pc.params.plaintext_mask() as u32}
        };

        // encrypt as trivial sample
        let cti = LWE::encrypt_uint_triv(
            ki,
            &pc.pub_keys.encoder,
        )?;

        ck.push(cti);
    }

    Ok(ParmArithmetics::add(pc, x, &ck))
}
