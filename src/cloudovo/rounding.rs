use std::error::Error;

//TODO add feature condition
pub use std::fs::{self,File,OpenOptions};
pub use std::path::Path;
pub use std::io::Write;
use crate::*;

#[allow(unused_imports)]
use colored::Colorize;

use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};
use super::{pbs,signum};

pub fn round_at_impl(
    pc: &ParmesanCloudovo,
    x:  &ParmCiphertext,
    pos: usize,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    match pos {
        // no rounding needed
        0 => Ok(x.clone()),
        // consider if this behavior is desired:
        // p if p > PARM_CT_MAXLEN => Err(format!("Rounding position > ParmCiphertext max length {}.", PARM_CT_MAXLEN).into()),
        // rounding 1 digit after x.len() -> return triv of length 1 (as in multiplication of empty ciphertexts)
        p if p >= x.len() + 1 => Ok(ParmArithmetics::zero()),

        // otherwise, do the job

        //  * in standard binary repre, rounding is just adding the next word
        //  * in redundant binary, a bit more complicated:
        //      * for 1 and -1, one must search for the next non-zero ~ calc its sign
        //
        // let A = X ∥ y | Z ... s := sgn(Z)
        //
        // y \ s   |-1 | 0 | 1 |
        // ---------------------
        //     1   | 0 | 1 | 1 |
        //     0   | 0 | 0 | 0 |
        //    -1   |-1 | 0 | 0 |
        //
        // add: 2y + s == 2, 3 .. +1 or 2y + s == -3 .. -1 otherwise 0
        _ => {
            let s = signum::sgn_impl(pc, &x[0..pos-1].to_vec())?;
            // calc 2y
            let mut yy_s = x[pos-1].mul_uint_constant(2)?;
            // 2y + s
            yy_s.add_uint_inplace(&s[0])?;

            // factor that is to be added
            let mut r = ParmCiphertext::triv(pos, &pc.pub_keys.encoder)?;
            r.push(pbs::round_2y_s__pi_5(&pc.pub_keys, &yy_s)?);

            // sliced input
                // was:
                //~ let mut slx = ParmCiphertext::triv(pos, &pc.pub_keys.encoder)?;
                //~ slx.append(&mut x[pos..].to_vec());
                // now:
            let slx = ParmArithmetics::shift(pc, &x[pos..].to_vec(), pos);

            Ok(ParmArithmetics::add(pc, &slx, &r))
        }
    }
}
