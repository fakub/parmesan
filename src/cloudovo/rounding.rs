use std::error::Error;

//TODO add feature condition
pub use std::fs::{self,File,OpenOptions};
pub use std::path::Path;
pub use std::io::Write;
use crate::*;

// parallelization tools
use rayon::prelude::*;

#[allow(unused_imports)]
use colored::Colorize;

use concrete::LWE;

use crate::params::Params;
use crate::userovo::keys::PubKeySet;
use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};
use super::pbs;

pub fn round_at_impl(
    params: &Params,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    pos: usize,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    match pos {
        // no rounding needed
        0 => { Ok(x.clone()) },
        //WISH add some constant for maximum ParmCiphertext length .. p if p >= MAX_PARM_CT_LEN => { panic!("Rounding position ≥ MAX_PARM_CT_LEN.") },
        // rounding 1 digit after x.len() -> return triv of length 1 (as in multiplication of empty ciphertexts)
        p if p >= x.len() + 1 => { ParmCiphertext::triv(1, &pub_keys.encoder) },

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
            //TODO `use super::signum` etc (get rid of super::<xyz>)
            let s = super::signum::sgn_impl(params, pub_keys, &x[0..pos-1].to_vec())?;
            // calc 2y
            let mut yy_s = x[pos-1].mul_uint_constant(2)?;
            // 2y + s
            yy_s.add_uint_inplace(&s[0])?;

            // factor that is to be added
            let mut r = ParmCiphertext::triv(pos, &pub_keys.encoder)?;
            r.push(pbs::round_2y_s__pi_5(pub_keys, &yy_s)?);

            // sliced input
            let mut slx = ParmCiphertext::triv(pos, &pub_keys.encoder)?;
            slx.append(&mut x[pos..].to_vec());

            super::addition::add_sub_impl(
                true,
                pub_keys,
                &slx,
                &r,
            )

            //~ Ok(x.clone())
        }
    }
}
