use std::error::Error;

#[cfg(not(feature = "sequential"))]
use rayon::prelude::*;
use concrete::LWE;
#[allow(unused_imports)]
use colored::Colorize;
use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};
use crate::userovo::keys::PubKeySet;
use crate::params::Params;
use super::pbs;

/// Parallel addition/subtraction followed by noise refreshal
pub fn add_sub_noise_refresh(
    is_add: bool,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    let z_noisy = add_sub_impl(
        is_add,
        pub_keys,
        x,
        y,
    )?;

    let mut z = ParmCiphertext::triv(z_noisy.len())?;

    z_noisy.par_iter().zip(z.par_iter_mut()).for_each(| (zni, zi) | {
        *zi = pbs::id(pub_keys, zni).expect("pbs::id failed.");
    });

    Ok(z)
}

/// Implementation of parallel addition/subtraction
pub fn add_sub_impl(
    is_add: bool,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    // calculate right overlap of trivial zero samples (any)
    //             ____
    //  001001███010000
    //     0010█████100
    //
    let mut x_rzero = 0usize;
    let mut y_rzero = 0usize;
    for xi in x {
        if xi.dimension == 0 && xi.ciphertext.get_body().0 == 0 {x_rzero += 1;} else {break;}
    }
    for yi in y {
        if yi.dimension == 0 && yi.ciphertext.get_body().0 == 0 {y_rzero += 1;} else {break;}
    }
    let r_triv = std::cmp::max(x_rzero, y_rzero);

    // calculate length of w that is to be calculated (incl. right zeros)
    //    _____________
    //  001001███010000
    //     0010█████100
    //
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

    //  Scenario A   -----------------------------------------------------------
    #[cfg(feature = "sc_A")]
    {
    measure_duration!(
        ["Sequential {}, sc. A ({}-bit, {} active)", if is_add {"addition"} else {"subtraction"}, wlen, wlen - r_triv],
        [
            // init result & carry
            z = ParmCiphertext::empty();
            let mut c: LWE = LWE::zero(0)?;

            for (xi, yi) in x.iter().zip(y.iter()) {
                // z_i = x_i XOR y_i XOR c
                let wi = pbs::XOR(pub_keys, xi, yi)?;
                z.push(pbs::XOR(pub_keys, &wi, &c)?);

                // c = (x_i AND y_i) XOR (c AND (x_i XOR y_i))
                let t1 = pbs::AND(pub_keys, xi, yi)?; // temp_1 = x_i AND y_i
                let t2 = pbs::AND(pub_keys, &c,&wi)?; // temp_2 = c AND w_i
                c = pbs::XOR(pub_keys, &t1, &t2)?;
            }

            z.push(c);
        ]
    );
    }

    //  Scenario B   -----------------------------------------------------------
    #[cfg(feature = "sc_B")]
    {
    measure_duration!(
        ["Sequential {}, sc. B ({}-bit, {} active)", if is_add {"addition"} else {"subtraction"}, wlen, wlen - r_triv],
        [
            z = x.clone(); //TODO
        ]
    );
    }

    //  Scenario C   -----------------------------------------------------------
    #[cfg(feature = "sc_C")]
    {
    measure_duration!(
        ["Sequential {}, sc. C ({}-bit, {} active)", if is_add {"addition"} else {"subtraction"}, wlen, wlen - r_triv],
        [
            z = x.clone(); //TODO
        ]
    );
    }

    //  Scenario D   -----------------------------------------------------------
    #[cfg(feature = "sc_D")]
    {
    measure_duration!(
        ["Sequential {}, sc. D ({}-bit, {} active)", if is_add {"addition"} else {"subtraction"}, wlen, wlen - r_triv],
        [
            z = x.clone(); //TODO
        ]
    );
    }

    //  Scenario E   -----------------------------------------------------------
    #[cfg(feature = "sc_E")]
    {
    measure_duration!(
        ["Sequential {}, sc. E ({}-bit, {} active)", if is_add {"addition"} else {"subtraction"}, wlen, wlen - r_triv],
        [
            z = x.clone(); //TODO
        ]
    );
    }

    //  Scenario F   -----------------------------------------------------------
    #[cfg(feature = "sc_F")]
    {
    measure_duration!(
        ["Parallel {}, sc. F ({}-bit, {} active)", if is_add {"addition"} else {"subtraction"}, wlen, wlen - r_triv],
        [
            let mut w = ParmCiphertext::empty();
            // fill w with x up to wlen (x might be shorter!)
            for (i, xi) in x.iter().enumerate() {
                if i == wlen {break;}
                w.push(xi.clone());
            }
            // if x is shorter than wlen, fill the rest with zeros
            for _ in 0..((wlen as i64) - (x.len() as i64)) {
                w.push(LWE::zero(0)?);
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

            let mut q = ParmCiphertext::triv(w.len())?;
            z = w.clone();
            // one more word for "carry"
            z.push(LWE::zero(0)?);

            q[r_triv..].par_iter_mut().zip(w[r_triv..].par_iter().enumerate()).for_each(| (qi, (i0, wi)) | {
                let i = i0 + r_triv;
                // calc   3 w_i + w_i-1
                let mut wi_3 = wi.mul_uint_constant(3).expect("mul_uint_constant failed.");
                if i0 > 0 { wi_3.add_uint_inplace(&w[i-1]).expect("add_uint_inplace failed."); }
                *qi = pbs::f_4__pi_5(pub_keys, &wi_3).expect("f_4__pi_5 failed.");
            });
            // q must have the same length as z
            q.push(LWE::zero(0)?);

            z.par_iter_mut().zip(q.par_iter().enumerate()).for_each(| (zi, (i, qi)) | {
                // calc   2 q_i
                let qi_2 = qi.mul_uint_constant(2).expect("mul_uint_constant failed.");
                zi.sub_uint_inplace(&qi_2).expect("sub_uint_inplace failed.");
                if i > 0 { zi.add_uint_inplace(&q[i-1]).expect("add_uint_inplace failed."); }
            });
            //TODO add one more bootstrap with identity (or leave it for user? in some cases BS could be saved)
            //TODO add one more thread if < maxlen
        ]
    );
    }

    //  Scenario G   -----------------------------------------------------------
    #[cfg(feature = "sc_G")]
    {
    measure_duration!(
        ["Sequential {}, sc. G ({}-bit, {} active)", if is_add {"addition"} else {"subtraction"}, wlen, wlen - r_triv],
        [
            z = x.clone(); //TODO
        ]
    );
    }

    //  Scenario H   -----------------------------------------------------------
    #[cfg(feature = "sc_H")]
    {
    measure_duration!(
        ["Sequential {}, sc. H ({}-bit, {} active)", if is_add {"addition"} else {"subtraction"}, wlen, wlen - r_triv],
        [
            z = x.clone(); //TODO
        ]
    );
    }

    //  Scenario I   -----------------------------------------------------------
    #[cfg(feature = "sc_I")]
    {
    measure_duration!(
        ["Sequential {}, sc. I ({}-bit, {} active)", if is_add {"addition"} else {"subtraction"}, wlen, wlen - r_triv],
        [
            z = x.clone(); //TODO
        ]
    );
    }

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
    params: &Params,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    k: i32,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    // resolve k == 0
    if k == 0 {
        return Ok(x.clone());
    }

    let k_abs = (k as i64).abs() as u32;   // deal with -2^31, for which abs() panics, because it does not fit i32
    let k_pos = k >= 0;

    let mut k_len = 0usize;
    for i in 0..31 {if k_abs & (1 << i) != 0 {k_len = i + 1;}}

    let mut ck = ParmCiphertext::empty();

    for i in 0..k_len {
        // calculate i-th bit with sign
        let ki = if ((k_abs >> i) & 1) == 0 {
            0u32
        } else {
            if k_pos {1u32} else {params.plaintext_mask() as u32}
        };

        // encrypt as trivial sample
        let cti = LWE::encrypt_uint_triv(
            ki,
            &pub_keys.encoder,
        )?;

        ck.push(cti);
    }

    Ok(add_sub_impl(
        true,
        pub_keys,
        x,
        &ck,
    )?)
}
