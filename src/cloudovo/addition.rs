use std::error::Error;

// parallelization tools
use rayon::prelude::*;
use crossbeam_utils::thread;

#[allow(unused_imports)]
use colored::Colorize;

use concrete::LWE;

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
        *zi = pbs::id__pi_5(pub_keys, zni).expect("pbs::id__pi_5 failed.");
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
            let mut c: LWE = LWE::encrypt_uint_triv(7, pub_keys.encoder)?;   // logical 0 encrypts -1

            for (xi, yi) in x.iter().zip(y.iter()) {
                // init tmp variables
                let mut t = LWE::zero(0)?;
                let mut u = LWE::zero(0)?;
                let mut v = LWE::zero(0)?;

                // only references can be passed to threads, otherwise they "consume" the values (t, u, v)
                // (quite a weird workaround)
                let tr = &mut t;
                let ur = &mut u;
                let vr = &mut v;

                // first parallel pool: t, u
                thread::scope(|tu_scope| {
                    tu_scope.spawn(|_| {
                        // t = x_i XOR y_i
                        *tr = pbs::XOR(pub_keys, xi, yi).expect("pbs::XOR failed.");
                    });
                    tu_scope.spawn(|_| {
                        // u = x_i AND y_i
                        *ur = pbs::AND(pub_keys, xi, yi).expect("pbs::XOR failed.");
                    });
                }).expect("thread::scope tu_scope failed.");

                // second parallel pool: zi, v
                thread::scope(|zv_scope| {
                    zv_scope.spawn(|_| {
                        // z_i = t XOR c
                        z.push(pbs::XOR(pub_keys, tr, &c).expect("pbs::XOR failed."));
                    });
                    zv_scope.spawn(|_| {
                        // v   = t AND c
                        *vr = pbs::AND(pub_keys, tr, &c).expect("pbs::XOR failed.");
                    });
                }).expect("thread::scope zv_scope failed.");

                // calc new carry
                c = pbs::XOR(pub_keys, &u, &v)?;
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
            // init result & carry
            z = ParmCiphertext::empty();
            let mut c: LWE = LWE::encrypt_uint_triv(7, pub_keys.encoder)?;   // logical 0 encrypts -1

            for (xi, yi) in x.iter().zip(y.iter()) {
                // init new carry & reference (only references can be passed to threads)
                let mut cn = LWE::zero(0)?;
                let cnr = &mut cn;

                // parallel pool: zi, c
                thread::scope(|zc_scope| {
                    zc_scope.spawn(|_| {
                        // z_i = x_i XOR y_i XOR c
                        z.push(pbs::XOR_THREE(pub_keys, xi, yi, &c).expect("pbs::XOR_THREE failed."));
                    });
                    zc_scope.spawn(|_| {
                        // c = 2OF3(x_i, y_i, c)
                        *cnr = pbs::TWO_OF_THREE(pub_keys, xi, yi, &c).expect("pbs::TWO_OF_THREE failed.");
                        // cf. https://www.wolframalpha.com/input/?i=%28x+AND+y%29+XOR+%28z+AND+%28x+XOR+y%29%29
                    });
                }).expect("thread::scope zc_scope failed.");

                c = cn.clone();
            }

            z.push(c);
        ]
    );
    }

    //  Scenario C   -----------------------------------------------------------
    #[cfg(feature = "sc_C")]
    {
    measure_duration!(
        ["Sequential {}, sc. C ({}-bit, {} active)", if is_add {"addition"} else {"subtraction"}, wlen, wlen - r_triv],
        [
            // init result & carry
            z = ParmCiphertext::empty();
            let mut c: LWE = LWE::zero(0)?;

            for (xi, yi) in x.iter().zip(y.iter()) {
                // w_i = x_i + y_i + c
                let mut wi = xi.add_uint(yi)?;
                wi.add_uint_inplace(&c)?;

                //TODO in parallel: bootstrap z_i-1 with identity

                // c = w_i >= 4 (0, -, 0, -, 0, -, 0, -, 2, -, 2, -, 2, -, 2, - .. in pi = 4 repre .. everything x2)
                c = pbs::c_4__pi_2x4(pub_keys, &wi)?;
                let one = LWE::encrypt_uint_triv(1, &pub_keys.encoder)?;
                c.add_uint_inplace(&one);

                // zi = wi - 4*c
                let fc = c.mul_uint_constant(4)?;   // 4*c
                wi.sub_uint_inplace(&fc)?;          // wi - 4*c

                // refresh
                z.push(pbs::pos_id(pub_keys, &wi)?);
                //TODO this can run in parallel: with the previous round
                //~ z.push(wi);
            }

            z.push(c);
        ]
    );
    }

    //  Scenario D   -----------------------------------------------------------
    #[cfg(feature = "sc_D")]
    {
    measure_duration!(
        ["Parallel {}, sc. D ({}-bit, {} active)", if is_add {"addition"} else {"subtraction"}, wlen, wlen - r_triv],
        [
            // w = x + y
            let mut w = x.clone();
            for (wi, yi) in w.iter_mut().zip(y.iter()) {
                wi.add_uint_inplace(&yi)?;
            }

            // init q with zeros and z with w
            let mut q = ParmCiphertext::triv(w.len())?;
            z = w.clone();
            // one more word for "carry"
            z.push(LWE::zero(0)?);

            q.par_iter_mut().zip(w.par_iter().enumerate()).for_each(| (qi, (i, wi)) | {
                //~ // ---   SEQUENTIAL BEGIN   ------------------------------------
                //~ let mut r1 = pbs::f_2__pi_3(pub_keys, wi).expect("f_2__pi_3 failed.");
                //~ let mut r2 = pbs::g_1__pi_3(pub_keys, wi).expect("g_1__pi_3 failed.");
                //~ let     r3 = if i > 0 {
                    //~ pbs::f_1__pi_3(pub_keys, &w[i-1]).expect("f_1__pi_3 failed.")
                //~ } else {
                    //~ LWE::zero(0).expect("LWE::zero failed.")
                //~ };
                //~ // ---   SEQUENTIAL END   --------------------------------------

                // ---   PARALLEL BEGIN   --------------------------------------
                // init tmp variables
                let mut r1 = LWE::zero(0).expect("LWE::zero failed.");
                let mut r2 = LWE::zero(0).expect("LWE::zero failed.");
                let mut r3 = LWE::zero(0).expect("LWE::zero failed.");
                // only references can be passed to threads
                let r1r = &mut r1;
                let r2r = &mut r2;
                let r3r = &mut r3;

                // parallel pool: r1-3
                thread::scope(|ri_scope| {
                    ri_scope.spawn(|_| {
                        // r1 = wi ⋛ ±2
                        *r1r = pbs::f_2__pi_3(pub_keys, wi).expect("f_2__pi_3 failed.");
                    });
                    ri_scope.spawn(|_| {
                        // r2 = wi ≡ ±1
                        *r2r = pbs::g_1__pi_3(pub_keys, wi).expect("g_1__pi_3 failed.");
                    });
                    ri_scope.spawn(|_| {
                        // r3 = w_i-1 ⋛ ±1
                        *r3r = if i > 0 {
                            pbs::f_1__pi_3(pub_keys, &w[i-1]).expect("f_1__pi_3 failed.")
                        } else {
                            LWE::zero(0).expect("LWE::zero failed.")
                        };
                    });
                }).expect("thread::scope ri_scope failed.");
                // ---   PARALLEL END   ----------------------------------------

                r2.add_uint_inplace(&r3).expect("add_uint_inplace failed.");   // r2 + r3
                // r23 = r2 + r3 ≡ ±2
                let r23 = pbs::g_2__pi_3(pub_keys, &r2).expect("g_2__pi_3 failed.");

                // qi = r1 + r23
                *qi = r1.add_uint(&r23).expect("add_uint failed.");
            });
            // q must have the same length as z
            q.push(LWE::zero(0)?);

            z.par_iter_mut().zip(q.par_iter().enumerate()).for_each(| (zi, (i, qi)) | {
                // calc   2 q_i
                let qi_2 = qi.mul_uint_constant(2).expect("mul_uint_constant failed.");
                zi.sub_uint_inplace(&qi_2).expect("sub_uint_inplace failed.");
                if i > 0 { zi.add_uint_inplace(&q[i-1]).expect("add_uint_inplace failed."); }

                // refresh
                let zi_fresh = pbs::id__pi_3(pub_keys, zi).expect("pbs::id__pi_3 failed.");
                *zi = zi_fresh.clone();
            });
        ]
    );
    }

    //  Scenario E   -----------------------------------------------------------
    #[cfg(feature = "sc_E")]
    {
    measure_duration!(
        ["Parallel {}, sc. E ({}-bit, {} active)", if is_add {"addition"} else {"subtraction"}, wlen, wlen - r_triv],
        [
            // w = x + y
            let mut w = x.clone();
            for (wi, yi) in w.iter_mut().zip(y.iter()) {
                wi.add_uint_inplace(&yi)?;
            }

            // init q with zeros and z with w
            let mut q = ParmCiphertext::triv(w.len())?;
            z = w.clone();
            // one more word for "carry"
            z.push(LWE::zero(0)?);

            q.par_iter_mut().zip(w.par_iter().enumerate()).for_each(| (qi, (i, wi)) | {
                //~ // ---   SEQUENTIAL BEGIN   ------------------------------------
                //~ let     r1 = pbs::f_2__pi_4(pub_keys, wi).expect("f_2__pi_4 failed.");
                //~ let mut r2 = pbs::g_1__pi_4__with_val(pub_keys, wi, 2).expect("g_1__pi_4__with_val failed.");
                //~ // ---   SEQUENTIAL END   --------------------------------------

                // ---   PARALLEL BEGIN   --------------------------------------
                // init tmp variables
                let mut r1 = LWE::zero(0).expect("LWE::zero failed.");
                let mut r2 = LWE::zero(0).expect("LWE::zero failed.");
                // only references can be passed to threads
                let r1r = &mut r1;
                let r2r = &mut r2;

                // parallel pool: r1, r2
                thread::scope(|r12_scope| {
                    r12_scope.spawn(|_| {
                        // r1 = wi ⋛ ±2
                        *r1r = pbs::f_2__pi_4(pub_keys, wi).expect("f_2__pi_4 failed.");
                    });
                    r12_scope.spawn(|_| {
                        // r2 = 2·(wi ≡ ±1)
                        *r2r = pbs::g_1__pi_4__with_val(pub_keys, wi, 2).expect("g_1__pi_4__with_val failed.");
                    });
                }).expect("thread::scope r12_scope failed.");
                // ---   PARALLEL END   ----------------------------------------

                if i > 0 {
                    r2.add_uint_inplace(&w[i-1]).expect("add_uint_inplace failed.");   // w_i-1 + r2
                }
                let r23 = pbs::f_3__pi_4(pub_keys, &r2).expect("f_3__pi_4 failed.");

                // qi = r1 + r23
                *qi = r1.add_uint(&r23).expect("add_uint failed.");
            });
            // q must have the same length as z
            q.push(LWE::zero(0)?);

            z.par_iter_mut().zip(q.par_iter().enumerate()).for_each(| (zi, (i, qi)) | {
                // calc   2 q_i
                let qi_2 = qi.mul_uint_constant(2).expect("mul_uint_constant failed.");
                zi.sub_uint_inplace(&qi_2).expect("sub_uint_inplace failed.");
                if i > 0 { zi.add_uint_inplace(&q[i-1]).expect("add_uint_inplace failed."); }

                // refresh
                let zi_fresh = pbs::id__pi_4(pub_keys, zi).expect("pbs::id__pi_4 failed.");
                *zi = zi_fresh.clone();
            });
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

                //DBG !!!
                // refresh
                let zi_fresh = pbs::id__pi_5(pub_keys, zi).expect("pbs::id__pi_5 failed.");
                *zi = zi_fresh.clone();
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
        ["Parallel {}, sc. G ({}-bit, {} active)", if is_add {"addition"} else {"subtraction"}, wlen, wlen - r_triv],
        [
            // w = x + y
            let mut w = x.clone();
            for (wi, yi) in w.iter_mut().zip(y.iter()) {
                wi.add_uint_inplace(&yi)?;
            }

            // init q with zeros and z with w
            let mut q = ParmCiphertext::triv(w.len())?;
            z = w.clone();
            // one more word for "carry"
            z.push(LWE::zero(0)?);

            q.par_iter_mut().zip(w.par_iter().enumerate()).for_each(| (qi, (i, wi)) | {
                //~ // ---   SEQUENTIAL BEGIN   ------------------------------------
                //~ let mut r1 = pbs::f_3__pi_4(pub_keys, wi).expect("f_3__pi_4 failed.");
                //~ let mut r2 = pbs::g_2__pi_4(pub_keys, wi).expect("g_2__pi_4 failed.");
                //~ let     r3 = if i > 0 {
                    //~ pbs::f_2__pi_4(pub_keys, &w[i-1]).expect("f_2__pi_4 failed.")
                //~ } else {
                    //~ LWE::zero(0).expect("LWE::zero failed.")
                //~ };
                //~ // ---   SEQUENTIAL END   --------------------------------------

                // ---   PARALLEL BEGIN   --------------------------------------
                // init tmp variables
                let mut r1 = LWE::zero(0).expect("LWE::zero failed.");
                let mut r2 = LWE::zero(0).expect("LWE::zero failed.");
                let mut r3 = LWE::zero(0).expect("LWE::zero failed.");
                // only references can be passed to threads
                let r1r = &mut r1;
                let r2r = &mut r2;
                let r3r = &mut r3;

                // parallel pool: r1-3
                thread::scope(|ri_scope| {
                    ri_scope.spawn(|_| {
                        // r1 = wi ⋛ ±3
                        *r1r = pbs::f_3__pi_4(pub_keys, wi).expect("f_3__pi_4 failed.");
                    });
                    ri_scope.spawn(|_| {
                        // r2 = wi ≡ ±2
                        *r2r = pbs::g_2__pi_4(pub_keys, wi).expect("g_2__pi_4 failed.");
                    });
                    ri_scope.spawn(|_| {
                        // r3 = w_i-1 ⋛ ±2
                        *r3r = if i > 0 {
                            pbs::f_2__pi_4(pub_keys, &w[i-1]).expect("f_2__pi_4 failed.")
                        } else {
                            LWE::zero(0).expect("LWE::zero failed.")
                        };
                    });
                }).expect("thread::scope ri_scope failed.");
                // ---   PARALLEL END   ----------------------------------------

                r2.add_uint_inplace(&r3).expect("add_uint_inplace failed.");   // r2 + r3
                let r23 = pbs::g_2__pi_4(pub_keys, &r2).expect("g_2__pi_4 failed.");

                // qi = r1 + r23
                *qi = r1.add_uint(&r23).expect("add_uint failed.");
            });
            // q must have the same length as z
            q.push(LWE::zero(0)?);

            z.par_iter_mut().zip(q.par_iter().enumerate()).for_each(| (zi, (i, qi)) | {
                // calc   4 q_i
                let qi_4 = qi.mul_uint_constant(4).expect("mul_uint_constant failed.");
                zi.sub_uint_inplace(&qi_4).expect("sub_uint_inplace failed.");
                if i > 0 { zi.add_uint_inplace(&q[i-1]).expect("add_uint_inplace failed."); }

                // refresh
                let zi_fresh = pbs::id__pi_4(pub_keys, zi).expect("pbs::id__pi_4 failed.");
                *zi = zi_fresh.clone();
            });
        ]
    );
    }

    //  Scenario H   -----------------------------------------------------------
    #[cfg(feature = "sc_H")]
    {
    measure_duration!(
        ["Parallel {}, sc. H ({}-bit, {} active)", if is_add {"addition"} else {"subtraction"}, wlen, wlen - r_triv],
        [
            // w = x + y
            let mut w = x.clone();
            for (wi, yi) in w.iter_mut().zip(y.iter()) {
                wi.add_uint_inplace(&yi)?;
            }

            // init q with zeros and z with w
            let mut q = ParmCiphertext::triv(w.len())?;
            z = w.clone();
            // one more word for "carry"
            z.push(LWE::zero(0)?);

            q.par_iter_mut().zip(w.par_iter().enumerate()).for_each(| (qi, (i, wi)) | {
                //~ // ---   SEQUENTIAL BEGIN   ------------------------------------
                //~ let     r1 = pbs::f_3__pi_5(pub_keys, wi).expect("f_3__pi_5 failed.");
                //~ let mut r2 = pbs::g_2__pi_5__with_val(pub_keys, wi, 3).expect("g_2__pi_5__with_val failed.");
                //~ // ---   SEQUENTIAL END   --------------------------------------

                // ---   PARALLEL BEGIN   --------------------------------------
                // init tmp variables
                let mut r1 = LWE::zero(0).expect("LWE::zero failed.");
                let mut r2 = LWE::zero(0).expect("LWE::zero failed.");
                // only references can be passed to threads
                let r1r = &mut r1;
                let r2r = &mut r2;

                // parallel pool: r1, r2
                thread::scope(|r12_scope| {
                    r12_scope.spawn(|_| {
                        // r1 = wi ⋛ ±3
                        *r1r = pbs::f_3__pi_5(pub_keys, wi).expect("f_3__pi_5 failed.");
                    });
                    r12_scope.spawn(|_| {
                        // r2 = 3·(wi ≡ ±2)
                        *r2r = pbs::g_2__pi_5__with_val(pub_keys, wi, 3).expect("g_2__pi_5__with_val failed.");
                    });
                }).expect("thread::scope r12_scope failed.");
                // ---   PARALLEL END   ----------------------------------------

                if i > 0 {
                    r2.add_uint_inplace(&w[i-1]).expect("add_uint_inplace failed.");   // w_i-1 + r2
                }
                let r23 = pbs::f_5__pi_5(pub_keys, &r2).expect("f_5__pi_5 failed.");

                // qi = r1 + r23
                *qi = r1.add_uint(&r23).expect("add_uint failed.");
            });
            // q must have the same length as z
            q.push(LWE::zero(0)?);

            z.par_iter_mut().zip(q.par_iter().enumerate()).for_each(| (zi, (i, qi)) | {
                // calc   4 q_i
                let qi_4 = qi.mul_uint_constant(4).expect("mul_uint_constant failed.");
                zi.sub_uint_inplace(&qi_4).expect("sub_uint_inplace failed.");
                if i > 0 { zi.add_uint_inplace(&q[i-1]).expect("add_uint_inplace failed."); }

                // refresh
                let zi_fresh = pbs::id__pi_5(pub_keys, zi).expect("pbs::id__pi_5 failed.");
                *zi = zi_fresh.clone();
            });
        ]
    );
    }

    //  Scenario I   -----------------------------------------------------------
    #[cfg(feature = "sc_I")]
    {
    measure_duration!(
        ["Parallel {}, sc. I ({}-bit, {} active)", if is_add {"addition"} else {"subtraction"}, wlen, wlen - r_triv],
        [
            // w = x + y
            let mut w = x.clone();
            for (wi, yi) in w.iter_mut().zip(y.iter()) {
                wi.add_uint_inplace(&yi)?;
            }

            // init q with zeros and z with w
            let mut q = ParmCiphertext::triv(w.len())?;
            z = w.clone();
            // one more word for "carry"
            z.push(LWE::zero(0)?);

            q.par_iter_mut().zip(w.par_iter().enumerate()).for_each(| (qi, (i, wi)) | {
                // calc   6 w_i + w_i-1
                let mut wi_6 = wi.mul_uint_constant(6).expect("mul_uint_constant failed.");
                if i > 0 { wi_6.add_uint_inplace(&w[i-1]).expect("add_uint_inplace failed."); }
                *qi = pbs::f_14__pi_7(pub_keys, &wi_6).expect("f_14__pi_7 failed.");
            });
            // q must have the same length as z
            q.push(LWE::zero(0)?);

            z.par_iter_mut().zip(q.par_iter().enumerate()).for_each(| (zi, (i, qi)) | {
                // calc   4 q_i
                let qi_4 = qi.mul_uint_constant(4).expect("mul_uint_constant failed.");
                zi.sub_uint_inplace(&qi_4).expect("sub_uint_inplace failed.");
                if i > 0 { zi.add_uint_inplace(&q[i-1]).expect("add_uint_inplace failed."); }

                // refresh
                let zi_fresh = pbs::id__pi_7(pub_keys, zi).expect("pbs::id__pi_7 failed.");
                *zi = zi_fresh.clone();
            });
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
