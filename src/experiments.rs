use std::collections::BTreeMap;

use crate::*;
use crate::userovo::*;
use crate::scalar_multiplication::*;

/// Based on Koyama-Tsuruoka representation, evaluate the improvement of:
///  - using optimal ASC's for 12-bit sliding windows, vs.
///  - simply adding the shifted numbers
pub fn avg_adds_in_scalar_mul() {

    println!("\n====    EXPERIMENT:  Avg. number of additions in Scalar Mul    =================\n");

    let mut val_ads: BTreeMap<usize, (usize, usize)> = BTreeMap::new();

    let gen_bits = ASC_BITLEN;   // generates the same with higher bitlen (KT is local)

    let mut nai_tot = 0;
    let mut opt_tot = 0;

    for k in 1..(1 << gen_bits) {
        // skip even
        if k & 1 == 0 {continue;}
        // get "NAF"
        let ktv = naf::koyama_tsuruoka_vec(k);
        // get window of size ASC_BITLEN
        let w = ktv[0..if ktv.len() < ASC_BITLEN {ktv.len()} else {ASC_BITLEN}].to_vec();
        // get its value
        let w_val = encryption::convert(&w).expect("convert failed.").abs() as usize;

        // HW-1 .. standard NAF approach ; ASC's length .. window-Koy-Tsu
        if !val_ads.contains_key(&w_val) {
            let hw = encryption::bin_hw(&w).expect("bin_hw failed.");
            val_ads.insert(w_val, (hw-1, ASC_12[&w_val].len()));
            nai_tot += hw-1;
            opt_tot += ASC_12[&w_val].len();
        }
    }

    //~ // full print-out
    //~ for k in 1..(1 << gen_bits) {
        //~ // skip even
        //~ if k & 1 == 0 {continue;}

        //~ if val_ads.contains_key(&k) {
            //~ println!("[{:2}] {:2}, {:2} ", k, val_ads[&k].0, val_ads[&k].1);
        //~ } else {
            //~ println!("[{:2}] ----", k);
        //~ }
    //~ }

    // print stats
    println!("Naive:   {} add's", nai_tot);
    println!("Optim:   {} add's", opt_tot);
    println!("..out of {} scalar mul's ({}-bit window).", val_ads.len(), ASC_BITLEN);
    println!("\n====    Enf of EXPERIMENT    ===================================================\n");
}