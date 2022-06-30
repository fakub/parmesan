use std::error::Error;

use serde::{Serialize, Deserialize};

//TODO add feature condition
pub use std::fs::{self,File,OpenOptions};
pub use std::path::Path;
pub use std::io::Write;
pub use std::collections::BTreeMap;

use crate::*;

#[allow(unused_imports)]
use colored::Colorize;

use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};
use super::addition;

/// Implementation of signum via parallel reduction
pub fn scalar_mul_impl(
    pc: &ParmesanCloudovo,
    k: i32,
    x: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    //TODO instead of this NAF, use representation with longer zero intervals and then apply window method with ASC_12
    let _ = ASC_12.len();

    // move sign of k to x, prepare both +1 and -1 multiples
    let mut x_pos = ParmCiphertext::empty();
    let mut x_neg = ParmCiphertext::empty();
    for xi in x {
        if k >= 0 {
            x_pos.push(xi.clone());
            x_neg.push(xi.opposite_uint()?);
        } else {
            x_pos.push(xi.opposite_uint()?);
            x_neg.push(xi.clone());
        }
    }
    // from now on, only work with k_abs (the sign is already moved to x)
    let k_abs = k.abs() as u32;

    // resolve |k| < 2
    if k_abs == 0 {return Ok(ParmCiphertext::empty());}
    if k_abs == 1 {return Ok(x_pos);}

    // |k| < 2 already resolved, set to len = 2 and start from length 3: take 1 << 2 (which is 0b100 = 4)
    let mut k_len = 2usize;
    for i in 2..31 {if k_abs & (1 << i) != 0 {k_len = i + 1;}}   //TODO as macro?

    // k as a vector of bits
    // replace sequences of 1's with 1|zeros|-1
    //
    // index   11  10   9   8   7   6   5   4   3   2   1   0
    //
    //          0   1   1   1   0   1   1   1   1   0   1   1
    //          1   0   0  -1   1   0   0   0  -1   1   0  -1       first hit
    //          1   0   0   0  -1   0   0   0   0  -1   0  -1       second hit
    //
    // e.g.: k_abs = 0b11001110011110011011101111;
    // first hit:   [-1, 0, 0, 0, 1, -1, 0, 0, 1, -1, 0, 1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 1, 0, -1, 0, 1]
    // second hit:  [-1, 0, 0, 0, -1, 0, 0, 0, -1, 0, 0, 1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 1, 0, -1, 0, 1]
    //
    //WISH detect any reusable patterns (honestly, I do not expect much an improvement)

    let mut k_vec: Vec<i32> = Vec::new();
    let mut low_1: usize = 0;
    for i in 0..k_len+1 {
        // add a bit of k to the vector
        k_vec.push(((k_abs >> i) & 1) as i32);

        if (k_abs >> i) & 1 == 0 {
            // at least two consecutive ones: i - low_1
            if i - low_1 > 1 {
                //  i             low_1
                //  0   1   1   1   1   0
                //  1   0   0   0  -1   0
                //
                // the new -1 can meet 1 from previous steps (if any): -1   1   0   =>  0  -1   0
                if low_1 > 0 && k_vec[low_1-1] == 1 {
                    k_vec[low_1-1] = -1;
                    k_vec[low_1] = 0;
                } else {
                    k_vec[low_1] = -1;
                }
                for j in low_1+1..i {
                    k_vec[j] = 0;
                }
                k_vec[i] = 1;
            }
            // move "pointer" forward
            low_1 = i + 1;
        }
        // k == 1 .. keep "pointer" at its current/previous position -> do nothing
    }

    // k_len ≥ 2
    let mut mulary: Vec<ParmCiphertext> = Vec::new();
    for (i, ki) in k_vec.iter().enumerate() {
        if *ki != 0 {
            // push shifted x_<pos/neg> to mulary
            mulary.push(ParmArithmetics::shift(pc, if *ki == 1 {&x_pos} else {&x_neg}, i));
        }
    }

    // Hamming weight of k is 1
    if mulary.len() == 1 {
        return Ok(mulary[0].clone());
    }

    //TODO
    //  since there are no subsequent lines of len & len+1 (follows from the fact that there are no neighboring non-zeros in optimized k_vec),
    //  this mulary does not need to be reduced sequentially, most of it can be done in parallel (carefully; the last row must be added in the last step)

    // reduce mulary
    measure_duration!(
        ["Scalar multiplication (non-triv ±{} · {}-bit)", k_abs, x.len()],
        [
            // reduce multiplication array (of length ≥ 2)
            let mut intmd = vec![ParmCiphertext::empty(); 2];
            let mut idx = 0usize;
            intmd[idx] = addition::add_sub_noise_refresh(
                true,
                pc.pub_keys,
                &mulary[0],
                &mulary[1],
            )?;

            for i in 2..mulary.len() {
                idx ^= 1;
                intmd[idx] = addition::add_sub_noise_refresh(
                    true,
                    pc.pub_keys,
                    &intmd[idx ^ 1],
                    &mulary[i],
                )?;
            }
        ]
    );

    Ok(intmd[idx].clone())
}


// =============================================================================
//
//  Addition-Subtraction Chains
//

/// element of ASC -- prescription (combination of previous):
/// left addend's sign, left addend's index (within the ASC), <same for right addend>, right addend's shift
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AddShift {
    pub l_pos:      bool,
    pub l_idx:      usize,
    pub r_pos:      bool,
    pub r_idx:      usize,
    pub r_shift:    usize,
}

/// Addition-Subtraction Chain as a vector of 'prescriptions'
pub type Asc = Vec<AddShift>;

pub trait AscEval<T: ParmArithmetics> {
    /// Evaluation function for `ParmArithmetics` types (no parallelization yet .. TODO)
    fn eval(
        &self,
        pc: &ParmesanCloudovo,
        x: T,
    ) -> Result<T, Box<dyn Error>>;
}

impl<T: ParmArithmetics + Clone> AscEval<T> for Asc
{
    fn eval(
        &self,
        pc: &ParmesanCloudovo,
        x: T,
    ) -> Result<T, Box<dyn Error>> {
        let mut asc_vals = vec![x];

        for adsh in self {
            //                     +-1                  *          left_val     +          +-1                  *           right_val   << right_shift
            //~ asc_vals.push((if adsh.l_pos {1} else {-1}) * asc_vals[adsh.l_idx]  + (if adsh.r_pos {1} else {-1}) * (asc_vals[adsh.r_idx] << adsh.r_shift));

            let neg_l = ParmArithmetics::opp(&asc_vals[adsh.l_idx]);

            let r_sh = ParmArithmetics::shift(pc, &asc_vals[adsh.r_idx], adsh.r_shift);
            let neg_r_sh = ParmArithmetics::opp(&r_sh);

            asc_vals.push(
                ParmArithmetics::add(&pc,
                    if adsh.l_pos {&asc_vals[adsh.l_idx]} else {&neg_l},
                    if adsh.r_pos {&r_sh} else {&neg_r_sh})
            );
        }
        //          Option<&T>   &T       T
        Ok(asc_vals.last()      .unwrap().clone())
    }
}

pub trait AscValue {
    /// Value (i64) of ASC
    fn value(
        &self,
        pc: &ParmesanCloudovo,
    ) -> i64;

    /// Load from YAML file
    fn map_from_yaml(
        bitlen: usize,
        filename: &str,
    ) -> Result<BTreeMap<usize, Self>, Box<dyn Error>> where Self: Sized;
}

impl AscValue for Asc {
    fn value(
        &self,
        pc: &ParmesanCloudovo,
    ) -> i64 {
        self.eval(pc, 1i64).expect("Asc::value failed.")
    }
    //~ fn value(&self) -> i64 {
        //~ // destructuring assignments are unstable: issue #71126 <https://github.com/rust-lang/rust/issues/71126>
        //~ // hence ParmesanCloudovo must be present
        //~ self.eval(_, 1i64).expect("Asc::value failed.")
    //~ }

    fn map_from_yaml(
        bitlen: usize,
        filename: &str,
    ) -> Result<BTreeMap<usize, Self>, Box<dyn Error>> {
        let asc_map: BTreeMap<usize, Self>;

        // check if YAML file exists
        if Path::new(filename).is_file() {
            println!("(i) Loading ASC's from '{}' ...", filename);

            // read YAML file
            let yaml_str = fs::read_to_string(filename)?;

            // load map of ASC's from YAML string
            asc_map = serde_yaml::from_str(&yaml_str)?;

        } else {
            return Err(format!("ASC file '{}' does not exist.", filename).into());
        }

        // number of elements = 2^bitlen / 2
        if asc_map.len() != (1 << bitlen) / 2 {return Err(format!("Wrong number of ASC's: {}, expected {} (n.b., '1: []' is expected, too).", asc_map.len(), (1 << bitlen) / 2).into());}

        // check correctness of chains
        //TODO ASC eval without ParmesanCloudovo
        //~ for (n, asc) in asc_map.iter() {
            //~ if *n as i64 != asc.value_i64() {
                //~ return Err(format!("Incorrect ASC value: '{:?}' evaluates to {}, expected {}.", asc, asc.value_i64(), *n as i64).into());
            //~ }
        //~ }

        Ok(asc_map)
    }
}
