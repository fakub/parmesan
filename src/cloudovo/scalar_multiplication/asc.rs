use std::error::Error;
use std::fs;

use serde::{Serialize, Deserialize};

use crate::*;


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
        x: &T,
    ) -> Result<T, Box<dyn Error>>;
}

impl<T: ParmArithmetics + Clone> AscEval<T> for Asc
{
    fn eval(
        &self,
        pc: &ParmesanCloudovo,
        x: &T,
    ) -> Result<T, Box<dyn Error>> {
        let mut asc_vals = vec![x.clone()];

        for adsh in self {
            // +-1 * left_val  +  +-1 * right_val << right_shift

            let neg_l = ParmArithmetics::opp(&asc_vals[adsh.l_idx]);

            let r_sh = ParmArithmetics::shift(pc, &asc_vals[adsh.r_idx], adsh.r_shift);
            let neg_r_sh = ParmArithmetics::opp(&r_sh);

            // only limited space for parallelization
            // (no example on the first sight)
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
        self.eval(pc, &1i64).expect("Asc::value failed.")
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
