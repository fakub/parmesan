use concrete::LWE;
use colored::Colorize;
//~ use crate::params::Params;
use crate::ciphertexts::ParmCiphertext;
use crate::userovo::keys::PubKeySet;
use super::pbs;

//TODO
//  mult by const: mul_constant_static_encoder_inplace (or ..?)
//  negate: self.ciphertext.update_with_neg(); (nth else in opposite_inplace)

/// Implementation of parallel addition
pub fn add_impl(
    //~ params: &Params,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> ParmCiphertext {
    // run parallel addition algorithm
    let mut z: Vec<LWE> = Vec::new();

    measure_duration!(
        "Parallel addition",
        [
            for (i, xi) in x.ctv.iter().enumerate() {
                //~ let wi: LWE = if i & 1 != 0 {pbs::id(pub_keys, ct)} else {y.ctv[i].clone()};
                //~ let wi: LWE = xi.add_uint(&y.ctv[i]).expect("Addition (uint) failed.");
                let wi: LWE = xi.mul_uint_constant(4).expect("Multiplication (uint) by const failed.");
                z.push(wi);
            }
        ]
    );

    ParmCiphertext {
        ctv: z,
        maxlen: 32,
    }
}
