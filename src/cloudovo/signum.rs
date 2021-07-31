use concrete::LWE;
#[allow(unused_imports)]
use colored::Colorize;
use crate::params::Params;
use crate::ciphertexts::ParmCiphertext;
use crate::userovo::keys::PubKeySet;
use super::pbs;

/// Implementation of signum via parallel reduction
pub fn sgn_impl(
    params: &Params,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
) -> ParmCiphertext {
    measure_duration!(
        "Signum",
        [
            let s = sgn_recursion(
                params.bit_precision - 1,
                pub_keys,
                x,
            );
        ]
    );

    s
}

fn sgn_recursion(
    gamma: usize,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
) -> ParmCiphertext {
    // end of recursion
    if x.len() == 1 {
        infoln!("length 1 bit (final signum bootstrap)");
        return vec![
        pbs::f_1__pi_5__with_val(
            pub_keys,
            &x[0],
            1,
        )];
    }

    let dim = x.first().expect("Empty vector.").dimension;
    let encoder = &x.first().expect("Empty vector.").encoder;
    let mut b: ParmCiphertext = Vec::new();

    measure_duration!(
        "- recursion",
        [
            infoln!("length {} bits, groups by {} bits", x.len(), gamma);
            for j in 0..((x.len() - 1) / gamma + 1) {
                let mut bj: LWE = LWE::zero_with_encoder(dim, encoder).expect("LWE fail.");

                for i in 0..gamma {
                    let mut s: LWE = LWE::zero_with_encoder(dim, encoder).expect("LWE fail.");

                    if gamma * j + i < x.len() {
                        s = pbs::f_1__pi_5__with_val(
                            pub_keys,
                            &x[gamma * j + i],
                            1 << i,
                        );
                    }

                    bj.add_uint_inplace(&s).expect("Add fail.");
                }

                b.push(bj);
            }

            let s = sgn_recursion(
                gamma,
                pub_keys,
                &b,
            );
        ]
    );

    s
}
