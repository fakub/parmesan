use super::ciphertexts::{ParmCiphertext, ParmCiphertextExt};
use super::ParmesanCloudovo;
use super::cloudovo::*;


// =============================================================================
//
//  Parmesan Arithmetics
//

/// Parmesan Arithmetics Trait
pub trait ParmArithmetics {
    /// Addition: `X + Y`
    fn add(
        pc: &ParmesanCloudovo,
        x: &Self,
        y: &Self,
    ) -> Self;

    /// Subtraction: `X - Y`
    fn sub(
        pc: &ParmesanCloudovo,
        x: &Self,
        y: &Self,
    ) -> Self;

    /// Scalar multiplication (by an integer): `k·X`
    fn scalar_mul(
        pc: &ParmesanCloudovo,
        k: i32,
        x: &Self,
    ) -> Self;

    /// Signum: `sgn(X)`
    fn sgn(
        pc: &ParmesanCloudovo,
        x: &Self,
    ) -> Self;

    /// Maximum: `max{X, Y}`
    fn max(
        pc: &ParmesanCloudovo,
        x: &Self,
        y: &Self,
    ) -> Self;

    /// Multiplication: `X × Y`
    fn mul(
        pc: &ParmesanCloudovo,
        x: &Self,
        y: &Self,
    ) -> Self;
}

impl ParmArithmetics for i64 {
    fn add(
        pc: &ParmesanCloudovo,
        x: &i64,
        y: &i64,
    ) -> i64 {x + y}

    fn sub(
        pc: &ParmesanCloudovo,
        x: &i64,
        y: &i64,
    ) -> i64 {x - y}

    fn scalar_mul(
        pc: &ParmesanCloudovo,
        k: i32,
        x: &i64,
    ) -> i64 {(k as i64) * x}

    fn sgn(
        pc: &ParmesanCloudovo,
        x: &i64,
    ) -> i64 {x.signum()}

    fn max(
        pc: &ParmesanCloudovo,
        x: &i64,
        y: &i64,
    ) -> i64 {std::cmp::max(*x, *y)}

    fn mul(
        pc: &ParmesanCloudovo,
        x: &i64,
        y: &i64,
    ) -> i64 {x * y}
}

impl ParmArithmetics for ParmCiphertext {
    fn add(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
        y: &ParmCiphertext,
    ) -> ParmCiphertext {
        addition::add_sub_impl(
            true,
            pc.pub_keys,
            x,
            y,
        ).expect("ParmArithmetics::add failed.")
    }

    fn sub(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
        y: &ParmCiphertext,
    ) -> ParmCiphertext {
        addition::add_sub_impl(
            false,
            pc.pub_keys,
            x,
            y,
        ).expect("ParmArithmetics::sub failed.")
    }

    fn scalar_mul(
        pc: &ParmesanCloudovo,
        k: i32,
        x: &ParmCiphertext,
    ) -> ParmCiphertext {
        scalar_multiplication::scalar_mul_impl(
            pc.params,
            pc.pub_keys,
            k,
            x,
        ).expect("ParmArithmetics::scalar_mul failed.")
    }

    fn sgn(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
    ) -> ParmCiphertext {
        signum::sgn_impl(
            pc.params,
            pc.pub_keys,
            x,
        ).expect("ParmArithmetics::sgn failed.")
    }

    fn max(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
        y: &ParmCiphertext,
    ) -> ParmCiphertext {
        maximum::max_impl(
            pc.params,
            pc.pub_keys,
            x,
            y,
        ).expect("ParmArithmetics::max failed.")
    }

    fn mul(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
        y: &ParmCiphertext,
    ) -> ParmCiphertext {
        multiplication::mul_impl(
            pc.pub_keys,
            x,
            y,
        ).expect("ParmArithmetics::mul failed.")
    }
}
