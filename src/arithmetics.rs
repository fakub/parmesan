use super::ciphertexts::{ParmCiphertext, ParmCiphertextExt};
use super::ParmesanCloudovo;
use super::cloudovo::*;


// =============================================================================
//
//  Parmesan Arithmetics
//

/// Parmesan Arithmetics Trait
pub trait ParmArithmetics {
    /// Zero: `0`
    fn zero() -> Self;

    // needed?
    //~ /// Const: `k`
    //~ fn constant(
        //~ pc: &ParmesanCloudovo,
        //~ k: i32,
    //~ ) -> Self;

    /// Opposite: `-X`
    fn opp(x: &Self) -> Self;

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

    /// Add constant: `X + k`
    fn add_const(
        pc: &ParmesanCloudovo,
        x: &Self,
        k: i32,
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
    fn zero() -> i64 {0i64}

    fn opp(x: &i64) -> i64 {-x}

    fn add(
        _pc: &ParmesanCloudovo,
        x: &i64,
        y: &i64,
    ) -> i64 {x + y}

    fn sub(
        _pc: &ParmesanCloudovo,
        x: &i64,
        y: &i64,
    ) -> i64 {x - y}

    fn add_const(
        _pc: &ParmesanCloudovo,
        x: &i64,
        k: i32,
    ) -> i64 {x + (k as i64)}

    fn scalar_mul(
        _pc: &ParmesanCloudovo,
        k: i32,
        x: &i64,
    ) -> i64 {(k as i64) * x}

    fn sgn(
        _pc: &ParmesanCloudovo,
        x: &i64,
    ) -> i64 {x.signum()}

    fn max(
        _pc: &ParmesanCloudovo,
        x: &i64,
        y: &i64,
    ) -> i64 {std::cmp::max(*x, *y)}

    fn mul(
        _pc: &ParmesanCloudovo,
        x: &i64,
        y: &i64,
    ) -> i64 {x * y}
}

impl ParmArithmetics for ParmCiphertext {
    fn zero() -> ParmCiphertext {
        ParmCiphertext::empty()
    }

    fn opp(x: &ParmCiphertext) -> ParmCiphertext {
        addition::opposite_impl(x).expect("ParmArithmetics::opp failed.")
    }

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

    fn add_const(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
        k: i32,
    ) -> ParmCiphertext {
        addition::add_const_impl(
            pc.params,
            pc.pub_keys,
            x,
            k,
        ).expect("ParmArithmetics::add_const failed.")
    }

    fn scalar_mul(
        pc: &ParmesanCloudovo,
        k: i32,
        x: &ParmCiphertext,
    ) -> ParmCiphertext {
        scalar_multiplication::scalar_mul_impl(
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
