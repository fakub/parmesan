use colored::Colorize;

use crate::ciphertexts::{ParmCiphertext, ParmCiphertextImpl};
use crate::ParmesanCloudovo;
use crate::cloudovo::*;


// =============================================================================
//
//  Parmesan Arithmetics
//

/// Parmesan Arithmetics Trait
pub trait ParmArithmetics {
    /// Zero: `0`
    fn zero() -> Self;

    //TODO (add parameter length)
    //~ /// Const: `k`
    //~ fn constant(
        //~ pc: &ParmesanCloudovo,
        //~ k: i32,
    //~ ) -> Self;

    /// Opposite: `-X`
    fn opp(x: &Self) -> Self;

    /// Binary Shift: `X << k`
    fn shift(
        pc: &ParmesanCloudovo,
        x: &Self,
        k: usize,
    ) -> Self;

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

    /// Noisy Addition: `X + Y`
    /// (n.b., only when result gets immediately decrypted)
    fn add_noisy(
        pc: &ParmesanCloudovo,
        x: &Self,
        y: &Self,
    ) -> Self;

    /// Noisy Subtraction: `X - Y`
    /// (n.b., only when result gets immediately decrypted)
    fn sub_noisy(
        pc: &ParmesanCloudovo,
        x: &Self,
        y: &Self,
    ) -> Self;

    /// Add constant: `X + k`
    fn add_const(
        pc: &ParmesanCloudovo,
        x: &Self,
        k: i64,
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

    /// ReLU: `max{0, X}`
    fn relu(
        pc: &ParmesanCloudovo,
        x: &Self,
    ) -> Self;

    /// Multiplication: `X × Y`
    fn mul(
        pc: &ParmesanCloudovo,
        x: &Self,
        y: &Self,
    ) -> Self;

    /// Squaring: `X²`
    fn squ(
        pc: &ParmesanCloudovo,
        x: &Self,
    ) -> Self;

    /// Rounding
    fn round_at(
        pc: &ParmesanCloudovo,
        x: &Self,
        pos: usize,
    ) -> Self;

    //WISH noisy variant of round_at?
}

impl ParmArithmetics for i64 {
    fn zero() -> i64 {0i64}

    fn opp(x: &i64) -> i64 {-x}

    fn shift(
        _pc: &ParmesanCloudovo,
        x: &i64,
        k: usize,
    ) -> i64 {x << k}

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

    fn add_noisy(
        _pc: &ParmesanCloudovo,
        x: &i64,
        y: &i64,
    ) -> i64 {x + y}

    fn sub_noisy(
        _pc: &ParmesanCloudovo,
        x: &i64,
        y: &i64,
    ) -> i64 {x - y}

    fn add_const(
        _pc: &ParmesanCloudovo,
        x: &i64,
        k: i64,
    ) -> i64 {x + k}

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

    fn relu(
        _pc: &ParmesanCloudovo,
        x: &i64,
    ) -> i64 {std::cmp::max(0, *x)}

    fn mul(
        _pc: &ParmesanCloudovo,
        x: &i64,
        y: &i64,
    ) -> i64 {x * y}

    fn squ(
        _pc: &ParmesanCloudovo,
        x: &i64,
    ) -> i64 {x * x}

    fn round_at(
        _pc: &ParmesanCloudovo,
        x: &i64,
        pos: usize,
    ) -> i64 {
        match pos {
            0 => { *x },
            p if p >= 63 => { panic!("Rounding position ≥ 63 (for i64).") },
            _ => {
            //  XXXX XXXX - 0000 0XXX + 0000 0X00 << 1
                        x
                          - (x & ((1 << pos) - 1))
                                      + ((x & (1 << (pos-1))) << 1)
            },
        }
    }
}

impl ParmArithmetics for ParmCiphertext {
    fn zero() -> ParmCiphertext {
        ParmCiphertext::empty()
    }

    fn opp(x: &ParmCiphertext) -> ParmCiphertext {
        addition::opposite_impl(x).expect("ParmArithmetics::opp failed.")
    }

    fn shift(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
        k: usize,
    ) -> ParmCiphertext {
        if k == 0 {return x.clone();}
        let mut x_shifted = ParmCiphertext::triv(k, &pc.params).expect("ParmCiphertext::triv failed.");
        x_shifted.append(&mut x.clone());
        x_shifted
    }

    fn add(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
        y: &ParmCiphertext,
    ) -> ParmCiphertext {
        #[cfg(feature = "seq_analyze")]
        unsafe { crate::N_PBS = 0; }

        let res = addition::add_sub_impl(
            true,
            pc,
            x,
            y,
            true,
        ).expect("ParmArithmetics::add failed.");

        #[cfg(feature = "seq_analyze")]
        unsafe { println!("{}  └ {} PBS", "  │ ".repeat(crate::LOG_LVL as usize), String::from(format!("{}", crate::N_PBS)).red().bold()); }

        res
    }

    fn sub(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
        y: &ParmCiphertext,
    ) -> ParmCiphertext {
        #[cfg(feature = "seq_analyze")]
        unsafe { crate::N_PBS = 0; }

        let res = addition::add_sub_impl(
            false,
            pc,
            x,
            y,
            true,
        ).expect("ParmArithmetics::sub failed.");

        #[cfg(feature = "seq_analyze")]
        unsafe { println!("{}  └ {} PBS", "  │ ".repeat(crate::LOG_LVL as usize), String::from(format!("{}", crate::N_PBS)).red().bold()); }

        res
    }

    fn add_noisy(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
        y: &ParmCiphertext,
    ) -> ParmCiphertext {
        #[cfg(feature = "seq_analyze")]
        unsafe { crate::N_PBS = 0; }

        let res = addition::add_sub_impl(
            true,
            pc,
            x,
            y,
            false,
        ).expect("ParmArithmetics::add failed.");

        #[cfg(feature = "seq_analyze")]
        unsafe { println!("{}  └ {} PBS", "  │ ".repeat(crate::LOG_LVL as usize), String::from(format!("{}", crate::N_PBS)).red().bold()); }

        res
    }

    fn sub_noisy(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
        y: &ParmCiphertext,
    ) -> ParmCiphertext {
        #[cfg(feature = "seq_analyze")]
        unsafe { crate::N_PBS = 0; }

        let res = addition::add_sub_impl(
            false,
            pc,
            x,
            y,
            false,
        ).expect("ParmArithmetics::sub failed.");

        #[cfg(feature = "seq_analyze")]
        unsafe { println!("{}  └ {} PBS", "  │ ".repeat(crate::LOG_LVL as usize), String::from(format!("{}", crate::N_PBS)).red().bold()); }

        res
    }

    fn add_const(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
        k: i64,
    ) -> ParmCiphertext {
        #[cfg(feature = "seq_analyze")]
        unsafe { crate::N_PBS = 0; }

        let res = addition::add_const_impl(
            pc,
            x,
            k,
        ).expect("ParmArithmetics::add_const failed.");

        #[cfg(feature = "seq_analyze")]
        unsafe { println!("{}  └ {} PBS", "  │ ".repeat(crate::LOG_LVL as usize), String::from(format!("{}", crate::N_PBS)).red().bold()); }

        res
    }

    fn scalar_mul(
        pc: &ParmesanCloudovo,
        k: i32,
        x: &ParmCiphertext,
    ) -> ParmCiphertext {
        #[cfg(feature = "seq_analyze")]
        unsafe { crate::N_PBS = 0; }

        let res = scalar_multiplication::scalar_mul_impl(
            pc,
            k,
            x,
        ).expect("ParmArithmetics::scalar_mul failed.");

        #[cfg(feature = "seq_analyze")]
        unsafe { println!("{}  └ {} PBS", "  │ ".repeat(crate::LOG_LVL as usize), String::from(format!("{}", crate::N_PBS)).red().bold()); }

        res
    }

    fn sgn(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
    ) -> ParmCiphertext {
        #[cfg(feature = "seq_analyze")]
        unsafe { crate::N_PBS = 0; }

        let res = signum::sgn_impl(
            pc,
            x,
        ).expect("ParmArithmetics::sgn failed.");

        #[cfg(feature = "seq_analyze")]
        unsafe { println!("{}  └ {} PBS", "  │ ".repeat(crate::LOG_LVL as usize), String::from(format!("{}", crate::N_PBS)).red().bold()); }

        res
    }

    fn max(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
        y: &ParmCiphertext,
    ) -> ParmCiphertext {
        #[cfg(feature = "seq_analyze")]
        unsafe { crate::N_PBS = 0; }

        let res = maximum::max_impl(
            pc,
            x,
            y,
        ).expect("ParmArithmetics::max failed.");

        #[cfg(feature = "seq_analyze")]
        unsafe { println!("{}  └ {} PBS", "  │ ".repeat(crate::LOG_LVL as usize), String::from(format!("{}", crate::N_PBS)).red().bold()); }

        res
    }

    fn relu(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
    ) -> ParmCiphertext {
        #[cfg(feature = "seq_analyze")]
        unsafe { crate::N_PBS = 0; }

        let res = maximum::max_impl(
            pc,
            &ParmArithmetics::zero(),
            x,
        ).expect("ParmArithmetics::relu failed.");

        #[cfg(feature = "seq_analyze")]
        unsafe { println!("{}  └ {} PBS", "  │ ".repeat(crate::LOG_LVL as usize), String::from(format!("{}", crate::N_PBS)).red().bold()); }

        res
    }

    fn mul(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
        y: &ParmCiphertext,
    ) -> ParmCiphertext {
        #[cfg(feature = "seq_analyze")]
        unsafe { crate::N_PBS = 0; }

        let res = multiplication::mul_impl(
            pc,
            x,
            y,
        ).expect("ParmArithmetics::mul failed.");

        #[cfg(feature = "seq_analyze")]
        unsafe { println!("{}  └ {} PBS", "  │ ".repeat(crate::LOG_LVL as usize), String::from(format!("{}", crate::N_PBS)).red().bold()); }

        res
    }

    fn squ(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
    ) -> ParmCiphertext {
        #[cfg(feature = "seq_analyze")]
        unsafe { crate::N_PBS = 0; }

        let res = squaring::squ_impl(
            pc,
            x,
        ).expect("ParmArithmetics::squ failed.");

        #[cfg(feature = "seq_analyze")]
        unsafe { println!("{}  └ {} PBS", "  │ ".repeat(crate::LOG_LVL as usize), String::from(format!("{}", crate::N_PBS)).red().bold()); }

        res
    }

    fn round_at(
        pc: &ParmesanCloudovo,
        x: &ParmCiphertext,
        pos: usize,
    ) -> ParmCiphertext {
        #[cfg(feature = "seq_analyze")]
        unsafe { crate::N_PBS = 0; }

        let res = rounding::round_at_impl(
            pc,
            x,
            pos,
        ).expect("ParmArithmetics::round_at failed.");

        #[cfg(feature = "seq_analyze")]
        unsafe { println!("{}  └ {} PBS", "  │ ".repeat(crate::LOG_LVL as usize), String::from(format!("{}", crate::N_PBS)).red().bold()); }

        res
    }
}
