//!
//! # Module for Neural Network evaluation over a generic type `<T>`
//!
//! Example with 7 inputs and 4 perceptrons depicted in two layers:
//!
//! ```text
//!                 o-- LIN ----o
//!                 |           |
//!     I0 -------> |   Wi      |
//!                 |           |
//!     I1 -------> |   Wi      |
//!                 |           |
//!     I2 -------> |   Wi  +B  | --------> ...
//!                 |           |
//!           ----> |   Wi      |
//!          |      |           |
//!          |   -> |   Wi      | ---       o-- MAX ---o
//!          |  |   |           |    |      |           |
//!          |  |   o-----------o     ----> |   Wi      |
//!          |  |                           |       +B  | -------->  ...  --------> OUTPUT
//!          |  |   o-- LIN ----o     ----> |   Wi      |
//!          |  |   |           |    |      |           |
//!     I3 --(--o-> |   Wi      | ----      o-----------o
//!          |      |           |
//!     I4 --(----> |   Wi  +B  |
//!          |      |           |
//!          |   -> |   Wi      |
//!          |  |   |           |
//!          |  |   o-----------o
//!          |  |
//!          |  |   o-- ACT ----o
//!          |  |   |           |
//!     I5 --o--o-> |   Wi      |
//!                 |       +B  | --------> ...
//!     I6 -------> |   Wi      |
//!                 |           |
//!                 o-----------o
//!```

use crate::ParmesanCloudovo;
use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};
use crate::ParmArithmetic;

/// Perceptron type:
/// * maximum,
/// * linear combination,
/// * linear combination with activation function (signum).
/// ReLU as activation function can be constructed in two layers as MAX{LIN, 0}.
pub enum PercType {
    // maximum of weighted inputs + bias
    MAX,
    // sum of weighted inputs + bias (affine mapping; useful as an input for MAX perceptron)
    LIN,
    // LIN with a non-linear activation function applied (signum)
    ACT,
}

/// Perceptron
pub struct Perceptron {
    // perceptron type
    t: PercType,
    // weights to perceptrons in the preceeding layer
    w: Vec<i32>,
    // bias
    b: i32,
}

/// Layer
pub type Layer = Vec<Perceptron>;

/// Neural Network
pub struct NeuralNetwork<'a> {
    //  NN consists of layers, evaluated one after each other
    pub layers: Vec<Layer>,
    pub pc: &'a ParmesanCloudovo<'a>,
}

impl NeuralNetwork<'_> {

    /// Evaluate Neural Network
    pub fn eval<T: Clone + ParmArithmetic>( // T is either i32, or ParmCiphertext
        &self,
        inputs: &Vec<T>,
    ) -> Vec<T> {   //TODO Result<Vec<T>, Box<dyn Error>>

        let mut il = inputs.clone();
        let mut ol: Vec<T> = Vec::new();

        for layer in &self.layers {
            self.eval_layer::<T>(layer, &il, &mut ol);
            // last output is next input
            il = ol.clone();
        }

        ol
    }

    /// Evaluate a layer of NN
    pub fn eval_layer<T: Clone + ParmArithmetic>(
        &self,
        layer: &Layer,
        input: &Vec<T>,
        output: &mut Vec<T>,
    ) {
        output.clear();

        // evaluate perceptron by type
        for perc in layer {
            match &perc.t {
                PercType::MAX => {
                    let max = self.max_pool::<T>(&perc.w, input, perc.b);
                    output.push(max);
                },
                PercType::LIN => {
                    let aff = self.affine_pool::<T>(&perc.w, input, perc.b);
                    output.push(aff);
                },
                PercType::ACT => {
                    let aff = self.affine_pool::<T>(&perc.w, input, perc.b);
                    output.push(self.act_fn::<T>(aff));
                },
            }
        }
    }

    pub fn affine_pool<T: Clone + ParmArithmetic>(
        &self,
        w: &Vec<i32>,
        a: &Vec<T>,
        b: i32,
    ) -> T {        //TODO Result<...>

        //~ let mut res: T = 0 as T;

        for (wi, ai) in w.iter().zip(a.iter()) {
            //TODO res += scalar_mul(wi, ai);
        }
        // res += b;

        //~ a[0].clone();
        //~ res

        ParmArithmetic::add_tr(self.pc, &a[0], &a[1])
    }

    pub fn max_pool<T: Clone + ParmArithmetic>(
        &self,
        w: &Vec<i32>,
        a: &Vec<T>,
        b: i32,
    ) -> T {        //TODO Result<...>

        let mut wa: Vec<T> = Vec::new();

        for (wi, ai) in w.iter().zip(a.iter()) {
            //TODO wa.push(scalar_mul(wi, ai));
        }

        //~ self.max_pool_recursion::<T>(wa) + b;

        a[0].clone()
        //~ res
    }

    fn max_pool_recursion<T: Clone + ParmArithmetic>(
        &self,
        a: &Vec<T>,
    ) -> T {

        //TODO
        if a.len() == 0 {
            // return MAX_NEG
        } else if a.len() == 1 {
            return a[0].clone();
        }

        let mut a_half: Vec<T> = Vec::new();
        // a_half.push(super::max_impl(each pair))
        // return max_pool_recursion::<T>(a_half);

        a[0].clone()
    }

    pub fn act_fn<T: ParmArithmetic>(
        &self,
        lc: T,
    ) -> T {
        //TODO signum(lc)
        lc
    }
}
