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
//!     I3 --(--o-> |   Wi      | ---       o-----------o
//!          |      |           |
//!     I4 --(----> |   Wi  +B  |
//!          |      |           |
//!          |   -> |   Wi      | ---
//!          |  |   |           |    |
//!          |  |   o-----------o    |
//!          |  |                    |
//!          |  |   o-- ACT ----o    |
//!          |  |   |           |     ----> ...
//!     I5 --o--o-> |   Wi      |
//!                 |       +B  | --------> ...
//!     I6 -------> |   Wi      |
//!                 |           |
//!                 o-----------o
//!```

#[allow(unused_imports)]
use colored::Colorize;

use crate::ParmesanCloudovo;
use crate::arithmetics::ParmArithmetics;

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
    pub t: PercType,
    // weights to perceptrons in the preceeding layer
    pub w: Vec<i32>,
    // bias
    pub b: i32,
}

/// Layer
pub type Layer = Vec<Perceptron>;

/// Neural Network
pub struct NeuralNetwork {
    //  NN consists of layers, evaluated one after each other
    pub layers: Vec<Layer>,
}

impl NeuralNetwork {

    /// Evaluate Neural Network
    pub fn eval<T: Clone + ParmArithmetics>( // T is either i32, or ParmCiphertext
        &self,
        pc: &ParmesanCloudovo,
        inputs: &Vec<T>,
    ) -> Vec<T> {

        let mut il = inputs.clone();
        let mut ol: Vec<T> = Vec::new();

        measure_duration!(
            ["Neural Network evaluation over {}", std::any::type_name::<T>()],
            [
                for (_li, layer) in self.layers.iter().enumerate() {
                    measure_duration!(
                        ["{}. layer evaluation", _li],
                        [
                            self.eval_layer::<T>(pc, layer, &il, &mut ol);
                            // last output is next input
                            il = ol.clone();
                        ]
                    );
                }
            ]
        );

        ol
    }

    /// Evaluate a layer of NN
    pub fn eval_layer<T: Clone + ParmArithmetics>(
        &self,
        pc: &ParmesanCloudovo,
        layer: &Layer,
        input: &Vec<T>,
        output: &mut Vec<T>,
    ) {
        output.clear();

        // evaluate perceptron by type
        for (_ip, perc) in layer.iter().enumerate() {
            measure_duration!(
                ["{}. perceptron evaluation", _ip],
                [
                    match &perc.t {
                        PercType::MAX => {
                            let max = self.max_pool::<T>(pc, &perc.w, input, perc.b);
                            output.push(max);
                        },
                        PercType::LIN => {
                            let aff = self.affine_pool::<T>(pc, &perc.w, input, perc.b);
                            output.push(aff);
                        },
                        PercType::ACT => {
                            let aff = self.affine_pool::<T>(pc, &perc.w, input, perc.b);
                            output.push(self.act_fn::<T>(pc, &aff));
                        },
                    }
                ]
            );
        }
    }

    pub fn affine_pool<T: Clone + ParmArithmetics>(
        &self,
        pc: &ParmesanCloudovo,
        w: &Vec<i32>,
        a: &Vec<T>,
        b: i32,
    ) -> T {

        let mut res: T = ParmArithmetics::zero();
        let mut agg: T;
        let mut scm: T;

        // dot product
        for (wi, ai) in w.iter().zip(a.iter()) {
            scm = ParmArithmetics::scalar_mul(pc, *wi, ai);
            agg = ParmArithmetics::add(pc, &res, &scm);
            //TODO try directly to res, or implement add_inplace? (rather not..)
            res = agg.clone();
        }

        // + bias
        ParmArithmetics::add_const(pc, &res, b)
    }

    pub fn max_pool<T: Clone + ParmArithmetics>(
        &self,
        pc: &ParmesanCloudovo,
        w: &Vec<i32>,
        a: &Vec<T>,
        b: i32,
    ) -> T {

        let mut wa: Vec<T> = Vec::new();

        // apply weights
        for (wi, ai) in w.iter().zip(a.iter()) {
            wa.push(ParmArithmetics::scalar_mul(pc, *wi, ai));
        }

        // locate maximum
        let res = self.max_pool_recursion::<T>(pc, &wa);

        // + bias
        ParmArithmetics::add_const(pc, &res, b)
    }

    fn max_pool_recursion<T: Clone + ParmArithmetics>(
        &self,
        pc: &ParmesanCloudovo,
        a: &Vec<T>,
    ) -> T {
        if a.len() == 0 {
            //TODO return MAX_NEG .. should be returned from mathematical point of view .. write a macro for its behavior?
            return ParmArithmetics::zero();
        } else if a.len() == 1 {
            return a[0].clone();
        }

        let mut a_half: Vec<T> = Vec::new();
        for aic in a.chunks(2) {
            if aic.len() == 2 {
                a_half.push(ParmArithmetics::max(pc, &aic[0], &aic[1]));
            } else {
                a_half.push(aic[0].clone())
            }
        }

        return self.max_pool_recursion::<T>(pc, &a_half);
    }

    pub fn act_fn<T: ParmArithmetics>(
        &self,
        pc: &ParmesanCloudovo,
        lc: &T,   // lc .. for linear combination
    ) -> T {
        ParmArithmetics::sgn(pc, lc)    // sgn   relu
    }
}
