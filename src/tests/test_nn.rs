//~ extern crate rand;
use rand::{distributions::{Distribution,Standard},Rng};

use crate::tests::{self,*};
use crate::userovo::encryption;
use crate::*;

#[test]
/// NN Evaluation over encrypted sub-samples only.
fn t_nn_eval_non_triv() {
    println!("Non-Triv ...");
    t_impl_nn_eval_with_mode(EncrVsTriv::ENCR);
}

#[test]
/// NN Evaluation over trivial sub-samples only.
fn t_nn_eval_all_triv() {
    println!("All-Triv ...");
    t_impl_nn_eval_with_mode(EncrVsTriv::TRIV);
}

#[test]
/// NN Evaluation over mixed sub-samples.
fn t_nn_eval_some_triv() {
    println!("Mixed ...");
    t_impl_nn_eval_with_mode(EncrVsTriv::ENCRTRIV);
}


// -----------------------------------------------------------------------------
//  Test Implementations

/// Implementation for three variants of vector to be evaluated.
fn t_impl_nn_eval_with_mode(mode: EncrVsTriv) {
    // generate random NN
    let nn = t_gen_nn();

    for _ in 0..TESTS_REPEAT_NNE {
        let mut m_in_vec = vec![];
        let mut m_in = vec![];
        let mut c_in = vec![];

        //TODO nn.n_inputs()
        for i in 0..3 {
            // generate random input
            let m_vec = gen_rand_vec(TESTS_BITLEN_NNE);
            // convert to integer
            let m = encryption::convert(&m_vec).expect("convert failed.");

            println!("  m[{}] = {} ({}-bit: {:?})", i, m, TESTS_BITLEN_NNE, m_vec);

            // encrypt
            let c = encrypt_with_mode(&m_vec, mode);

            // push to input vectors
            m_in_vec.push(m_vec);
            m_in.push(m);
            c_in.push(c);
        }

        // homomorphic eval
        let c_he = nn.eval(&tests::PC, &c_in);

        // decrypt
        let mut m_he = vec![];
        for co in c_he {
            m_he.push(PU.decrypt(&co).expect("ParmesanUserovo::decrypt failed."));

        }

        // plain eval
        let m_pl = nn.eval(&tests::PC, &m_in);

        println!("  nn_eval = {:?}\n  (exp. {:?})", m_he, m_pl);

        // compare results
        assert_eq!(m_he, m_pl);
    }
}


// -----------------------------------------------------------------------------
//  Generate Random NN

fn t_gen_nn() -> NeuralNetwork {
    let mut rng = rand::thread_rng();

    // fixed depth = 3
    let depth = 3;
    // prepare layers
    let mut layers = vec![];
    // generate input length
    let mut in_len = rng.gen_range(1..5);

    for _ in 0..depth {
        // generate number of perceptrons
        let layer_len = rng.gen_range(1..5);
        let mut layer = vec![];

        for _ in 0..layer_len {
            // generate perceptron
            //~ let t: PercType = rng.gen();

            // push to layer
            layer.push(Perceptron {
                t: rand::random(),
                w: gen_w(in_len),
                b: rng.gen_range(-15..=15),
            });
        }

        layers.push(layer);

        // number of perceptrons is the number of inputs to the next layer
        in_len = layer_len;
    }

    NeuralNetwork {layers}
}

/// Generate random `PercType`
// cf. https://stackoverflow.com/questions/48490049/how-do-i-choose-a-random-value-from-an-enum
impl Distribution<PercType> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> PercType {
        match rng.gen_range(0..=2) {
            0 => PercType::MAX,
            1 => PercType::LIN,
            _ => PercType::ACT,
        }
    }
}

fn gen_w(wlen: usize) -> Vec<i32> {
    let mut rng = rand::thread_rng();

    let mut w = vec![];
    for _ in 0..wlen {
        w.push(rng.gen_range(-7..=7))
    }
    w
}


// #############################################################################

//~ fn gen_perctype() -> PercType {
    //~ let mut rng = rand::thread_rng();
    //~ let k = rng.gen_range(0..3);
    //~ if k == 0 {
        //~ println!("t : MAX, ");
        //~ return PercType::MAX;
    //~ }
    //~ if k == 1 {
        //~ println!("t : LIN, ");
        //~ return PercType::LIN;
    //~ }
    //~ println!("t: ACT, ");
    //~ return PercType::ACT;
//~ }
