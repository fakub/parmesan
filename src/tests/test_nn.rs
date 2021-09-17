use super::*;
#[cfg(test)]
use rand::Rng;

// this function takes as input a message m and returns its size in bits
fn message_size(m: i64) -> usize {
    if m >= 0 {
        let m_bin = format!("{:b}", m);
        return m_bin.to_string().len();
    } else {
        let m_abs = m.abs();
        let m_abs_bin = format!("{:b}", m_abs);
        return m_abs_bin.to_string().len() + 1;
    }
}

fn demo_nn() -> NeuralNetwork {
    NeuralNetwork {
        layers: vec![vec![
            Perceptron {
                t: PercType::MAX,
                w: vec![1, -2, -2],
                b: 2,
            },
            Perceptron {
                t: PercType::LIN,
                w: vec![1, 3, -1],
                b: -5,
            },
            Perceptron {
                t: PercType::ACT,
                w: vec![1, 3, -1],
                b: 3,
            },
        ]],
    }
}

fn gen_perctype() -> PercType {
    let mut rng = rand::thread_rng();
    let k = rng.gen_range(0..3);
    if k == 0 {
        println!("t : MAX, ");
        return PercType::MAX;
    }
    if k == 1 {
        println!("t : LIN, ");
        return PercType::LIN;
    }
    println!("t: ACT, ");
    return PercType::ACT;
}

fn gen_w(wlen: i32) -> Vec<i32> {
    let mut rng = rand::thread_rng();
    let mut w = vec![];
    for _i in 0..wlen {
        w.push(rng.gen_range(-3..3))
    }
    println!("w : {:?}, ", w);
    return w;
}

fn gen_b() -> i32 {
    let mut rng = rand::thread_rng();
    let b = rng.gen_range(-3..3);
    println!("b : {} \n", b);
    return b;
}

fn gen_nn() -> NeuralNetwork {
    let mut rng = rand::thread_rng();
    let nb_layers = rng.gen_range(1..5);
    let wlen = rng.gen_range(1..5);
    let mut vec_layers = vec![];
    for i in 0..nb_layers {
        println!("nn layer {} : ", i);
        let perctype_i = gen_perctype();
        let w_i = gen_w(wlen);
        let b_i = gen_b();
        vec_layers.push(Perceptron {
            t: perctype_i,
            w: w_i,
            b: b_i,
        });
    }
    NeuralNetwork {
        layers: vec![vec_layers],
    }
}

fn gen_m_in() -> Vec<i64> {
    let mut rng = rand::thread_rng();
    let m_in_len = rng.gen_range(1..5);
    let mut m_in = vec![];
    let base: i64 = 2;
    let max_range = base.pow(30);
    let mut m_in_i: i64;
    for _i in 0..m_in_len {
        m_in_i = rng.gen_range(-max_range..max_range);
        m_in.push(m_in_i);
    }
    return m_in;
}

#[test]
fn nn_eval() -> Result<(), Box<dyn Error>> {
    #[cfg(not(feature = "sequential"))]
    infobox!(
        "Parallel Neural Network DEMO ({} threads)",
        rayon::current_num_threads()
    );
    #[cfg(feature = "sequential")]
    infobox!("Sequential Neural Network DEMO");

    // =================================
    //  Initialization

    // ---------------------------------
    //  Global Scope
    let par = &params::PARM90__PI_5__D_20__LEN_32; //     PARM90__PI_5__D_20__LEN_32      PARMXX__TRIVIAL

    // ---------------------------------
    //  Userovo Scope
    let pu = ParmesanUserovo::new(par)?;
    let pub_k = pu.export_pub_keys();

    // ---------------------------------
    //  Cloudovo Scope
    let pc = ParmesanCloudovo::new(par, &pub_k);

    // =================================
    // NN input layer
    let m_in = gen_m_in();
    let input_size: usize = m_in.len();
    // encrypt all values
    let mut c_in: Vec<ParmCiphertext> = vec![];
    for _i in 0..m_in.len() {
        c_in.push(ParmCiphertext::empty());
    }
    for (ci, mi) in c_in.iter_mut().zip(m_in.iter()) {
        *ci = pu.encrypt(*mi, message_size(*mi))?;
    }

    // print input layer
    let mut intro_text = format!(
        "{}: input layer ({} elements)",
        String::from("User").bold().yellow(),
        input_size
    );
    for (i, mi) in m_in.iter().enumerate() {
        intro_text = format!(
            "{}\nIN[{}] = {}{:08b} ({:4})",
            intro_text,
            i,
            if *mi >= 0 { " " } else { "-" },
            (*mi).abs(),
            mi
        );
    }
    infoln!("{}", intro_text);

    // =================================
    //  C: Evaluation

    let gen_nn: NeuralNetwork = gen_nn();
    let c_out = gen_nn.eval(&pc, &c_in);
    let m_out_plain = gen_nn.eval(&pc, &m_in);

    // =================================
    //  U: Decryption

    let mut m_out_homo = Vec::new();
    for ci in c_out {
        m_out_homo.push(pu.decrypt(&ci)?);
    }
    println!(" m_out_homo {:?} \n ", m_out_homo);
    println!(" m_out_plain {:?} \n", m_out_plain);
    assert_eq!(m_out_homo, m_out_plain);
    Ok(())
}

#[test]
fn nn_demo() -> Result<(), Box<dyn Error>> {
    #[cfg(not(feature = "sequential"))]
    infobox!(
        "Parallel Neural Network DEMO ({} threads)",
        rayon::current_num_threads()
    );
    #[cfg(feature = "sequential")]
    infobox!("Sequential Neural Network DEMO");

    // =================================
    //  Initialization

    // ---------------------------------
    //  Global Scope
    let par = &params::PARM90__PI_5__D_20__LEN_32; //     PARM90__PI_5__D_20__LEN_32      PARMXX__TRIVIAL

    // ---------------------------------
    //  Userovo Scope
    let pu = ParmesanUserovo::new(par)?;
    let pub_k = pu.export_pub_keys();

    const INPUT_BITLEN: usize = 8;
    const INPUT_SIZE: usize = 6;

    // ---------------------------------
    //  Cloudovo Scope
    let pc = ParmesanCloudovo::new(par, &pub_k);

    // =================================
    //  U: Encryption

    // NN input layer
    let m_in: Vec<i64> = vec![
        0b11011000,
        -0b01000110,
        -0b10000100,
        0b01110011,
        -0b11011110,
        0b11110001,
    ];

    // encrypt all values
    let mut c_in: Vec<ParmCiphertext> = vec![
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
        ParmCiphertext::empty(),
    ];
    for (ci, mi) in c_in.iter_mut().zip(m_in.iter()) {
        *ci = pu.encrypt(*mi, INPUT_BITLEN)?;
    }

    // print input layer
    let mut intro_text = format!(
        "{}: input layer ({} elements)",
        String::from("User").bold().yellow(),
        INPUT_SIZE
    );
    for (i, mi) in m_in.iter().enumerate() {
        intro_text = format!(
            "{}\nIN[{}] = {}{:08b} ({:4})",
            intro_text,
            i,
            if *mi >= 0 { " " } else { "-" },
            (*mi).abs(),
            mi
        );
    }
    infoln!("{}", intro_text);

    // =================================
    //  C: Evaluation

    let c_out = demo_nn().eval(&pc, &c_in);
    let m_out_plain = demo_nn().eval(&pc, &m_in);

    // =================================
    //  U: Decryption

    let mut m_out_homo = Vec::new();
    for ci in c_out {
        m_out_homo.push(pu.decrypt(&ci)?);
    }
    println!(" m_out_homo {:?} \n ", m_out_homo);
    println!(" m_out_plain {:?} \n", m_out_plain);
    assert_eq!(m_out_homo, m_out_plain);
    Ok(())
}
