use super::*;
#[cfg(test)]
use rand::Rng;
use std::fs::OpenOptions;
use std::io::Write;

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

// In this function take two integers, m1 and m2, encrypt and add them, then we decrypt the result and compare it to m1+m2
// we save the result of tests into specific files related to each test

fn test_add_m(m1: i64, m2: i64, filename: &str) -> Result<(), Box<dyn Error>> {
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
    // check for add overflow
    let mut add_check = None;
    while add_check == None {
        add_check = m1.checked_add(m2);
    }
    let m1_len = message_size(m1);
    let m2_len = message_size(m2);
    let nb_enc_bits = std::cmp::max(m1_len, m2_len);
    println!(
            "test: addition, status:- , samples : m1 : {} , m2 : {} , m1.size : {} , m2.size : {} , length of decrypted result : - ",
            m1, m2, m1_len, m2_len
        );
    let enc_m1 = pu.encrypt(m1, nb_enc_bits)?;
    let enc_m2 = pu.encrypt(m2, nb_enc_bits)?;
    let enc_res = ParmArithmetics::add(&pc, &enc_m1, &enc_m2);
    let res: i64 = pu.decrypt(&enc_res)?;
    let res_len = message_size(res);
    if m1 + m2 == res {
        println!(
                "test: addition , status: valid , samples : m1 : {} , m2: {} , decrypted_result : {} ,  m1.size : {} , m2.size : {} , length of decrypted result : {} ",
                m1,m2,res,m1_len,m2_len,res_len
            );
        // if the test succeeds, we write the test result into a file "filename_samples.txt"
        let line = "test: addition , status : valid, samples : m1 : ".to_owned()
            + &m1.to_string()
            + ", m2 : "
            + &m2.to_string()
            + ", decrypted result : "
            + &res.to_string()
            + ", m1.size : "
            + &m1_len.to_string()
            + ", m2.size : "
            + &m2_len.to_string()
            + ", length of decrypted result"
            + &res_len.to_string()
            + "\n";
        let mut add_message = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open("src/tests/test_history/".to_owned() + filename + "_samples.txt")
            .unwrap();
        add_message.write_all(line.as_bytes()).unwrap();
    } else {
        println!(
                "test: addition , failure: valid , samples : m1 : {} , m2: {} , decrypted_result {} , m1.size : {} , m2.size : {} , length of decrypted result : {} ",
                m1,m2,res,m1_len,m2_len,res_len
            );
        // if the test fails, we write the test result into a file "filename_failures.txt"
        let line = "test: addition , status : failure, samples : m1 : ".to_owned()
            + &m1.to_string()
            + ", m2 : "
            + &m2.to_string()
            + ", decrypted result : "
            + &res.to_string()
            + ", m1.size : "
            + &m1_len.to_string()
            + ", m2.size : "
            + &m2_len.to_string()
            + ", length of decrypted result"
            + &res_len.to_string()
            + "\n";
        let mut add_message = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open("src/tests/test_history/".to_owned() + filename + "add_message_failures.txt")
            .unwrap();
        add_message.write_all(line.as_bytes()).unwrap();
    }
    assert_eq!(m1 + m2, res);
    Ok(())
}

#[test]
// in this test we add specific values we choose as input and call test_add_m to test them

fn add_m() {
    let filename = "add_message";
    test_add_m(0, -8681422182905776600, filename).unwrap();
}

#[test]
// in this test we generate random integers and add them to zero and call test_add_m to test them

fn add_zero() {
    let filename = "add_zero";
    let base: i64 = 2;
    let max_range = base.pow(62);
    let mut rng = rand::thread_rng();
    for _i in 0..10 {
        let m1 = rng.gen_range(-max_range..max_range);
        test_add_m(m1, 0, filename).unwrap();
    }
}

#[test]
// in this test we generate random values and add them to each other and call test_add_m to test them

fn add_rd() {
    let filename = "add_rand";
    let base: i64 = 2;
    let max_range = base.pow(62);
    let mut rng = rand::thread_rng();
    for _i in 0..10 {
        let m1 = rng.gen_range(-max_range..max_range);
        let m2 = rng.gen_range(-max_range..max_range);
        test_add_m(m1, m2, filename).unwrap();
    }
}

#[test]
// in this test we generate random values and add them to their opposite and call test_add_m to test them

fn add_opposite() {
    let filename = "add_opposite";
    let base: i64 = 2;
    let max_range = base.pow(62);
    let mut rng = rand::thread_rng();
    for _i in 0..10 {
        let m1 = rng.gen_range(-max_range..max_range);
        let m2 = -m1;
        test_add_m(m1, m2, filename).unwrap();
    }
}