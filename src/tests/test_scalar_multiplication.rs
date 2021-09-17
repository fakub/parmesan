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

// We implement a function that takes as input two integers, we encrypt one of the two integers, multiply it with scalar and compare the result obtained after
// parmesan scalar_multiplication and the expected result of multiplication on plaintext integers.

fn test_scalar_mul_m(k: i32, m1: i64, filename: &str) -> Result<(), Box<dyn Error>> {
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
    //----------------------------------
    let len_m1 = message_size(m1);
    let len_k = message_size(k as i64);

    // encrypt the message m1
    let nb_enc_bits = std::cmp::max(len_m1, len_k);
    let enc_m1 = pu.encrypt(m1, nb_enc_bits)?;

    // print the input of the current test and the length of the input

    println!(
                "test: scalar multiplication , status:- , samples : m1(encrypted) : {} , k(scalar) : {} , m1.size : {} , k.size : {} , length of decrypted result : - ",
                m1, k, len_m1, len_k
            );

    // add(scalar_multiply(enc_m1,k),enc_m1) and then decrypt
    // For k=0, we surprisingly obtain as a result 2*m1 while we expect m1

    let output_sc = ParmArithmetics::scalar_mul(&pc, k, &enc_m1);
    let res: i64 = pu.decrypt(&output_sc)?;
    let len_res = message_size(res);
    /*
    println!(
        "test: scalar multiplication , status:- , samples : m1(encrypted) : {} , m2(plaintext) : {} ,  m1.size : {} , m2.size : {} , length of decrypted result : - ",
        m1, k, len_m1, len_k
    ); */

    // we compare the decrypted result to the multiplication between plaintext integers m1 and k
    if m1 * k as i64 == res {
        println!(
            "test: scalar multiplication , status: valid , samples : m1(encrypted) : {} , m2(plaintext) : {} , decrypted result {},  m1.size : {} , m2.size : {} , length of decrypted result : {} ",
            m1, k , res, len_m1 , len_k, len_res
        );
        // if the test succeeds, we write the test result into a file "scalar_multiply_samples.txt"
        let line = "test: scalar multiplication , status : valid, samples : m1 : ".to_owned()
            + &m1.to_string()
            + ", k : "
            + &k.to_string()
            + ", decrypted result : "
            + &res.to_string()
            + ", m1.size : "
            + &len_m1.to_string()
            + ", m2.size : "
            + &len_k.to_string()
            + "length of decrypted result : "
            + &len_res.to_string()
            + "\n";
        let mut scalar_multiply_message = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open("src/tests/test_history/".to_owned() + filename + "_samples.txt")
            .unwrap();
        scalar_multiply_message.write_all(line.as_bytes()).unwrap();
    } else {
        println!(
                    "test: scalar multiplication , status: failure , samples : m1(encrypted) : {} , m2(plaintext) : {} , m1.size : {} , m2.size : {} , decrypted result : {} , length of decrypted result : {} ",
                    m1, k, res, len_m1, len_k, len_res
                );
        // if the test fails, we write the test result into a file "scalar_multiply_failures.txt"
        let line = "test: scalar multiplication , status : failure, samples : m1 : ".to_owned()
            + &m1.to_string()
            + ", k : "
            + &k.to_string()
            + ", decrypted result : "
            + &res.to_string()
            + ", m1.size : "
            + &len_m1.to_string()
            + ", m2.size : "
            + &len_k.to_string()
            + "length of decrypted result : "
            + &len_res.to_string()
            + "\n";
        let mut scalar_multiply_message = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open("src/tests/test_history/".to_owned() + filename + "_failures.txt")
            .unwrap();
        scalar_multiply_message.write_all(line.as_bytes()).unwrap();
    }
    assert_eq!(res, m1 * k as i64);
    Ok(())
}

// we implement a function that takes as input two integers k and m1 and perform : add(scalar_multiply(enc_m1,k),enc_m1)
// then we decrypt the result and compare it to m1*k + m1

fn test_scalar_mul_add_m(k: i32, m1: i64, filename: &str) -> Result<(), Box<dyn Error>> {
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
    //----------------------------------
    let len_m1 = message_size(m1);
    let len_k = message_size(k as i64);

    // encrypt the message m1
    let nb_enc_bits = std::cmp::max(len_m1, len_k);
    let enc_m1 = pu.encrypt(m1, nb_enc_bits)?;

    // print the input of the current test and the length of the input

    println!(
                "test: scalar multiplication + addition , status:- , samples : m1(encrypted) : {} , k (scalar): {} , m1.size : {} , k.size : {} , length of decrypted result : - ",
                m1, k, len_m1, len_k
            );

    // add(scalar_multiply(enc_m1,k),enc_m1) and then decrypt

    let output_sc = ParmArithmetics::scalar_mul(&pc, k, &enc_m1);
    let output_add = ParmArithmetics::add(&pc, &enc_m1, &output_sc);
    let res: i64 = pu.decrypt(&output_add)?;
    let len_res = message_size(res);
    /*
    println!(
        "test: scalar multiplication , status:- , samples : m1(encrypted) : {} , m2(plaintext) : {} ,  m1.size : {} , m2.size : {} , length of decrypted result : - ",
        m1, k, len_m1, len_k
    ); */

    // we compare the decrypted result to the multiplication between plaintext integers m1 and k

    if m1 * k as i64 + m1 as i64 == res {
        println!(
            "test: scalar multiplication + addition , status: valid , samples : m1(encrypted) : {} , k (scalar): {} , decrypted result {},  m1.size : {} , k.size : {} , length of decrypted result : {} ",
            m1, k , res, len_m1 , len_k, len_res
        );

        // if the test succeeds, we write the test result into a file "scalar_multiply_samples.txt"

        let line = "test: scalar multiplication + addition, status : valid, samples : m1 : "
            .to_owned()
            + &m1.to_string()
            + ", k : "
            + &k.to_string()
            + ", decrypted result : "
            + &res.to_string()
            + ", m1.size : "
            + &len_m1.to_string()
            + ", m2.size : "
            + &len_k.to_string()
            + "length of decrypted result : "
            + &len_res.to_string()
            + "\n";
        let mut scalar_multiply_message = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open("src/tests/test_history/".to_owned() + filename + "_samples.txt")
            .unwrap();
        scalar_multiply_message.write_all(line.as_bytes()).unwrap();
    } else {
        println!(
                    "test: scalar multiplication + addition , status: failure , samples : m1(encrypted) : {} , k (scalar): {} , m1.size : {} , k.size : {} , decrypted result : {} , length of decrypted result : {} ",
                    m1, k, res, len_m1, len_k, len_res
                );
        // if the test fails, we write the test result into a file "scalar_multiply_failures.txt"
        let line = "test: scalar multiplication + addition, status : failure, samples : m1 : "
            .to_owned()
            + &m1.to_string()
            + ", k : "
            + &k.to_string()
            + ", decrypted result : "
            + &res.to_string()
            + ", m1.size : "
            + &len_m1.to_string()
            + ", m2.size : "
            + &len_k.to_string()
            + "length of decrypted result : "
            + &len_res.to_string()
            + "\n";
        let mut scalar_multiply_message = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open("src/tests/test_history/".to_owned() + filename + "_failures.txt")
            .unwrap();
        scalar_multiply_message.write_all(line.as_bytes()).unwrap();
    }
    assert_eq!(res, k as i64 * m1 + m1);
    Ok(())
}

#[test]

// this test calls the function test_scalar_mul_m and test_scalar_mul_add_m, therefore we can make tests on a specific input we want to test

fn test_scalar_multiply() {
    let mut rng = rand::thread_rng();
    let m = rng.gen_range(-1073741823..1073741823);
    test_scalar_mul_add_m(0, m, "scalar_mul_add_zero").unwrap();
    test_scalar_mul_m(0, m, "scalar_mul_zero").unwrap();
    test_scalar_mul_m(1, m, "scalar_mul_one").unwrap();
    test_scalar_mul_m(-1, m, "scalar_mul_neg_one").unwrap();
}

#[test]

// this test generates two random integers m1 and k, encrypts m1 and multiplies it by the scalar k, then we decrypt the result and compare it
// to the expected result of the multiplication on plaintext integeres ; m1*k.

fn scalar_mul_rd() {
    let mut rng = rand::thread_rng();
    let filename = "scalar_mul_rd";
    let mut m1: i64;
    let mut k: i32;
    for _i in 0..10 {
        m1 = rng.gen_range(-1073741823..1073741823);
        k = rng.gen_range(-1073741823..1073741823);
        test_scalar_mul_m(k, m1, filename).unwrap();
    }
}

#[test]

// In this test we encrypt an integer and multiply it with a scalar k such as the hamming_weight(k) = 1, then we decrypt the result and compare it
// to the expected result of the multiplication on plaintext integeres ; m1*k.

fn scalar_mul_hw1() {
    let mut rng = rand::thread_rng();
    let filename = "scalar_mul_hw1";
    for i in 0..31 {
        // generate k such that k = 2^i
        let base: i32 = 2;
        let k = base.pow(i);
        // generate a random integer m1
        let m1 = rng.gen_range(-1073741823..1073741823);
        test_scalar_mul_m(k, m1, filename).unwrap();
    }
}
