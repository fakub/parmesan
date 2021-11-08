use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;

use rand::Rng;

use crate::params;
use crate::ParmesanUserovo;
use crate::ParmesanCloudovo;
use crate::arithmetics::ParmArithmetics;

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

// In this function take two integers, m1 and m2, encrypt and multiply them, then we decrypt the result and compare it to m1*m2
// we save the result of tests into specific files related to each test

fn test_mul_m(m1: i64, m2: i64, filename: &str) -> Result<(), Box<dyn Error>> {
    // =================================
    //  Initialization

    // ---------------------------------
    //  Global Scope
    let par = &params::PARM90__PI_5__D_20__F; //     PARM90__PI_5__D_20__F      PARMXX__TRIVIAL

    // ---------------------------------
    //  Userovo Scope
    let pu = ParmesanUserovo::new(par)?;
    let pub_k = pu.export_pub_keys();
    // ---------------------------------
    //  Cloudovo Scope
    let pc = ParmesanCloudovo::new(par, &pub_k);
    let len_m1 = message_size(m1);
    let len_m2 = message_size(m2);
    let nb_enc_bits = std::cmp::max(len_m1, len_m2);
    println!(
        "test: multiplication , status: valid , samples : m1 : {} , m2: {} , decrypted result : - , m1.size : {} , m2.size : {} , length of decrypted result : - ",
        m1,m2,len_m1,len_m2
    );
    let enc_m1 = pu.encrypt(m1, nb_enc_bits)?;
    let enc_m2 = pu.encrypt(m2, nb_enc_bits)?;
    let enc_res = ParmArithmetics::mul(&pc, &enc_m1, &enc_m2);
    let res: i64 = pu.decrypt(&enc_res)?;
    let len_res = message_size(res);
    if (m1 * m2) as i64 == res {
        println!(
            "test: multiplication , status: valid , samples : m1 : {} , m2: {} , decrypted result : {} , m1.size : {} , m2.size : {} , length of decrypted result : {}",
            m1,m2,res,len_m1,len_m2,len_res
        );
        let line = "test: addition , status : valid, samples : m1 : ".to_owned()
            + &m1.to_string()
            + ", m2 : "
            + &m2.to_string()
            + ", decrypted result : "
            + &res.to_string()
            + ", m1.size : "
            + &len_m1.to_string()
            + ", m2.size : "
            + &len_m2.to_string()
            + ", length of decrypted result"
            + &len_res.to_string()
            + "\n";
        let mut mul_message = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open("src/tests/test_history/".to_owned() + filename + "_samples.txt")
            .unwrap();
        mul_message.write_all(line.as_bytes()).unwrap();
    } else {
        println!(
                "test: multiplication , status: valid , samples : m1 : {} , m2: {} , decrypted result : {} , m1.size : {} , m2.size : {} , length of decrypted result : {} ",
                m1,m2,res,len_m1,len_m2,len_res
            );
        let line = "test: addition , status : valid, samples : m1 : ".to_owned()
            + &m1.to_string()
            + ", m2 : "
            + &m2.to_string()
            + ", decrypted result : "
            + &res.to_string()
            + ", m1.size : "
            + &len_m1.to_string()
            + ", m2.size : "
            + &len_m2.to_string()
            + ", length of decrypted result"
            + &len_res.to_string()
            + "\n";
        let mut mul_message = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open("src/tests/test_history/".to_owned() + filename + "_samples.txt")
            .unwrap();
        mul_message.write_all(line.as_bytes()).unwrap();
    }
    assert_eq!((m1 * m2) as i64, res);
    Ok(())
}

//test squaring
fn test_squaring (m1: i64 , filename: &str) -> Result<(), Box<dyn Error>> {
    // =================================
    //  Initialization

    // ---------------------------------
    //  Global Scope
    let par = &params::PARM90__PI_5__D_20__F; //     PARM90__PI_5__D_20__F      PARMXX__TRIVIAL

    // ---------------------------------
    //  Userovo Scope
    let pu = ParmesanUserovo::new(par)?;
    let pub_k = pu.export_pub_keys();
    // ---------------------------------
    //  Cloudovo Scope
    let pc = ParmesanCloudovo::new(par, &pub_k);
    let len_m1 = message_size(m1);
    println!(
        "test: squaring , status: - , samples : m1 : {}, decrypted result : - , m1.size : {}, length of decrypted result : - ",
        m1,len_m1,
    );
    let enc_m1 = pu.encrypt(m1, len_m1)?;
    let enc_res = ParmArithmetics::squ(&pc, &enc_m1);
    let res: i64 = pu.decrypt(&enc_res)?;
    let len_res = message_size(res);
    if (m1 * m1) as i64 == res {
        println!(
            "test: multiplication , status: valid , samples : m1 : {} , decrypted result : {} , m1.size : {} , length of decrypted result : {}",
            m1,res,len_m1,len_res
        );
        let line = "test: addition , status : valid, samples : m1 : ".to_owned()
            + &m1.to_string()
            + ", decrypted result : "
            + &res.to_string()
            + ", m1.size : "
            + &len_m1.to_string()
            + ", length of decrypted result"
            + &len_res.to_string()
            + "\n";
        let mut squ_message = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open("src/tests/test_history/".to_owned() + filename + "_samples.txt")
            .unwrap();
        squ_message.write_all(line.as_bytes()).unwrap();
    } else {
        println!(
                "test: squaring , status: failure , samples : m1 : {}, decrypted result : {} , m1.size : {}, length of decrypted result : {} ",
                m1,res,len_m1,len_res
            );
        let line = "test: addition , status : valid, samples : m1 : ".to_owned()
            + &m1.to_string()
            + ", decrypted result : "
            + &res.to_string()
            + ", m1.size : "
            + &len_m1.to_string()
            + ", length of decrypted result"
            + &len_res.to_string()
            + "\n";
        let mut squ_message = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open("src/tests/test_history/".to_owned() + filename + "_samples.txt")
            .unwrap();
        squ_message.write_all(line.as_bytes()).unwrap();
    }
    assert_eq!((m1 * m1) as i64, res);
    Ok(())
}
#[test]
fn test_squ() {
    let filename= "squaring_rd" ;
    let mut rng = rand::thread_rng() ;
    let base: i64 = 2;
    let max_bitlen = 5;
    let max_range = base.pow(max_bitlen);
    /*for _i in 0..10 {
        let rand_neg = rng.gen_range(-max_range..0) ;
        test_squaring(rand_neg,filename).unwrap() ;
    }*/
    for _i in 0..10 {
        let rand_neg = rng.gen_range(0..max_range) ;
        test_squaring(rand_neg,filename).unwrap() ;
    }
    test_squaring(1,filename).unwrap() ;
    test_squaring(0,filename).unwrap() ;
    test_squaring(-1,filename).unwrap() ;
    test_squaring(2,filename).unwrap() ;
    test_squaring(-2,filename).unwrap() ;
}
#[test]
fn test_hc_squ() {
    let filename= "squaring_rd" ;
    test_squaring(0,filename).unwrap() ;
    test_squaring(16,filename).unwrap() ;
    test_squaring(27,filename).unwrap() ;
    test_squaring(1,filename).unwrap() ;
    test_squaring(500,filename).unwrap() ;
    test_squaring(814,filename).unwrap() ;
    test_squaring(814,filename).unwrap() ;
}

#[test]
// in this test we generate random values and multiply them (enc(m1)*enc(m2)) and call test_mul_m to test them

fn multiplication_rd() {
    let filename = "multiply_random";
    let mut rng = rand::thread_rng();
    let base: i64 = 2;
    let max_bitlen = 30;
    let max_range = base.pow(max_bitlen);
    for _i in 0..10 {
        let m1 = rng.gen_range(-max_range..max_range);
        let m2 = rng.gen_range(-max_range..max_range);
        test_mul_m(m1, m2, filename).unwrap();
    }
}

#[test]
// in this test we generate negative values and multiply them (enc(m1)*enc(m2)) and call test_mul_m to test them

fn multiplication_negative() {
    let filename = "multiply_negative";
    let mut rng = rand::thread_rng();
    let base: i64 = 2;
    let max_bitlen = 30;
    let max_range = base.pow(max_bitlen);
    for _i in 0..10 {
        let m1 = rng.gen_range(-max_range..0);
        let m2 = rng.gen_range(-max_range..0);
        test_mul_m(m1, m2, filename).unwrap();
    }
}

#[test]
// in this test we generate negative values and multiply them (enc(m1)*enc(m2)) and call test_mul_m to test them

fn multiplication_positive() {
    let filename = "multiply_negative";
    let mut rng = rand::thread_rng();
    let base: i64 = 2;
    let max_bitlen = 30;
    let max_range = base.pow(max_bitlen);
    for _i in 0..10 {
        let m1 = rng.gen_range(0..max_range);
        let m2 = rng.gen_range(0..max_range);
        test_mul_m(m1, m2, filename).unwrap();
    }
}

#[test]
// in this test we generate a negative integer and a positive one and multiply them (enc(m1)*enc(m2)) and call test_mul_m to test them

fn multiplication_positive_negative() {
    let filename = "multiply_negative";
    let mut rng = rand::thread_rng();
    let base: i64 = 2;
    let max_bitlen = 8;
    let max_range = base.pow(max_bitlen);
    for _i in 0..10 {
        let m1 = rng.gen_range(-max_range..0);
        let m2 = rng.gen_range(0..max_range);
        test_mul_m(m1, m2, filename).unwrap();
    }
}

#[test]
// in this test we multiply specific values we choose as input and call test_mul_m to test them

fn multiplication_m() {
    let filename = "multiply_message";
    let mut rng = rand::thread_rng();
    let base: i64 = 2;
    let max_range = base.pow(30);
    for _i in 0..10 {
        let m1 = rng.gen_range(-max_range..0);
        test_mul_m(m1, 0, filename).unwrap();
        test_mul_m(m1, 1, filename).unwrap();
        test_mul_m(m1, -1, filename).unwrap();
    }
}
