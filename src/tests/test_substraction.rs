use super::*;
#[cfg(test)]
use rand::Rng;
use std::fs::OpenOptions;
use std::io::Write;
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

#[test]
// this test generates two random integers m1 and m2, encrypt m1 and m2, substract m1 from m2 them and then compare the result to the expected result on plaintext integers ; m1-m2.
fn test_sub_opposite() -> Result<(), Box<dyn Error>> {
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

    // In order to avoid addition overflows, our random generator has to generate numbers between [-2^62,2^62]

    let base: i64 = 2;
    let max_range = base.pow(62);

    // generate 10 random samples for tests
    let mut rng = rand::thread_rng();
    for _i in 0..10 {
        let m1: i64 = rng.gen_range(-max_range..max_range);
        let m2: i64 = -m1;
        let m1_len = message_size(m1);
        let m2_len = message_size(m2);
        let nb_enc_bits = std::cmp::max(m1_len, m2_len);
        println!(
            "test: substraction, status:- , samples : m1 : {} , m2 : {} , decrypted result : -, m1.size : {} , m2.size : {} , length of decrypted result : - ",
            m1, m2, m1_len, m2_len
        );
        let enc_m1 = pu.encrypt(m1, nb_enc_bits)?;
        let enc_m2 = pu.encrypt(m2, nb_enc_bits)?;
        let enc_res = ParmArithmetics::sub(&pc, &enc_m1, &enc_m2);
        let res: i64 = pu.decrypt(&enc_res)?;
        let res_len = message_size(res);
        if m1 - m2 == res {
            println!(
                "test: substraction , status: valid , samples : m1 : {} , m2: {} , decrypted result : {} , m1.size : {} , m2.size : {} , length of decrypted result : {} ",
                m1,m2,res,m1_len,m2_len,res_len
            );
            let line = "test: substraction , status : valid, samples : m1 : ".to_owned()
                + &m1.to_string()
                + ", m2 : "
                + &m2.to_string()
                + ", decrypted result : "
                + &res.to_string()
                + ", m1.size : "
                + &m1_len.to_string()
                + ", m2.size : "
                + &m2_len.to_string()
                + "length of decrypted result : "
                + &res_len.to_string()
                + "\n";
            let mut sub_opposite = OpenOptions::new()
                .read(true)
                .append(true)
                .create(true)
                .open("src/tests/test_history/sub_opposite_samples.txt")
                .unwrap();
            sub_opposite.write_all(line.as_bytes()).unwrap();
        } else {
            println!(
                "test: substraction , status : valid , samples : m1 : {} , m2: {} , decrypted result : {}, m1.size : {} , m2.size : {} , length of decrypted result : {} ",
                m1,m2,res,m1_len,m2_len,res_len
            );
            let line = "test: substraction , status : failure , samples : m1 : ".to_owned()
                + &m1.to_string()
                + ", m2 : "
                + &m2.to_string()
                + ", decrypted result : "
                + &res.to_string()
                + ", m1.size : "
                + &m1_len.to_string()
                + ", m2.size : "
                + &m2_len.to_string()
                + "length of decrypted result : "
                + &res_len.to_string()
                + "\n";
            let mut sub_opposite = OpenOptions::new()
                .read(true)
                .append(true)
                .create(true)
                .open("src/tests/test_history/sub_opposite_failures.txt")
                .unwrap();
            sub_opposite.write_all(line.as_bytes()).unwrap();
        }
        assert_eq!(m1 - m2, res);
    }
    Ok(())
}
#[test]
fn test_sub_rd() -> Result<(), Box<dyn Error>> {
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

    // In order to avoid addition overflows, our random generator has to generate numbers between [-2^62,2^62]

    let base: i64 = 2;
    let max_range = base.pow(62);

    // generate 10 random samples for tests
    let mut rng = rand::thread_rng();
    for _i in 0..10 {
        let m1 = rng.gen_range(-max_range..max_range);
        let m2 = rng.gen_range(-max_range..max_range);
        let m1_len = message_size(m1);
        let m2_len = message_size(m2);
        let nb_enc_bits = std::cmp::max(m1_len, m2_len);
        println!(
            "test: substraction, status:- , samples : m1 : {} , m2 : {} , decrypted result : -, m1.size : {} , m2.size : {} , length of decrypted result : - ",
            m1, m2, m1_len, m2_len
        );
        let enc_m1 = pu.encrypt(m1, nb_enc_bits)?;
        let enc_m2 = pu.encrypt(m2, nb_enc_bits)?;
        let enc_res = ParmArithmetics::sub(&pc, &enc_m1, &enc_m2);
        let res: i64 = pu.decrypt(&enc_res)?;
        let res_len = message_size(res);
        if m1 - m2 == res {
            println!(
                "test: substraction , status: valid , samples : m1 : {} , m2: {} , decrypted result : {} , m1.size : {} , m2.size : {} , length of decrypted result : {} ",
                m1,m2,res,m1_len,m2_len,res_len
            );
            let line = "test: substraction , status : valid, samples : m1 : ".to_owned()
                + &m1.to_string()
                + ", m2 : "
                + &m2.to_string()
                + ", decrypted result : "
                + &res.to_string()
                + ", m1.size : "
                + &m1_len.to_string()
                + ", m2.size : "
                + &m2_len.to_string()
                + "length of decrypted result : "
                + &res_len.to_string()
                + "\n";
            let mut add_opposite = OpenOptions::new()
                .read(true)
                .append(true)
                .create(true)
                .open("src/tests/test_history/sub_rd_samples.txt")
                .unwrap();
            add_opposite.write_all(line.as_bytes()).unwrap();
        } else {
            println!(
                "test: substraction , status : valid , samples : m1 : {} , m2: {} , decrypted result : {}, m1.size : {} , m2.size : {} , length of decrypted result : {} ",
                m1,m2,res,m1_len,m2_len,res_len
            );
            let line = "test: substraction , status : failure , samples : m1 : ".to_owned()
                + &m1.to_string()
                + ", m2 : "
                + &m2.to_string()
                + ", decrypted result : "
                + &res.to_string()
                + ", m1.size : "
                + &m1_len.to_string()
                + ", m2.size : "
                + &m2_len.to_string()
                + "length of decrypted result : "
                + &res_len.to_string()
                + "\n";
            let mut add_opposite = OpenOptions::new()
                .read(true)
                .append(true)
                .create(true)
                .open("src/tests/test_history/sub_rd_failures.txt")
                .unwrap();
            add_opposite.write_all(line.as_bytes()).unwrap();
        }
        assert_eq!(m1 - m2, res);
    }
    Ok(())
}
#[test]
fn test_sub_zero() -> Result<(), Box<dyn Error>> {
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

    // In order to avoid addition overflows, our random generator has to generate numbers between [-2^62,2^62]

    let base: i64 = 2;
    let max_range = base.pow(62);

    // generate 10 random samples for tests
    let mut rng = rand::thread_rng();
    for _i in 0..10 {
        let m1 = rng.gen_range(-max_range..max_range);
        let m2 = 0;
        let m1_len = message_size(m1);
        let m2_len = message_size(m2);
        let nb_enc_bits = std::cmp::max(m1_len, m2_len);
        println!(
            "test: substraction, status:- , samples : m1 : {} , m2 : {} , decrypted result : -, m1.size : {} , m2.size : {} , length of decrypted result : - ",
            m1, m2, m1_len, m2_len
        );
        let enc_m1 = pu.encrypt(m1, nb_enc_bits)?;
        let enc_m2 = pu.encrypt(m2, nb_enc_bits)?;
        let enc_res = ParmArithmetics::sub(&pc, &enc_m1, &enc_m2);
        let res: i64 = pu.decrypt(&enc_res)?;
        let res_len = message_size(res);
        if m1 - m2 == res {
            println!(
                "test: substraction , status: valid , samples : m1 : {} , m2: {} , decrypted result : {} , m1.size : {} , m2.size : {} , length of decrypted result : {} ",
                m1,m2,res,m1_len,m2_len,res_len
            );
            let line = "test: substraction , status : valid, samples : m1 : ".to_owned()
                + &m1.to_string()
                + ", m2 : "
                + &m2.to_string()
                + ", decrypted result : "
                + &res.to_string()
                + ", m1.size : "
                + &m1_len.to_string()
                + ", m2.size : "
                + &m2_len.to_string()
                + "length of decrypted result : "
                + &res_len.to_string()
                + "\n";
            let mut add_opposite = OpenOptions::new()
                .read(true)
                .append(true)
                .create(true)
                .open("src/tests/test_history/sub_zero_samples.txt")
                .unwrap();
            add_opposite.write_all(line.as_bytes()).unwrap();
        } else {
            println!(
                "test: substraction , status : valid , samples : m1 : {} , m2: {} , decrypted result : {}, m1.size : {} , m2.size : {} , length of decrypted result : {} ",
                m1,m2,res,m1_len,m2_len,res_len
            );
            let line = "test: substraction , status : failure , samples : m1 : ".to_owned()
                + &m1.to_string()
                + ", m2 : "
                + &m2.to_string()
                + ", decrypted result : "
                + &res.to_string()
                + ", m1.size : "
                + &m1_len.to_string()
                + ", m2.size : "
                + &m2_len.to_string()
                + "length of decrypted result : "
                + &res_len.to_string()
                + "\n";
            let mut add_opposite = OpenOptions::new()
                .read(true)
                .append(true)
                .create(true)
                .open("src/tests/test_history/sub_zero_failures.txt")
                .unwrap();
            add_opposite.write_all(line.as_bytes()).unwrap();
        }
        assert_eq!(m1 - m2, res);
    }
    Ok(())
}
fn test_sub_msge(m1: i64, m2: i64) -> Result<(), Box<dyn Error>> {
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
    let m1_len = message_size(m1);
    let m2_len = message_size(m2);
    let nb_enc_bits = std::cmp::max(m1_len, m2_len);
    println!(
        "test: substraction , status: -, samples : m1 : {} , m2: {} , decrypted result : - , m1.size : {} , m2.size : {} , length of decrypted result : - ",
        m1,m2,m1_len,m2_len
    );
    let enc_m1 = pu.encrypt(m1, nb_enc_bits)?;
    let enc_m2 = pu.encrypt(m2, nb_enc_bits)?;
    let enc_res = ParmArithmetics::add(&pc, &enc_m1, &enc_m2);
    let res: i64 = pu.decrypt(&enc_res)?;
    let res_len = message_size(res);
    if m1 - m2 == res {
        println!(
            "test: substraction , status: valid , samples : m1 : {} , m2: {} , decrypted result : {} , m1.size : {} , m2.size : {} , length of decrypted result : {} ",
            m1,m2,res,m1_len,m2_len,res_len
        );
        let line = "test: substraction , status : valid, samples : m1 : ".to_owned()
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
            .open("src/tests/test_history/sub_message_samples.txt")
            .unwrap();
        add_message.write_all(line.as_bytes()).unwrap();
    } else {
        println!(
            "test: substraction , status: failure , samples : m1 : {} , m2: {} , decrypted result : {} , m1.size : {} , m2.size : {} , length of decrypted result : {} ",
            m1,m2,res,m1_len,m2_len,res_len
        );
        let line = "test: substraction , status : failure, samples : m1 : ".to_owned()
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
            .open("src/tests/test_history/sub_message_failures.txt")
            .unwrap();
        add_message.write_all(line.as_bytes()).unwrap();
    }
    assert_eq!(m1 - m2, res);
    Ok(())
}
#[test]
fn test_custom_sub() {
    let mut rng = rand::thread_rng();
    let base: i64 = 2;
    let max_range = base.pow(62);
    let m1 = rng.gen_range(-max_range..max_range);
    let m2 = rng.gen_range(-max_range..max_range);
    test_sub_msge(m1, m2).unwrap();
    test_sub_msge(m2, m1).unwrap();
}
