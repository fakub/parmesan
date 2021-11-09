use crate::tests::{self,*};
use crate::userovo::encryption;
use crate::arithmetics::ParmArithmetics;

#[test]
/// Addition & Subtraction of encrypted sub-samples only, aligned lengths.
fn t_add_sub_non_triv_aligned() {
    //DBG
    println!("Non-Triv Aligned ...");

    t_impl_add_with_mode(EncrVsTriv::ENCR, true);
}

#[test]
/// Addition & Subtraction of encrypted sub-samples only, different lengths.
fn t_add_sub_non_triv_difflen() {
    //DBG
    println!("Non-Triv Misaligned ...");

    t_impl_add_with_mode(EncrVsTriv::ENCR, false);
}

#[test]
/// Addition & Subtraction of trivial sub-samples only, aligned lengths.
fn t_add_sub_all_triv_aligned() {
    //DBG
    println!("All-Triv Aligned ...");

    t_impl_add_with_mode(EncrVsTriv::TRIV, true);
}

#[test]
/// Addition & Subtraction of trivial sub-samples only, different lengths.
fn t_add_sub_all_triv_difflen() {
    //DBG
    println!("All-Triv Misaligned ...");

    t_impl_add_with_mode(EncrVsTriv::TRIV, false);
}

#[test]
/// Addition & Subtraction of mixed sub-samples, aligned lengths.
fn t_add_sub_some_triv_aligned() {
    //DBG
    println!("Mixed Aligned ...");

    t_impl_add_with_mode(EncrVsTriv::ENCRTRIV, true);
}

#[test]
/// Addition & Subtraction of mixed sub-samples, different lengths.
fn t_add_sub_some_triv_difflen() {
    //DBG
    println!("Mixed Misaligned ...");

    t_impl_add_with_mode(EncrVsTriv::ENCRTRIV, false);
}


// -----------------------------------------------------------------------------
//  Test Implementations

/// Implementation for three variants of vector to be evaluated.
fn t_impl_add_with_mode(
    mode: EncrVsTriv,
    aligned: bool,
) {
    // for mis-aligned length generation
    let mut rng = rand::thread_rng();

    // set up bit-lengths
    let mut range: Vec<_> = (0..=TESTS_BITLEN_ADD).collect();
    range.extend(TESTS_EXTRA_BITLEN_ADD);

    for bl in range {
        // generate random vector(s)
        let bl1 = if aligned {bl} else {rng.gen_range(0..=bl)};
        let bl2 = if aligned {bl} else {rng.gen_range(0..=bl)};
        let m1_vec = gen_rand_vec(bl1);
        let m2_vec = gen_rand_vec(bl2);
        // convert to integer(s)
        let m1 = encryption::convert(&m1_vec).expect("convert failed.");
        let m2 = encryption::convert(&m2_vec).expect("convert failed.");

        //DBG
        println!("  m1 = {} ({}-bit: {:?}), m2 = {} ({}-bit: {:?})", m1, bl1, m1_vec, m2, bl2, m2_vec);

        // encrypt -> homomorphic eval -> decrypt
        let c1 = encrypt_with_mode(&m1_vec, mode);
        let c2 = encrypt_with_mode(&m2_vec, mode);

        let c_he_a = ParmArithmetics::add(&tests::PC, &c1, &c2);
        let c_he_s = ParmArithmetics::sub(&tests::PC, &c1, &c2);

        let m_he_a = PU.decrypt(&c_he_a).expect("ParmesanUserovo::decrypt failed.");
        let m_he_s = PU.decrypt(&c_he_s).expect("ParmesanUserovo::decrypt failed.");

        // plain eval
        let m_pl_a = ParmArithmetics::add(&tests::PC, &m1, &m2);
        let m_pl_s = ParmArithmetics::sub(&tests::PC, &m1, &m2);

        //DBG
        println!("  add = {} (exp. {})", m_he_a, m_pl_a);
        println!("  sub = {} (exp. {})", m_he_s, m_pl_s);

        // compare results
        assert_eq!(m_he_a, m_pl_a);
        assert_eq!(m_he_s, m_pl_s);
    }
}



// #############################################################################




//~ use std::error::Error;
//~ use std::fs::OpenOptions;
//~ use std::io::Write;

//~ use rand::Rng;

//~ use crate::params;
//~ use crate::ParmesanUserovo;
//~ use crate::ParmesanCloudovo;
//~ use crate::arithmetics::ParmArithmetics;

//~ // this function takes as input a message m and returns its size in bits
//~ fn message_size(m: i64) -> usize {
    //~ if m >= 0 {
        //~ let m_bin = format!("{:b}", m);
        //~ return m_bin.to_string().len();
    //~ } else {
        //~ let m_abs = m.abs();
        //~ let m_abs_bin = format!("{:b}", m_abs);
        //~ return m_abs_bin.to_string().len() + 1;
    //~ }
//~ }

//~ // In this function take two integers, m1 and m2, encrypt and add them, then we decrypt the result and compare it to m1+m2
//~ // we save the result of tests into specific files related to each test
//~ fn test_add_m(m1: i64, m2: i64, filename: &str) -> Result<(), Box<dyn Error>> {
    //~ // =================================
    //~ //  Initialization

    //~ // ---------------------------------
    //~ //  Global Scope
    //~ let par = &params::PARM90__PI_5__D_20__F; //     PARM90__PI_5__D_20__F      PARMXX__TRIVIAL

    //~ // ---------------------------------
    //~ //  Userovo Scope
    //~ let pu = ParmesanUserovo::new(par)?;
    //~ let pub_k = pu.export_pub_keys();
    //~ // ---------------------------------
    //~ //  Cloudovo Scope
    //~ let pc = ParmesanCloudovo::new(par, &pub_k);
    //~ // =================================
    //~ // check for add overflow
    //~ let mut add_check = None;
    //~ while add_check == None {
        //~ add_check = m1.checked_add(m2);
    //~ }
    //~ let m1_len = message_size(m1);
    //~ let m2_len = message_size(m2);
    //~ let nb_enc_bits = std::cmp::max(m1_len, m2_len);
    //~ println!(
            //~ "test: addition, status:- , samples : m1 : {} , m2 : {} , m1.size : {} , m2.size : {} , length of decrypted result : - ",
            //~ m1, m2, m1_len, m2_len
        //~ );
    //~ let enc_m1 = pu.encrypt(m1, nb_enc_bits)?;
    //~ let enc_m2 = pu.encrypt(m2, nb_enc_bits)?;
    //~ let enc_res = ParmArithmetics::add(&pc, &enc_m1, &enc_m2);
    //~ let res: i64 = pu.decrypt(&enc_res)?;
    //~ let res_len = message_size(res);
    //~ if m1 + m2 == res {
        //~ println!(
                //~ "test: addition , status: valid , samples : m1 : {} , m2: {} , decrypted_result : {} ,  m1.size : {} , m2.size : {} , length of decrypted result : {} ",
                //~ m1,m2,res,m1_len,m2_len,res_len
            //~ );
        //~ // if the test succeeds, we write the test result into a file "filename_samples.txt"
        //~ let line = "test: addition , status : valid, samples : m1 : ".to_owned()
            //~ + &m1.to_string()
            //~ + ", m2 : "
            //~ + &m2.to_string()
            //~ + ", decrypted result : "
            //~ + &res.to_string()
            //~ + ", m1.size : "
            //~ + &m1_len.to_string()
            //~ + ", m2.size : "
            //~ + &m2_len.to_string()
            //~ + ", length of decrypted result"
            //~ + &res_len.to_string()
            //~ + "\n";
        //~ let mut add_message = OpenOptions::new()
            //~ .read(true)
            //~ .append(true)
            //~ .create(true)
            //~ .open("src/tests/test_history/".to_owned() + filename + "_samples.txt")
            //~ .unwrap();
        //~ add_message.write_all(line.as_bytes()).unwrap();
    //~ } else {
        //~ println!(
                //~ "test: addition , failure: valid , samples : m1 : {} , m2: {} , decrypted_result {} , m1.size : {} , m2.size : {} , length of decrypted result : {} ",
                //~ m1,m2,res,m1_len,m2_len,res_len
            //~ );
        //~ // if the test fails, we write the test result into a file "filename_failures.txt"
        //~ let line = "test: addition , status : failure, samples : m1 : ".to_owned()
            //~ + &m1.to_string()
            //~ + ", m2 : "
            //~ + &m2.to_string()
            //~ + ", decrypted result : "
            //~ + &res.to_string()
            //~ + ", m1.size : "
            //~ + &m1_len.to_string()
            //~ + ", m2.size : "
            //~ + &m2_len.to_string()
            //~ + ", length of decrypted result"
            //~ + &res_len.to_string()
            //~ + "\n";
        //~ let mut add_message = OpenOptions::new()
            //~ .read(true)
            //~ .append(true)
            //~ .create(true)
            //~ .open("src/tests/test_history/".to_owned() + filename + "add_message_failures.txt")
            //~ .unwrap();
        //~ add_message.write_all(line.as_bytes()).unwrap();
    //~ }
    //~ assert_eq!(m1 + m2, res);
    //~ Ok(())
//~ }

//~ #[test]
//~ // in this test we add specific values we choose as input and call test_add_m to test them
//~ fn add_m() {
    //~ let filename = "add_message";
    //~ test_add_m(0, -8681422182905776600, filename).unwrap();
//~ }

//~ #[test]
//~ // in this test we generate random integers and add them to zero and call test_add_m to test them
//~ fn add_zero() {
    //~ let filename = "add_zero";
    //~ let base: i64 = 2;
    //~ let max_range = base.pow(62);
    //~ let mut rng = rand::thread_rng();
    //~ for _i in 0..10 {
        //~ let m1 = rng.gen_range(-max_range..max_range);
        //~ test_add_m(m1, 0, filename).unwrap();
    //~ }
//~ }

//~ #[test]
//~ // in this test we generate random values and add them to each other and call test_add_m to test them
//~ fn add_rd() {
    //~ let filename = "add_rand";
    //~ let base: i64 = 2;
    //~ let max_range = base.pow(62);
    //~ let mut rng = rand::thread_rng();
    //~ for _i in 0..10 {
        //~ let m1 = rng.gen_range(-max_range..max_range);
        //~ let m2 = rng.gen_range(-max_range..max_range);
        //~ test_add_m(m1, m2, filename).unwrap();
    //~ }
//~ }

//~ #[test]
//~ // in this test we generate random values and add them to their opposite and call test_add_m to test them
//~ fn add_opposite() {
    //~ let filename = "add_opposite";
    //~ let base: i64 = 2;
    //~ let max_range = base.pow(62);
    //~ let mut rng = rand::thread_rng();
    //~ for _i in 0..10 {
        //~ let m1 = rng.gen_range(-max_range..max_range);
        //~ let m2 = -m1;
        //~ test_add_m(m1, m2, filename).unwrap();
    //~ }
//~ }


//~ // -----------------------------------------------------------------------------
//~ //  Subtraction

//~ #[test]
//~ // this test generates two random integers m1 and m2, encrypt m1 and m2, substract m1 from m2 them and then compare the result to the expected result on plaintext integers ; m1-m2.
//~ fn test_sub_opposite() -> Result<(), Box<dyn Error>> {
    //~ // =================================
    //~ //  Initialization

    //~ // ---------------------------------
    //~ //  Global Scope
    //~ let par = &params::PARM90__PI_5__D_20__F; //     PARM90__PI_5__D_20__F      PARMXX__TRIVIAL

    //~ // ---------------------------------
    //~ //  Userovo Scope
    //~ let pu = ParmesanUserovo::new(par)?;
    //~ let pub_k = pu.export_pub_keys();
    //~ // ---------------------------------
    //~ //  Cloudovo Scope
    //~ let pc = ParmesanCloudovo::new(par, &pub_k);
    //~ // =================================

    //~ // In order to avoid addition overflows, our random generator has to generate numbers between [-2^62,2^62]

    //~ let base: i64 = 2;
    //~ let max_range = base.pow(62);

    //~ // generate 10 random samples for tests
    //~ let mut rng = rand::thread_rng();
    //~ for _i in 0..10 {
        //~ let m1: i64 = rng.gen_range(-max_range..max_range);
        //~ let m2: i64 = -m1;
        //~ let m1_len = message_size(m1);
        //~ let m2_len = message_size(m2);
        //~ let nb_enc_bits = std::cmp::max(m1_len, m2_len);
        //~ println!(
            //~ "test: subtraction, status:- , samples : m1 : {} , m2 : {} , decrypted result : -, m1.size : {} , m2.size : {} , length of decrypted result : - ",
            //~ m1, m2, m1_len, m2_len
        //~ );
        //~ let enc_m1 = pu.encrypt(m1, nb_enc_bits)?;
        //~ let enc_m2 = pu.encrypt(m2, nb_enc_bits)?;
        //~ let enc_res = ParmArithmetics::sub(&pc, &enc_m1, &enc_m2);
        //~ let res: i64 = pu.decrypt(&enc_res)?;
        //~ let res_len = message_size(res);
        //~ if m1 - m2 == res {
            //~ println!(
                //~ "test: subtraction , status: valid , samples : m1 : {} , m2: {} , decrypted result : {} , m1.size : {} , m2.size : {} , length of decrypted result : {} ",
                //~ m1,m2,res,m1_len,m2_len,res_len
            //~ );
            //~ let line = "test: subtraction , status : valid, samples : m1 : ".to_owned()
                //~ + &m1.to_string()
                //~ + ", m2 : "
                //~ + &m2.to_string()
                //~ + ", decrypted result : "
                //~ + &res.to_string()
                //~ + ", m1.size : "
                //~ + &m1_len.to_string()
                //~ + ", m2.size : "
                //~ + &m2_len.to_string()
                //~ + "length of decrypted result : "
                //~ + &res_len.to_string()
                //~ + "\n";
            //~ let mut sub_opposite = OpenOptions::new()
                //~ .read(true)
                //~ .append(true)
                //~ .create(true)
                //~ .open("src/tests/test_history/sub_opposite_samples.txt")
                //~ .unwrap();
            //~ sub_opposite.write_all(line.as_bytes()).unwrap();
        //~ } else {
            //~ println!(
                //~ "test: subtraction , status : valid , samples : m1 : {} , m2: {} , decrypted result : {}, m1.size : {} , m2.size : {} , length of decrypted result : {} ",
                //~ m1,m2,res,m1_len,m2_len,res_len
            //~ );
            //~ let line = "test: subtraction , status : failure , samples : m1 : ".to_owned()
                //~ + &m1.to_string()
                //~ + ", m2 : "
                //~ + &m2.to_string()
                //~ + ", decrypted result : "
                //~ + &res.to_string()
                //~ + ", m1.size : "
                //~ + &m1_len.to_string()
                //~ + ", m2.size : "
                //~ + &m2_len.to_string()
                //~ + "length of decrypted result : "
                //~ + &res_len.to_string()
                //~ + "\n";
            //~ let mut sub_opposite = OpenOptions::new()
                //~ .read(true)
                //~ .append(true)
                //~ .create(true)
                //~ .open("src/tests/test_history/sub_opposite_failures.txt")
                //~ .unwrap();
            //~ sub_opposite.write_all(line.as_bytes()).unwrap();
        //~ }
        //~ assert_eq!(m1 - m2, res);
    //~ }
    //~ Ok(())
//~ }

//~ #[test]
//~ fn test_sub_rd() -> Result<(), Box<dyn Error>> {
    //~ // =================================
    //~ //  Initialization

    //~ // ---------------------------------
    //~ //  Global Scope
    //~ let par = &params::PARM90__PI_5__D_20__F; //     PARM90__PI_5__D_20__F      PARMXX__TRIVIAL

    //~ // ---------------------------------
    //~ //  Userovo Scope
    //~ let pu = ParmesanUserovo::new(par)?;
    //~ let pub_k = pu.export_pub_keys();
    //~ // ---------------------------------
    //~ //  Cloudovo Scope
    //~ let pc = ParmesanCloudovo::new(par, &pub_k);
    //~ // =================================

    //~ // In order to avoid addition overflows, our random generator has to generate numbers between [-2^62,2^62]

    //~ let base: i64 = 2;
    //~ let max_range = base.pow(62);

    //~ // generate 10 random samples for tests
    //~ let mut rng = rand::thread_rng();
    //~ for _i in 0..10 {
        //~ let m1 = rng.gen_range(-max_range..max_range);
        //~ let m2 = rng.gen_range(-max_range..max_range);
        //~ let m1_len = message_size(m1);
        //~ let m2_len = message_size(m2);
        //~ let nb_enc_bits = std::cmp::max(m1_len, m2_len);
        //~ println!(
            //~ "test: subtraction, status:- , samples : m1 : {} , m2 : {} , decrypted result : -, m1.size : {} , m2.size : {} , length of decrypted result : - ",
            //~ m1, m2, m1_len, m2_len
        //~ );
        //~ let enc_m1 = pu.encrypt(m1, nb_enc_bits)?;
        //~ let enc_m2 = pu.encrypt(m2, nb_enc_bits)?;
        //~ let enc_res = ParmArithmetics::sub(&pc, &enc_m1, &enc_m2);
        //~ let res: i64 = pu.decrypt(&enc_res)?;
        //~ let res_len = message_size(res);
        //~ if m1 - m2 == res {
            //~ println!(
                //~ "test: subtraction , status: valid , samples : m1 : {} , m2: {} , decrypted result : {} , m1.size : {} , m2.size : {} , length of decrypted result : {} ",
                //~ m1,m2,res,m1_len,m2_len,res_len
            //~ );
            //~ let line = "test: subtraction , status : valid, samples : m1 : ".to_owned()
                //~ + &m1.to_string()
                //~ + ", m2 : "
                //~ + &m2.to_string()
                //~ + ", decrypted result : "
                //~ + &res.to_string()
                //~ + ", m1.size : "
                //~ + &m1_len.to_string()
                //~ + ", m2.size : "
                //~ + &m2_len.to_string()
                //~ + "length of decrypted result : "
                //~ + &res_len.to_string()
                //~ + "\n";
            //~ let mut add_opposite = OpenOptions::new()
                //~ .read(true)
                //~ .append(true)
                //~ .create(true)
                //~ .open("src/tests/test_history/sub_rd_samples.txt")
                //~ .unwrap();
            //~ add_opposite.write_all(line.as_bytes()).unwrap();
        //~ } else {
            //~ println!(
                //~ "test: subtraction , status : valid , samples : m1 : {} , m2: {} , decrypted result : {}, m1.size : {} , m2.size : {} , length of decrypted result : {} ",
                //~ m1,m2,res,m1_len,m2_len,res_len
            //~ );
            //~ let line = "test: subtraction , status : failure , samples : m1 : ".to_owned()
                //~ + &m1.to_string()
                //~ + ", m2 : "
                //~ + &m2.to_string()
                //~ + ", decrypted result : "
                //~ + &res.to_string()
                //~ + ", m1.size : "
                //~ + &m1_len.to_string()
                //~ + ", m2.size : "
                //~ + &m2_len.to_string()
                //~ + "length of decrypted result : "
                //~ + &res_len.to_string()
                //~ + "\n";
            //~ let mut add_opposite = OpenOptions::new()
                //~ .read(true)
                //~ .append(true)
                //~ .create(true)
                //~ .open("src/tests/test_history/sub_rd_failures.txt")
                //~ .unwrap();
            //~ add_opposite.write_all(line.as_bytes()).unwrap();
        //~ }
        //~ assert_eq!(m1 - m2, res);
    //~ }
    //~ Ok(())
//~ }

//~ #[test]
//~ fn test_sub_zero() -> Result<(), Box<dyn Error>> {
    //~ // =================================
    //~ //  Initialization

    //~ // ---------------------------------
    //~ //  Global Scope
    //~ let par = &params::PARM90__PI_5__D_20__F; //     PARM90__PI_5__D_20__F      PARMXX__TRIVIAL

    //~ // ---------------------------------
    //~ //  Userovo Scope
    //~ let pu = ParmesanUserovo::new(par)?;
    //~ let pub_k = pu.export_pub_keys();
    //~ // ---------------------------------
    //~ //  Cloudovo Scope
    //~ let pc = ParmesanCloudovo::new(par, &pub_k);
    //~ // =================================

    //~ // In order to avoid addition overflows, our random generator has to generate numbers between [-2^62,2^62]

    //~ let base: i64 = 2;
    //~ let max_range = base.pow(62);

    //~ // generate 10 random samples for tests
    //~ let mut rng = rand::thread_rng();
    //~ for _i in 0..10 {
        //~ let m1 = rng.gen_range(-max_range..max_range);
        //~ let m2 = 0;
        //~ let m1_len = message_size(m1);
        //~ let m2_len = message_size(m2);
        //~ let nb_enc_bits = std::cmp::max(m1_len, m2_len);
        //~ println!(
            //~ "test: subtraction, status:- , samples : m1 : {} , m2 : {} , decrypted result : -, m1.size : {} , m2.size : {} , length of decrypted result : - ",
            //~ m1, m2, m1_len, m2_len
        //~ );
        //~ let enc_m1 = pu.encrypt(m1, nb_enc_bits)?;
        //~ let enc_m2 = pu.encrypt(m2, nb_enc_bits)?;
        //~ let enc_res = ParmArithmetics::sub(&pc, &enc_m1, &enc_m2);
        //~ let res: i64 = pu.decrypt(&enc_res)?;
        //~ let res_len = message_size(res);
        //~ if m1 - m2 == res {
            //~ println!(
                //~ "test: subtraction , status: valid , samples : m1 : {} , m2: {} , decrypted result : {} , m1.size : {} , m2.size : {} , length of decrypted result : {} ",
                //~ m1,m2,res,m1_len,m2_len,res_len
            //~ );
            //~ let line = "test: subtraction , status : valid, samples : m1 : ".to_owned()
                //~ + &m1.to_string()
                //~ + ", m2 : "
                //~ + &m2.to_string()
                //~ + ", decrypted result : "
                //~ + &res.to_string()
                //~ + ", m1.size : "
                //~ + &m1_len.to_string()
                //~ + ", m2.size : "
                //~ + &m2_len.to_string()
                //~ + "length of decrypted result : "
                //~ + &res_len.to_string()
                //~ + "\n";
            //~ let mut add_opposite = OpenOptions::new()
                //~ .read(true)
                //~ .append(true)
                //~ .create(true)
                //~ .open("src/tests/test_history/sub_zero_samples.txt")
                //~ .unwrap();
            //~ add_opposite.write_all(line.as_bytes()).unwrap();
        //~ } else {
            //~ println!(
                //~ "test: subtraction , status : valid , samples : m1 : {} , m2: {} , decrypted result : {}, m1.size : {} , m2.size : {} , length of decrypted result : {} ",
                //~ m1,m2,res,m1_len,m2_len,res_len
            //~ );
            //~ let line = "test: subtraction , status : failure , samples : m1 : ".to_owned()
                //~ + &m1.to_string()
                //~ + ", m2 : "
                //~ + &m2.to_string()
                //~ + ", decrypted result : "
                //~ + &res.to_string()
                //~ + ", m1.size : "
                //~ + &m1_len.to_string()
                //~ + ", m2.size : "
                //~ + &m2_len.to_string()
                //~ + "length of decrypted result : "
                //~ + &res_len.to_string()
                //~ + "\n";
            //~ let mut add_opposite = OpenOptions::new()
                //~ .read(true)
                //~ .append(true)
                //~ .create(true)
                //~ .open("src/tests/test_history/sub_zero_failures.txt")
                //~ .unwrap();
            //~ add_opposite.write_all(line.as_bytes()).unwrap();
        //~ }
        //~ assert_eq!(m1 - m2, res);
    //~ }
    //~ Ok(())
//~ }

//~ fn test_sub_msge(m1: i64, m2: i64) -> Result<(), Box<dyn Error>> {
    //~ // =================================
    //~ //  Initialization

    //~ // ---------------------------------
    //~ //  Global Scope
    //~ let par = &params::PARM90__PI_5__D_20__F; //     PARM90__PI_5__D_20__F      PARMXX__TRIVIAL

    //~ // ---------------------------------
    //~ //  Userovo Scope
    //~ let pu = ParmesanUserovo::new(par)?;
    //~ let pub_k = pu.export_pub_keys();
    //~ // ---------------------------------
    //~ //  Cloudovo Scope
    //~ let pc = ParmesanCloudovo::new(par, &pub_k);
    //~ // =================================
    //~ let m1_len = message_size(m1);
    //~ let m2_len = message_size(m2);
    //~ let nb_enc_bits = std::cmp::max(m1_len, m2_len);
    //~ println!(
        //~ "test: subtraction , status: -, samples : m1 : {} , m2: {} , decrypted result : - , m1.size : {} , m2.size : {} , length of decrypted result : - ",
        //~ m1,m2,m1_len,m2_len
    //~ );
    //~ let enc_m1 = pu.encrypt(m1, nb_enc_bits)?;
    //~ let enc_m2 = pu.encrypt(m2, nb_enc_bits)?;
    //~ let enc_res = ParmArithmetics::add(&pc, &enc_m1, &enc_m2);
    //~ let res: i64 = pu.decrypt(&enc_res)?;
    //~ let res_len = message_size(res);
    //~ if m1 - m2 == res {
        //~ println!(
            //~ "test: subtraction , status: valid , samples : m1 : {} , m2: {} , decrypted result : {} , m1.size : {} , m2.size : {} , length of decrypted result : {} ",
            //~ m1,m2,res,m1_len,m2_len,res_len
        //~ );
        //~ let line = "test: subtraction , status : valid, samples : m1 : ".to_owned()
            //~ + &m1.to_string()
            //~ + ", m2 : "
            //~ + &m2.to_string()
            //~ + ", decrypted result : "
            //~ + &res.to_string()
            //~ + ", m1.size : "
            //~ + &m1_len.to_string()
            //~ + ", m2.size : "
            //~ + &m2_len.to_string()
            //~ + ", length of decrypted result"
            //~ + &res_len.to_string()
            //~ + "\n";
        //~ let mut add_message = OpenOptions::new()
            //~ .read(true)
            //~ .append(true)
            //~ .create(true)
            //~ .open("src/tests/test_history/sub_message_samples.txt")
            //~ .unwrap();
        //~ add_message.write_all(line.as_bytes()).unwrap();
    //~ } else {
        //~ println!(
            //~ "test: subtraction , status: failure , samples : m1 : {} , m2: {} , decrypted result : {} , m1.size : {} , m2.size : {} , length of decrypted result : {} ",
            //~ m1,m2,res,m1_len,m2_len,res_len
        //~ );
        //~ let line = "test: subtraction , status : failure, samples : m1 : ".to_owned()
            //~ + &m1.to_string()
            //~ + ", m2 : "
            //~ + &m2.to_string()
            //~ + ", decrypted result : "
            //~ + &res.to_string()
            //~ + ", m1.size : "
            //~ + &m1_len.to_string()
            //~ + ", m2.size : "
            //~ + &m2_len.to_string()
            //~ + ", length of decrypted result"
            //~ + &res_len.to_string()
            //~ + "\n";
        //~ let mut add_message = OpenOptions::new()
            //~ .read(true)
            //~ .append(true)
            //~ .create(true)
            //~ .open("src/tests/test_history/sub_message_failures.txt")
            //~ .unwrap();
        //~ add_message.write_all(line.as_bytes()).unwrap();
    //~ }
    //~ assert_eq!(m1 - m2, res);
    //~ Ok(())
//~ }

//~ #[test]
//~ fn test_custom_sub() {
    //~ let mut rng = rand::thread_rng();
    //~ let base: i64 = 2;
    //~ let max_range = base.pow(62);
    //~ let m1 = rng.gen_range(-max_range..max_range);
    //~ let m2 = rng.gen_range(-max_range..max_range);
    //~ test_sub_msge(m1, m2).unwrap();
    //~ test_sub_msge(m2, m1).unwrap();
//~ }
