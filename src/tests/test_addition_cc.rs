use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;

use rand::Rng;
use concrete::LWE;

use crate::params;
use crate::ParmesanUserovo;
use crate::ParmesanCloudovo;
use crate::arithmetics::ParmArithmetics;
use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};

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
fn reverse_vec(input_plaintext: Vec<u32>) -> Vec<u32> {
    let mut input_plaintext_x: Vec<u32> = vec![];
    for _i in 0..input_plaintext.len() {
        input_plaintext_x.push(0);
    }
    for i in 0..input_plaintext.len() {
        input_plaintext_x[input_plaintext.len() - i - 1] = input_plaintext[i];
    }
    return input_plaintext_x;
}
fn test_encrypt_decrypt_cc(m: i64) -> Result<(), Box<dyn Error>> {
    // =================================
    //  Initialization

    // ---------------------------------
    //  Global Scope
    let par = &params::PARM90__PI_5__D_20__F; //     PARM90__PI_5__D_20__F      PARMXX__TRIVIAL

    // ---------------------------------
    //  Userovo Scope
    let pu = ParmesanUserovo::new(par)?;

    // we encrypt m with a number of encrypted bits = message_size than decrypt to compare the result to the input value

    let nb_enc_bits = message_size(m);
    let enc_m = pu.encrypt(m, nb_enc_bits)?;

    let res: i64 = pu.decrypt(&enc_m)?;
    let res_len = message_size(res);
    if m == res {
        println!("enc_result {:?}", enc_m);
    } else {
        println!(
                "test status: failure , sample : {} , decrypted result : {} , number of encrypted bits (input size) {}, decrypted result: length{} ",
                m, res, nb_enc_bits, res_len
            );
    }
    assert_eq!(res, m);
    Ok(())
}

#[test]
fn encryption_cc() {
    test_encrypt_decrypt_cc(16).unwrap();
}

fn gen_ct_rtriv_zero(
    pu: &ParmesanUserovo,
    x_length: i32,
    x_wlen: i32,
    r_triv_len: i32,
) -> Result<(Vec<u32>, ParmCiphertext), Box<dyn Error>> {
    // =================================
    // gen_ct_triv_zero returns a ciphertext with the following structure
    // 0|0|1| enc_bits  |rtriv_zero |
    // 0|0|1|-|-|-|-|-|-|0|0|0|0|0|0|
    let mut nx = ParmCiphertext::empty();
    let pub_k = pu.export_pub_keys();
    let mut rng = rand::thread_rng();
    let mut vec = vec![];
    let mut input_plaintext: Vec<u32> = vec![];
    let mut rand_bit;
    for i in 0..x_length {
        if i < r_triv_len {
            input_plaintext.push(0);
            let triv_0 = LWE::encrypt_uint_triv(0, &pub_k.encoder)?;
            nx.push(triv_0);
        }
        if i >= r_triv_len && i < x_wlen {
            rand_bit = rng.gen_range(0..2);
            input_plaintext.push(rand_bit);
            vec.push(rand_bit as i32);
        }
        if i == x_wlen - 1 {
            let mut enc_x = pu.encrypt_vec(&vec)?;
            nx.append(&mut enc_x);
        }
        if i >= x_wlen {
            input_plaintext.push(0);
            let triv_0 = LWE::encrypt_uint_triv(0, &pub_k.encoder)?;
            nx.push(triv_0);
        }
    }
    Ok((reverse_vec(input_plaintext), nx))
}

fn gen_ct_rtriv_custom(
    pu: &ParmesanUserovo,
    y_length: i32,
    y_wlen: i32,
    y_triv_len: i32,
) -> Result<(Vec<u32>, ParmCiphertext), Box<dyn Error>> {
    //==================================
    // gen ct_triv_custom returns a ciphertext with the following structure
    // |0|0|.. -|-|-|-|1|0|0
    //==================================
    let mut ny = ParmCiphertext::empty();
    let pub_k = pu.export_pub_keys();
    let mut rng = rand::thread_rng();
    let mut input_plaintext: Vec<u32> = vec![];
    for _j in 0..y_triv_len {
        let rand_bit = rng.gen_range(0..2);
        input_plaintext.push(rand_bit);
        let triv_rand_bit = LWE::encrypt_uint_triv(rand_bit, &pub_k.encoder)?;
        ny.push(triv_rand_bit);
    }
    let mut vec = vec![];
    for j in y_triv_len..y_wlen {
        let rand_bit = rng.gen_range(0..2);
        input_plaintext.push(rand_bit);
        vec.push(rand_bit as i32);
        if j == y_wlen - 1 {
            let mut enc_y = pu.encrypt_vec(&vec)?;
            ny.append(&mut enc_y);
        }
    }
    for _j in y_wlen..y_length {
        input_plaintext.push(0);
        let triv_rand_bit = LWE::encrypt_uint_triv(0, &pub_k.encoder)?;
        ny.push(triv_rand_bit);
    }
    Ok((reverse_vec(input_plaintext), ny))
}

fn gen_ct_triv(
    pu: &ParmesanUserovo,
    triv_ct_len: i32,
) -> Result<(Vec<u32>, ParmCiphertext), Box<dyn Error>> {
    //==================================
    // gen ct_triv returns a ciphertext with the following structure
    // |0|0|.. |0|1|1|0|1
    //==================================
    let mut nx_triv = ParmCiphertext::empty();
    let pub_k = pu.export_pub_keys();
    let mut rng = rand::thread_rng();
    let mut input_plaintext: Vec<u32> = vec![];
    for _j in 0..triv_ct_len {
        let rand_bit = rng.gen_range(0..2);
        input_plaintext.push(rand_bit);
        let triv_rand_bit = LWE::encrypt_uint_triv(rand_bit, &pub_k.encoder)?;
        nx_triv.push(triv_rand_bit);
    }
    Ok((reverse_vec(input_plaintext), nx_triv))
}

#[test]
fn add_trivial01 (
) -> Result< (), Box<dyn Error>> {
    // Initialization
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
    let mut trivial_1 = ParmCiphertext::empty() ;
    let pub_k = pu.export_pub_keys() ;
    trivial_1.push(LWE::encrypt_uint_triv(1,&pub_k.encoder)?) ;
    let mut trivial_0 = ParmCiphertext::empty() ;
    trivial_0.push(LWE::encrypt_uint_triv(0,&pub_k.encoder)?) ;
    let enc_add_res = ParmArithmetics::add(&pc,&trivial_1,&trivial_0) ;
    let dec_add_res = pu.decrypt(&enc_add_res)? ;
    assert_eq!(1, dec_add_res) ;
    Ok(())
}

#[test]
fn add_0_to_enc (
) -> Result< (), Box<dyn Error>> {
    // Initialization
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
    let pub_k = pu.export_pub_keys() ;
    for i in 2..10 {
    let nb_enc_bits = message_size(i) ;
    let ct_1 = pu.encrypt(i,nb_enc_bits+1)? ;
    let mut trivial_0 = ParmCiphertext::empty() ;
    trivial_0.push(LWE::encrypt_uint_triv(0,&pub_k.encoder)?) ;
    let enc_add_res = ParmArithmetics::add(&pc,&ct_1,&trivial_0) ;
    println!("test: addition_cc, status : - , m1 : {} , m1_len: {} , m2: {}, m2_len: {} , add_res : - ", i, nb_enc_bits, 0, message_size(0)) ;
    let dec_add_res = pu.decrypt(&enc_add_res)? ;
    assert_eq!(i, dec_add_res) ;
    }
    for i in 1..10 {
        let nb_enc_bits = message_size(i) ;
        let ct_1 = pu.encrypt(i,nb_enc_bits)? ;
        let mut trivial_0 = ParmCiphertext::empty() ;
        trivial_0.push(LWE::encrypt_uint_triv(0,&pub_k.encoder)?) ;
        let enc_add_res = ParmArithmetics::add(&pc,&ct_1,&trivial_0) ;
        println!("test: addition_cc, status : - , m1 : {} , m1_len: {} , m2: {}, m2_len: {} , add_res : - ", i, nb_enc_bits, 0, message_size(0)) ;
        let dec_add_res = pu.decrypt(&enc_add_res)? ;
        assert_eq!(i, dec_add_res) ;
    }
    Ok(())
}

fn scalar_add(
    m_len: i32,
    m_wlen: i32,
    r_triv: i32,
    triv_ct_len: i32,
) -> Result<Vec<u32>, Box<dyn Error>> {
    // =================================
    // test : add two elements x and y such as y is trivial
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
    // generate x and y ciphertexts
    let (plaintext_m, ct_m) = gen_ct_rtriv_zero(&pu, m_len, m_wlen, r_triv)?;
    let m = pu.decrypt(&ct_m);
    // handle error in decryption of mx
    let m = match m {
        Ok(m) => m,
        Err(err) => {
            println!("plaintext_input_m : {:?}", plaintext_m);
            println!("Error in the decryption of ct_m : {}", err);
            return Ok(plaintext_m);
        }
    };
    let (plaintext_triv, triv_ct) = gen_ct_triv(&pu, triv_ct_len)?;
    let m_triv = pu.decrypt(&triv_ct);
    // handle error in decryption of my
    let m_triv = match m_triv {
        Ok(m_triv) => m_triv,
        Err(err) => {
            println!("plaintext_input_trivial : {:?}", plaintext_triv);
            println!(
                "Error in the decryption of the trivial ciphertext : {}",
                err
            );
            return Ok(plaintext_triv);
        }
    };
    println!(
        " test: addition_cc , samples : m : {} , binary_input_m {:?}, m_len : {} , m_wlen : {} , m_rtriv_len : {} ,   m_triv : {} , binary_input_m_triv {:?}, ct_triv_len: {} ,   decrypted_result - ",
        m, plaintext_m,m_len,m_wlen,r_triv, m_triv ,  plaintext_triv, triv_ct_len
    );

    let enc_add_res = ParmArithmetics::add(&pc, &ct_m, &triv_ct);
    let add_res = pu.decrypt(&enc_add_res);
    let add_res = match add_res {
        Ok(add_res) => add_res,
        Err(err) => {
            println!("Error in the decryption of enc(m_triv) + enc(m) : {}", err);
            let filename = "scalar_addition";
            let line = "test: addition_corner_cases , status : failure, samples : mx : ".to_owned()
                + &m.to_string()
                + ", binary_input_m"
                + &format!("{:?}", plaintext_m).to_owned()
                + ", m_len : "
                + &m_len.to_string()
                + ", m_wlen: "
                + &m_wlen.to_string()
                + ", m_rtriv_len"
                + &r_triv.to_string()
                + ", m_triv : "
                + &m_triv.to_string()
                + ", binary_input_m_triv : "
                + &format!("{:?}", plaintext_triv).to_owned()
                + ", triv_ct_len : "
                + &triv_ct_len.to_string()
                + "\n";
            let mut add_cc_message = OpenOptions::new()
                .read(true)
                .append(true)
                .create(true)
                .open("src/tests/test_history/".to_owned() + filename + ".txt")
                .unwrap();
            add_cc_message.write_all(line.as_bytes()).unwrap();
            return Ok(plaintext_m);
        }
    };

    if m + m_triv == add_res {
        println!(
        " test: addition_cc , samples : m : {} , m_triv : {} , decrypted_result {}, ct_m.len : {} , triv_ct.len : {} ",
        m, m_triv, add_res, ct_m.len() , triv_ct.len()
    );
    } else {
        println!(
            " failure for test of the parallel additon corner case of {} and {} ",
            m, m_triv
        );
    }
    assert_eq!(m as i64 + m_triv as i64, add_res);
    Ok(plaintext_m)
}

fn plain_add(triv_ct_len: i32, triv_ct1_len: i32) -> Result<Vec<u32>, Box<dyn Error>> {
    // =================================
    // test : add two elements x and y such as y is trivial
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
    // generate x and y ciphertexts
    let (plaintext_triv, triv_ct) = gen_ct_triv(&pu, triv_ct_len)?;
    let m_triv = pu.decrypt(&triv_ct);
    // handle error in decryption of mx
    let m_triv = match m_triv {
        Ok(m_triv) => m_triv,
        Err(err) => {
            println!("plaintext_input_m : {:?}", plaintext_triv);
            println!("Error in the decryption of ct_m : {}", err);
            return Ok(plaintext_triv);
        }
    };
    let (plaintext_triv1, triv_ct1) = gen_ct_triv(&pu, triv_ct1_len)?;
    let m_triv1 = pu.decrypt(&triv_ct1);
    // handle error in decryption of my
    let m_triv1 = match m_triv1 {
        Ok(m_triv1) => m_triv1,
        Err(err) => {
            println!("plaintext_input_trivial : {:?}", plaintext_triv1);
            println!(
                "Error in the decryption of the trivial ciphertext : {}",
                err
            );
            return Ok(plaintext_triv1);
        }
    };
    println!(
        " test: addition_cc , samples : m_triv : {} , binary_input_m_triv {:?}, triv_ct_len : {} , m_triv1 : {},  binary_input_m_triv1 {:?}, triv_ct1_len: {} ,   decrypted_result - ",
        m_triv, plaintext_triv,triv_ct_len, m_triv1, plaintext_triv1, triv_ct1_len
    );

    let enc_add_res = ParmArithmetics::add(&pc, &triv_ct, &triv_ct1);
    let add_res = pu.decrypt(&enc_add_res);
    let add_res = match add_res {
        Ok(add_res) => add_res,
        Err(err) => {
            println!(
                "Error in the decryption of enc(m_triv) + enc(m_triv1) : {}",
                err
            );
            let filename = "triv_addition";
            let line = "test: addition_corner_cases , status : failure, samples : mx : ".to_owned()
                + &m_triv.to_string()
                + ", binary_input_m_triv : "
                + &format!("{:?}", plaintext_triv).to_owned()
                + ", triv_ct_len : "
                + &triv_ct_len.to_string()
                + ", m_triv1 : "
                + &m_triv1.to_string()
                + ", binary_input_m_triv1 : "
                + &format!("{:?}", plaintext_triv1).to_owned()
                + ", triv_ct1_len : "
                + &triv_ct1_len.to_string()
                + "\n";
            let mut add_cc_message = OpenOptions::new()
                .read(true)
                .append(true)
                .create(true)
                .open("src/tests/test_history/".to_owned() + filename + ".txt")
                .unwrap();
            add_cc_message.write_all(line.as_bytes()).unwrap();
            return Ok(plaintext_triv);
        }
    };

    if m_triv + m_triv1 == add_res {
        println!(
        " test: addition_cc , samples : m : {} , m_triv : {} , decrypted_result {}, ct_m.len : {} , triv_ct.len : {} ",
        m_triv, m_triv1, add_res, triv_ct1.len() , triv_ct.len()
    );
    } else {
        println!(
            " failure for test of the parallel additon corner case of {} and {} ",
            m_triv, m_triv1
        );
    }
    assert_eq!(m_triv as i64 + m_triv1 as i64, add_res);
    Ok(plaintext_triv)
}

fn gen_ct_rtriv_hc(
    pu: &ParmesanUserovo,
    x: &[u32],
    x_wlen: usize,
    x_triv_len: usize,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    // =================================
    // gen_ct_triv_zero returns a ciphertext with the following structure
    // 0|0|1| enc_bits  |rtriv_zero |
    // 0|0|1|-|-|-|-|-|-|0|0|0|0|0|0|
    let mut nx = ParmCiphertext::empty();
    let pub_k = pu.export_pub_keys();
    let mut vec: Vec<i32> = vec![];
    let x_rev = reverse_vec(x.to_vec());
    for i in 0..x.len() {
        if i < x_triv_len {
            let triv_0 = LWE::encrypt_uint_triv(x_rev[i], &pub_k.encoder)?;
            nx.push(triv_0);
        }
        if i >= x_triv_len && i < x_wlen {
            vec.push(x_rev[i] as i32);
        }
        if i == x_wlen - 1 {
            let mut enc_x = pu.encrypt_vec(&vec)?;
            nx.append(&mut enc_x);
        }
        if i >= x_wlen {
            let triv_0 = LWE::encrypt_uint_triv(x_rev[i], &pub_k.encoder)?;
            nx.push(triv_0);
        }
    }
    Ok(nx)
}

fn add_cc_hc(
    x: &[u32],
    x_wlen: usize,
    x_triv_len: usize,
    y: &[u32],
    y_wlen: usize,
    y_triv_len: usize,
) -> Result<u32, Box<dyn Error>> {
    // =================================
    // test : add two elements x and y such as r_triv !=0 in both ciphertexts
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
    // generate x and y ciphertexts!
    let ct_x = gen_ct_rtriv_hc(&pu, x, x_wlen, x_triv_len)?;
    let mx = pu.decrypt(&ct_x);
    // handle error in decryption of mx
    let mx = match mx {
        Ok(mx) => mx,
        Err(err) => {
            println!("plaintext input: {:?}", x);
            println!("Error : {}", err);
            return Ok(0);
        }
    };
    let ct_y = gen_ct_rtriv_hc(&pu, y, y_wlen, y_triv_len)?;
    let my = pu.decrypt(&ct_y);
    // handle error in decryption of my
    let my = match my {
        Ok(my) => my,
        Err(err) => {
            println!("plaintext input: {:?}", y);
            println!("Error : {}", err);
            return Ok(0);
        }
    };
    println!(
        " test: addition_cc , samples : mx : {} , binary_input_mx {:?}, x_len : {} , x_wlen : {} , x_rtriv_len : {} ,   my : {} , binary_input_my {:?}, y_len: {} , y_wlen : {} , y_triv_len : {} ,    decrypted_result - ",
        mx, x,x.len(),x_wlen,x_triv_len, my ,  y, y.len(),y_wlen,y_triv_len
    );

    let enc_add_res = ParmArithmetics::add(&pc, &ct_x, &ct_y);
    let add_res = pu.decrypt(&enc_add_res);
    let add_res = match add_res {
        Ok(add_res) => add_res,
        Err(err) => {
            println!("Error : {}", err);
            let filename = "addition_corner_cases_failures";
            let line = "test: addition_corner_cases , status : failure, samples : mx : ".to_owned()
                + &mx.to_string()
                + ", binary_input_mx"
                + &format!("{:?}", x).to_owned()
                + ", x_len : "
                + &x.len().to_string()
                + ", x_wlen: "
                + &x_wlen.to_string()
                + ", x_rtriv_len"
                + &x_triv_len.to_string()
                + ", my : "
                + &my.to_string()
                + ", binary_input_my : "
                + &format!("{:?}", y).to_owned()
                + ", y_len : "
                + &y.len().to_string()
                + ", y_wlen : "
                + &y_wlen.to_string()
                + ", y_triv_len : "
                + &y_triv_len.to_string()
                + "\n";
            let mut add_cc_message = OpenOptions::new()
                .read(true)
                .append(true)
                .create(true)
                .open("src/tests/test_history/".to_owned() + filename + ".txt")
                .unwrap();
            add_cc_message.write_all(line.as_bytes()).unwrap();
            return Ok(0);
        }
    };

    if mx + my == add_res {
        println!(
        " test: addition_cc , samples : mx : {} , my : {} , decrypted_result {}, ct_x.len : {} , ct_y.len : {} ",
        mx, my, add_res, ct_x.len() , ct_y.len()
    );
    } else {
        println!(
            " valid test of the parallel additon corner case 1 of {} and {} ",
            mx, my
        );
    }
    assert_eq!(mx as i64 + my as i64, add_res);
    Ok(0)
}

#[test]
fn add_cc_hc1() {
    /*let x1 = [0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0];
    let x1_wlen = 7;
    let x1_triv = 3;
    let y1 = [0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0];
    let y1_wlen = 10;
    let y1_triv = 3;
    add_cc_hc(&x1, x1_wlen, x1_triv, &y1, y1_wlen, y1_triv).unwrap();
    let x2 = [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0];
    let x2_wlen = 6;
    let x2_triv = 5;
    let y2 = [0, 0, 1, 1, 0, 0, 1, 0, 0, 1];
    let y2_wlen = 9;
    let y2_triv = 8;
    add_cc_hc(&x2, x2_wlen, x2_triv, &y2, y2_wlen, y2_triv).unwrap(); */
    let x3 = [0, 0, 0, 0, 0, 0, 1, 0, 0, 0];
    let x3_wlen = 4;
    let x3_triv = 2;
    let y3 = [0, 0, 0, 0, 1, 0, 0, 0, 0];
    let y3_wlen = 6;
    let y3_triv = 5;
    add_cc_hc(&x3, x3_wlen, x3_triv, &y3, y3_wlen, y3_triv).unwrap();
}
fn add_cc_nz(
    x_len: i32,
    x_wlen: i32,
    x_triv_len: i32,
    y_len: i32,
    y_wlen: i32,
    y_triv_len: i32,
) -> Result<Vec<u32>, Box<dyn Error>> {
    // =================================
    // test : add two elements x and y such as r_triv !=0 in both ciphertexts
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
    // generate x and y ciphertexts
    let (plaintext_x, ct_x) = gen_ct_rtriv_custom(&pu, x_len, x_wlen, x_triv_len)?;
    let mx = pu.decrypt(&ct_x);
    // handle error in decryption of ct_x
    let mx = match mx {
        Ok(mx) => mx,
        Err(err) => {
            println!("plaintext input: {:?}", plaintext_x);
            println!("Error in the decryption of mx : {}", err);
            return Ok(plaintext_x);
        }
    };
    let (plaintext_y, ct_y) = gen_ct_rtriv_custom(&pu, y_len, y_wlen, y_triv_len)?;
    let my = pu.decrypt(&ct_y);
    // handle error in decryption of ct_y
    let my = match my {
        Ok(my) => my,
        Err(err) => {
            println!("plaintext input: {:?}", plaintext_y);
            println!("Error in the decryption of my : {}", err);
            return Ok(plaintext_y);
        }
    };

    println!(
        " test: addition_cc , samples : mx : {} , binary_input_mx {:?}, x_len : {} , x_wlen : {} , x_triv_len : {} ,   my : {} , binary_input_my {:?}, y_len: {} , y_wlen : {} , y_triv_len : {} ,  decrypted_result - ",
        mx, plaintext_x,x_len,x_wlen,x_triv_len, my ,  plaintext_y, y_len,y_wlen, y_triv_len
    );

    let enc_add_res = ParmArithmetics::add(&pc, &ct_x, &ct_y);
    let add_res = pu.decrypt(&enc_add_res);
    let add_res = match add_res {
        Ok(add_res) => add_res,
        Err(err) => {
            println!("Error in the decryption of en(mx)+enc(my) : {}", err);
            return Ok(plaintext_x);
        }
    };
    if mx + my == add_res {
        println!(
        " Addition_cc: r_triv !=0 , samples : mx : {} , my : {} , decrypted_result {}, ct_x.len : {} , ct_y.len : {} ",
        mx, my, add_res, ct_x.len() , ct_y.len()
    );
    } else {
        println!(
            " valid test of the parallel additon corner case 1 of {} and {} ",
            mx, my
        );
    }
    assert_eq!(mx as i64 + my as i64, add_res);
    Ok(plaintext_x)
}

fn add_cc(
    x_len: i32,
    x_wlen: i32,
    x_triv_len: i32,
    y_len: i32,
    y_wlen: i32,
    y_triv_len: i32,
) -> Result<Vec<u32>, Box<dyn Error>> {
    // =================================
    // test : add two elements x and y such as r_triv !=0 in both ciphertexts
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
    // generate x and y ciphertexts
    let (plaintext_x, ct_x) = gen_ct_rtriv_zero(&pu, x_len, x_wlen, x_triv_len)?;
    let mx = pu.decrypt(&ct_x);
    // handle error in decryption of mx
    let mx = match mx {
        Ok(mx) => mx,
        Err(err) => {
            println!("plaintext input: {:?}", plaintext_x);
            println!("Error : {}", err);
            return Ok(plaintext_x);
        }
    };
    let (plaintext_y, ct_y) = gen_ct_rtriv_custom(&pu, y_len, y_wlen, y_triv_len)?;
    let my = pu.decrypt(&ct_y);
    // handle error in decryption of my
    let my = match my {
        Ok(my) => my,
        Err(err) => {
            println!("plaintext input: {:?}", plaintext_y);
            println!("Error : {}", err);
            return Ok(plaintext_y);
        }
    };
    println!(
        " test: addition_cc , samples : mx : {} , binary_input_mx {:?}, x_len : {} , x_wlen : {} , x_triv_len : {} ,   my : {} , binary_input_my {:?}, y_len: {} , y_wlen : {} , y_triv_len : {} ,  decrypted_result - ",
        mx, plaintext_x,x_len,x_wlen,x_triv_len, my ,  plaintext_y, y_len,y_wlen, y_triv_len
    );

    let enc_add_res = ParmArithmetics::add(&pc, &ct_x, &ct_y);
    let add_res = pu.decrypt(&enc_add_res);
    let add_res = match add_res {
        Ok(add_res) => add_res,
        Err(err) => {
            println!("Error : {}", err);
            let filename = "addition_corner_cases_failures";
            let line = "test: addition_corner_cases , status : failure, samples : mx : ".to_owned()
                + &mx.to_string()
                + ", binary_input_mx"
                + &format!("{:?}", plaintext_x).to_owned()
                + ", x_len : "
                + &x_len.to_string()
                + ", x_wlen: "
                + &x_wlen.to_string()
                + ", x_rtriv_len"
                + &x_triv_len.to_string()
                + ", my : "
                + &my.to_string()
                + ", binary_input_my : "
                + &format!("{:?}", plaintext_y).to_owned()
                + ", y_len : "
                + &y_len.to_string()
                + ", y_wlen : "
                + &y_wlen.to_string()
                + ", y_triv_len : "
                + &y_triv_len.to_string()
                + "\n";
            let mut add_cc_message = OpenOptions::new()
                .read(true)
                .append(true)
                .create(true)
                .open("src/tests/test_history/".to_owned() + filename + ".txt")
                .unwrap();
            add_cc_message.write_all(line.as_bytes()).unwrap();
            return Ok(plaintext_x);
        }
    };

    if mx + my == add_res {
        println!(
        " test: addition_cc , samples : mx : {} , my : {} , decrypted_result {}, ct_x.len : {} , ct_y.len : {} ",
        mx, my, add_res, ct_x.len() , ct_y.len()
    );
    } else {
        println!(
            " valid test of the parallel additon corner case 1 of {} and {} ",
            mx, my
        );
    }
    assert_eq!(mx as i64 + my as i64, add_res);
    Ok(plaintext_x)
}

#[test]
// =================================
// test : addition of two elements x and y such as x and y generated randomly
//         {      wlen      }
// x : |0|0|.. -|-|-|-|1|1|0|1
// y :  0|0|0|..|-|1|0|0|1|0|1
//==================================
fn add_cc_1() {
    for _i in 0..10 {
        let mut rng = rand::thread_rng();
        let x_len = rng.gen_range(6..32);
        let x_wlen = rng.gen_range(4..x_len);
        let x_triv_len = rng.gen_range(2..x_wlen);
        let y_len = rng.gen_range(6..32);
        let y_wlen = rng.gen_range(4..y_len);
        let y_triv_len = rng.gen_range(2..y_wlen);
        add_cc_nz(x_len, x_wlen, x_triv_len, y_len, y_wlen, y_triv_len).unwrap();
    }
}

#[test]
fn add_cc_2() {
    // =================================
    // test : addition of two elements x and y such as : |x|> wlen > |y|
    //         {      wlen      }
    // x : |0|0|.. -|-|-|-|1|0|0
    // y :        0|0|..|-|1|0|0
    //==================================
    for _i in 0..10 {
        let mut rng = rand::thread_rng();
        let x_len = rng.gen_range(10..32);
        let x_wlen = rng.gen_range(8..x_len);
        let x_triv_len = rng.gen_range(2..x_wlen);
        let y_len = rng.gen_range(6..x_wlen);
        let y_wlen = rng.gen_range(4..y_len);
        let y_triv_len = rng.gen_range(2..y_wlen);
        add_cc(x_len, x_wlen, x_triv_len, y_len, y_wlen, y_triv_len).unwrap();
    }
}
#[test]
fn add_cc_3() {
    // =================================
    // Addition corner case 3 : |y| > |x| > wlen
    // test : addition of two elements x and y such as : |y|> |x| >wlen
    //            {       wlen    }
    // x :    |0|0|... -|-|-|-|1|0|0
    // y : 0|0|0|0|0|-..|-|-|-|1|0|0
    //==================================
    let mut rng = rand::thread_rng();
    // generate 10 random ciphertexts for x and y and call add_cc to test them
    for _i in 0..10 {
        let x_len = rng.gen_range(8..32);
        let x_wlen = rng.gen_range(6..x_len);
        let x_triv_len = rng.gen_range(2..x_wlen);
        let y_len = rng.gen_range(x_len - 1..32);
        let y_wlen = rng.gen_range(4..x_wlen);
        let y_triv_len = rng.gen_range(2..y_wlen);
        add_cc(x_len, x_wlen, x_triv_len, y_len, y_wlen, y_triv_len).unwrap();
    }
}

#[test]
fn add_cc_4() {
    // =================================
    // test : addition of two elements x and y such as : |x|> |y|> wlen
    //            {      wlen      }
    // x :|0|0|0|0|0|-|-|-|-|1|0|0
    // y :     0|0|-..|-|-|-|1|0|0
    //==================================
    let mut rng = rand::thread_rng();
    // generate 10 random ciphertexts for x and y and call add_cc to test them
    for _i in 0..10 {
        let x_len = rng.gen_range(10..12);
        let y_len = rng.gen_range(8..x_len);
        let y_wlen = rng.gen_range(6..y_len);
        let x_wlen = rng.gen_range(4..y_wlen);
        let x_triv_len = rng.gen_range(2..x_wlen);
        let y_triv_len = rng.gen_range(2..y_wlen);
        add_cc(x_len, x_wlen, x_triv_len, y_len, y_wlen, y_triv_len).unwrap();
    }
}

#[test]
fn add_cc_5() {
    // =================================
    // Addition corner case 4 : |y| > wlen > |x|
    // test : addition of two elements x and y such as : |y|> wlen > |x|
    //        {      wlen      }
    // x :      |0|0|-|-|1|0|0|0
    // y :|0|0|-...|-|-|-|1|0|1
    //==================================
    let mut rng = rand::thread_rng();
    // generate 10 random ciphertexts for x and y and call add_cc to test them
    for _i in 0..10 {
        let x_len = rng.gen_range(6..31);
        let y_len = rng.gen_range(x_len..32);
        let y_wlen = rng.gen_range(x_len..y_len);
        let x_wlen = rng.gen_range(3..x_len);
        let x_triv_len = rng.gen_range(2..x_wlen);
        let y_triv_len = rng.gen_range(2..y_wlen);
        add_cc(x_len, x_wlen, x_triv_len, y_len, y_wlen, y_triv_len).unwrap();
    }
}
// addition with plain data and encrypted data
#[test]
fn add_scalar() {
    scalar_add(11, 8, 3, 10).unwrap();
}

// addition with plain data for both integers
#[test]
fn add_plain() {
    plain_add(3, 3).unwrap();
}
