use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;

use rand::Rng;

use crate::params;
use crate::ParmesanUserovo;
use crate::ParmesanCloudovo;
use crate::arithmetics::ParmArithmetics;

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

fn test_sgn(m1: i64) -> Result<(), Box<dyn Error>> {
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
        "test: signum , status:- , samples : m1 : {}, m1.size : {}, decrypted_result : - , length of decrypted result : - ",
        m1, len_m1
    );
    let enc_m1 = pu.encrypt(m1, len_m1)?;
    let enc_res = ParmArithmetics::sgn(&pc, &enc_m1);
    let res: i64 = pu.decrypt(&enc_res)?;
    let len_res = message_size(res);
    if m1.signum() as i64 - res == 0 {
        println!(
            "test: signum , status: valid, samples : m1 : {}, decrypted result : {},  m1.size : {}, length of decrypted result : {} ",
            m1, res, len_m1,  len_res
        );
        let line = "test: signum , status : valid, samples : m1 : ".to_owned()
            + &m1.to_string()
            + ", decrypted result : "
            + &res.to_string()
            + ", m1.size : "
            + &len_m1.to_string()
            + ", length of decrypted result"
            + &len_res.to_string()
            + "\n";
        let mut signum_message = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open("src/tests/test_history/signum_samples.txt")
            .unwrap();
        signum_message.write_all(line.as_bytes()).unwrap();
    } else {
        println!(
            "test: signum , status: failure, samples : m1 : {}, decrypted result : {}, m1.size : {}, length of decrypted result : {} ",
            m1, res, len_m1, len_res
        );
        let line = "test: signum , status : valid, samples : m1 : ".to_owned()
            + &m1.to_string()
            + ", decrypted result : "
            + &res.to_string()
            + ", m1.size : "
            + &len_m1.to_string()
            + ", length of decrypted result"
            + &len_res.to_string()
            + "\n";
        let mut signum_message = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open("src/tests/test_history/signum_failures.txt")
            .unwrap();
        signum_message.write_all(line.as_bytes()).unwrap();
    }
    assert_eq!(m1.signum() as i64, res);
    Ok(())
}

#[test]
fn sgn_rd() {
    let mut rng = rand::thread_rng();
    let mut m1: i64;
    for _i in 0..10 {
        m1 = rng.gen::<i64>();
        test_sgn(m1).unwrap();
    }
}

#[test]
fn sgn_m() {
    let m1 = 0;
    test_sgn(m1).unwrap();
}
