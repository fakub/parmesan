use super::*;
#[cfg(test)]
use rand::Rng;
#[test]
fn test_max() -> Result<(), Box<dyn Error>> {
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
    // generate 10 random samples to test
    for _i in 0..10 {
        let mut rng = rand::thread_rng();
        let m1 = rng.gen::<i64>();
        let m2 = rng.gen::<i64>();
        //let nb_enc_bits = rng.gen_range(1..20) ;
        let m1_bin = format!("{:b}", m1);
        let nb_enc_bits = m1_bin.to_string().len();
        println!(
            "parallel maximum test for {} {} with a number of encrypted bits{}",
            m1, m2, nb_enc_bits
        );
        let mut enc_r1 = pu.encrypt(m1, nb_enc_bits)?;
        let enc_r2 = pu.encrypt(m2, nb_enc_bits)?;
        enc_r1 = ParmArithmetics::max(&pc, &enc_r1, &enc_r2);
        let r1: i64 = pu.decrypt(&enc_r1)?;
        if (std::cmp::max(m1, m2) - r1) % nb_enc_bits as i64 == 0 {
            println!(" valid test of the parallel maximum of {} and {} with a number of encrypted bits {} ", m1,m2,nb_enc_bits);
        } else {
            println!(" failure in the test of the parallel maximum of {} and {} with a number of encrypted bits {} ", m1,m2,nb_enc_bits);
        }
        assert_eq!(std::cmp::max(m1, m2), r1);
    }
    Ok(())
}
