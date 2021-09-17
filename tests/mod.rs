#[cfg(test)]
use rand::Rng ; 
use concrete::LWE;
use super::* ; 
/*
fn inti_userovo()-> Result<ParmesanUserovo <'static>, Box<dyn Error>>{
// =================================
    //  Initialization

    // ---------------------------------
    //  Global Scope
    let par = &params::PARM90__PI_5__D_20__LEN_32;   //     PARM90__PI_5__D_20__LEN_32      PARMXX__TRIVIAL

    // ---------------------------------
    //  Userovo Scope
    let pu = ParmesanUserovo::new(par)?; 
    Ok(pu)  
} 
fn init_cloudovo(pu: ParmesanUserovo)-> Result <ParmesanCloudovo<'static>, Box<dyn Error+'_>>{
    let pub_k = pu.export_pub_keys();
    let par = pu.params ; 
    // ---------------------------------
    //  Cloudovo Scope
    let pc = ParmesanCloudovo::new(
        par,
        &pub_k,
    );
    Ok(pc)  
}
*/


fn gen_ct_rtriv_zero(pu : &ParmesanUserovo , x_length:i32 , x_wlen:i32 , r_triv_len:i32)-> Result<ParmCiphertext, Box<dyn Error>>{
    // =================================
    // gen_ct_triv_zero returns a ciphertext with the following structure 
    // 0|0|1| enc_bits  |rtriv_zero |
    // 0|0|1|-|-|-|-|-|-|0|0|0|0|0|0|
    let mut nx = ParmCiphertext::empty();  
    let pub_k = pu.export_pub_keys();
    let mut rng = rand::thread_rng();
    let mut vec = vec![] ; 
    let mut rand_bit ; 
    for i in 0..x_length{
        if i < r_triv_len { 
        let triv_0 = LWE::encrypt_uint_triv(0,&pub_k.encoder)? ; 
        nx.push(triv_0) ; } 
        if i >= r_triv_len && i< x_wlen - 2  
        {
        rand_bit= rng.gen_range(0..1) ; 
        vec.push(rand_bit) ;     }
        if i== x_wlen - 2 {
        let mut enc_x = pu.encrypt_vec(&vec)? ; 
        nx.append(& mut enc_x) ; }
        if  i == x_wlen -1  {
        let triv_1 = LWE::encrypt_uint_triv(1,&pub_k.encoder) ? ;
        nx.push(triv_1) ; }
        if  i>= x_wlen {
        let triv_0 = LWE::encrypt_uint_triv(0,&pub_k.encoder)? ; 
        nx.push(triv_0) ; }
    }
    Ok(nx)   
}
fn gen_ct_rtriv_custom(pu:&ParmesanUserovo, y_length: i32, y_wlen:i32) -> Result<ParmCiphertext, Box<dyn Error>> {
    //==================================
    // gen ct_triv_custom returns a ciphertext with the following structure 
    // |0|0|.. -|-|-|-|1|0|0
    //==================================
    let mut ny= ParmCiphertext::empty() ; 
    let pub_k= pu.export_pub_keys() ; 
    let mut rng = rand::thread_rng() ; 
    let rand_rng = rng.gen_range(1..y_wlen) ; 
    for _j in 0..rand_rng as i32{
        let rand_bit= rng.gen_range(0..1) ; 
        let triv_rand_bit= LWE::encrypt_uint_triv(rand_bit,&pub_k.encoder)? ; 
        ny.push(triv_rand_bit) ; }
    let mut vec = vec![] ; 
    for _j in rand_rng..y_wlen{
        let rand_bit = rng.gen_range(0..1) ; 
        vec.push(rand_bit) ; 
    }
    let mut enc_y = pu.encrypt_vec(&vec)? ;
    ny.append(& mut enc_y) ;
    for _j in y_wlen..y_length{ 
        let triv_rand_bit= LWE::encrypt_uint_triv(0,&pub_k.encoder)? ; 
        ny.push(triv_rand_bit) ; }
    Ok(ny) 
}
fn demo_nn() -> NeuralNetwork {
    NeuralNetwork {
        layers: vec![
            vec![
                Perceptron {
                    t: PercType::MAX,
                    w: vec![1,-2,-2,],
                    b: 2,
                },
                Perceptron {
                    t: PercType::LIN,
                    w: vec![1,3,-1,],
                    b: -5,
                },
                Perceptron {
                    t: PercType::ACT,
                    w: vec![1,3,-1,],
                    b: 3,
                },
            ],
        ],
    }
}

#[test]  
fn test_encrypt_decrypt()-> Result<(),Box<dyn Error>>{
     // =================================
    //  Initialization

    // ---------------------------------
    //  Global Scope
    let par = &params::PARM90__PI_5__D_20__LEN_32;   //     PARM90__PI_5__D_20__LEN_32      PARMXX__TRIVIAL

    // ---------------------------------
    //  Userovo Scope
    let pu = ParmesanUserovo::new(par)?;    
    let mut rng = rand::thread_rng();
    // generate 10 random samples to test 
    for _i in 0..10 {
    let m1:i64 = rng.gen::<i64>() ; 
    let nb_enc_bits = rng.gen_range(1..20) ; 
    let enc_r1= pu.encrypt(m1,nb_enc_bits)? ; 
    let r1:i64 = pu.decrypt(&enc_r1)? ;
    if (m1-r1) % nb_enc_bits as i64 ==0 {
        println!("valid test for encrypt_decrypt {}",m1) ; 

    } 
    else {
        println!("problem with the test of encrypt_decrypt {}",m1) ; 

    }
    assert_eq! ( (r1-m1) % nb_enc_bits as i64, 0   ); }
    Ok(())
    
}
#[test]
fn test_add() ->Result<(), Box<dyn Error>> {
     // =================================
    //  Initialization

    // ---------------------------------
    //  Global Scope
    let par = &params::PARM90__PI_5__D_20__LEN_32;   //     PARM90__PI_5__D_20__LEN_32      PARMXX__TRIVIAL

    // ---------------------------------
    //  Userovo Scope
    let pu = ParmesanUserovo::new(par)?;
    let pub_k = pu.export_pub_keys();
    // ---------------------------------
    //  Cloudovo Scope
    let pc = ParmesanCloudovo::new(
        par,
        &pub_k,
    );
    // =================================
    // generate 10 random samples to test 
    for _i in 0..10 {
    // check for add overflow
    let mut add_check = None ; 
    let mut m1:i64 = 0 ; 
    let mut m2:i64 = 0 ; 
    let mut rng = rand::thread_rng();
    while add_check == None {
        m1 = rng.gen::<i64>() ; 
        m2 = rng.gen::<i64>() ; 
        add_check = m1.checked_add(m2); }
        let nb_enc_bits = rng.gen_range(1..20) ;
        let mut enc_r1 = pu.encrypt(m1, nb_enc_bits)?; 
        let enc_r2 = pu.encrypt(m2, nb_enc_bits)?; 
        enc_r1 = ParmArithmetics::add(&pc,&enc_r1,&enc_r2) ; 
        let r1:i64 = pu.decrypt(&enc_r1)?; 
        if (m1+m2  - r1 ) % nb_enc_bits as i64 ==0  {
                println!("valid test for add op of {} and {}", m1,m2) ; 
                } 
                else {
                println!("problem with the add operation of {} and {}",m1,m2)
    }
    println!("add test for {} {}",m1,m2) ; 
    assert_eq! ( (m1 as i64 + m2 as i64 - r1) % nb_enc_bits as i64 , 0   ); }
    Ok(())  

}
#[test]
fn test_sub()->Result<(), Box<dyn Error>> { 
    // =================================
    //  Initialization

    // ---------------------------------
    //  Global Scope
    let par = &params::PARM90__PI_5__D_20__LEN_32;   //     PARM90__PI_5__D_20__LEN_32      PARMXX__TRIVIAL

    // ---------------------------------
    //  Userovo Scope
    let pu = ParmesanUserovo::new(par)?;
    let pub_k = pu.export_pub_keys();
    // ---------------------------------
    //  Cloudovo Scope
    let pc = ParmesanCloudovo::new(
        par,
        &pub_k,
    );

    // generate 10 random samples to test 
    for _i in 0..10 {
    // check for sub overflow
    let mut sub_check = None ; 
    let mut m1: i64 = 0 ; 
    let mut m2: i64 = 0 ;
    let mut rng = rand::thread_rng();
    while sub_check == None {
        m1  = rng.gen::<i64>() ; 
        m2  = rng.gen::<i64>() ; 
        sub_check = m1.checked_sub(m2); }
        let nb_enc_bits = rng.gen_range(1..20) ; 
        let enc_r1 = pu.encrypt(m1,nb_enc_bits)?; 
        let enc_r2 = pu.encrypt(m2, nb_enc_bits)?; 
        let enc_r1 = ParmArithmetics::sub(&pc,&enc_r1,&enc_r2) ; 
        let r1:i64 = pu.decrypt(&enc_r1)?;
        if (m1 - m2  - r1)% nb_enc_bits as i64 ==0  {
                println!("valid test for add op of {} and {}", m1,m2) ; 
                } 
                else {
                println!("problem with the add operation of {} and {}",m1,m2)
    }
    println!("sub test for {} {}",m1,m2) ; 
    assert_eq! ( (m1 - m2  - r1) % nb_enc_bits as i64 , 0   ); }
    Ok(())  
    }
#[test]
fn test_sgn()->Result<(),Box<dyn Error>> {
    // =================================
    //  Initialization

    // ---------------------------------
    //  Global Scope
    let par = &params::PARM90__PI_5__D_20__LEN_32;   //     PARM90__PI_5__D_20__LEN_32      PARMXX__TRIVIAL

    // ---------------------------------
    //  Userovo Scope
    let pu = ParmesanUserovo::new(par)?;
    let pub_k = pu.export_pub_keys();
    // ---------------------------------
    //  Cloudovo Scope
    let pc = ParmesanCloudovo::new(
        par,
        &pub_k,
    );
    // generate 10 random samples to test 
    for _i in 0..10 {
    let mut rng = rand::thread_rng();
    let m1 = rng.gen::<i64>() ; 
    let nb_enc_bits = rng.gen_range(1..20) ; 
    let mut enc_r1 = pu.encrypt(m1,nb_enc_bits)?; 
    enc_r1 = ParmArithmetics::sgn(&pc, &enc_r1) ; 
    let r1:i64 = pu.decrypt(&enc_r1)?; 

    if (m1.signum() as i64 - r1 ) % nb_enc_bits as i64  ==0  {
            println!(" valid test for sign operation of {} ", m1) ; 
        } 
    else {
            println!("problem with the test of sign operation of {}",m1) ; 
        }
    assert_eq!( (m1.signum() - r1 )% nb_enc_bits as i64, 0 ); }
    Ok(())  
    }
#[test]
fn test_max()->Result<(), Box<dyn Error>> {
            // =================================
    //  Initialization

    // ---------------------------------
    //  Global Scope
    let par = &params::PARM90__PI_5__D_20__LEN_32;   //     PARM90__PI_5__D_20__LEN_32      PARMXX__TRIVIAL

    // ---------------------------------
    //  Userovo Scope
    let pu = ParmesanUserovo::new(par)?;
    let pub_k = pu.export_pub_keys();
    // ---------------------------------
    //  Cloudovo Scope
    let pc = ParmesanCloudovo::new(
        par,
        &pub_k,
    );
    // generate 10 random samples to test 
    for _i in 0..10 {
    let mut rng = rand::thread_rng();
    let m1  = rng.gen::<i64>() ; 
    let m2  = rng.gen::<i64>() ; 
    let nb_enc_bits = rng.gen_range(1..20) ;
    let mut enc_r1 = pu.encrypt(m1,nb_enc_bits)?; 
    let enc_r2 = pu.encrypt(m2,nb_enc_bits)?; 
    enc_r1 = ParmArithmetics::max(&pc, &enc_r1,&enc_r2) ; 
    let r1:i64 = pu.decrypt(&enc_r1)?; 
    if (std::cmp::max(m1,m2) - r1) % nb_enc_bits as i64 ==0  {
    println!(" valid test for max operation of {} and {} ", m1,m2) ; 
    } 
    else {
        println!("problem with the test of max operation of {} and {}",m1,m2) ; 
        }
        assert_eq!((std::cmp::max(m1,m2) - r1) % nb_enc_bits as i64, 0 ); }
        Ok(())  

    }
    #[test]
    fn test_mul()->Result<(),Box<dyn Error>> {
        // =================================
        //  Initialization

        // ---------------------------------
        //  Global Scope
        let par = &params::PARM90__PI_5__D_20__LEN_32;   //     PARM90__PI_5__D_20__LEN_32      PARMXX__TRIVIAL

        // ---------------------------------
        //  Userovo Scope
        let pu = ParmesanUserovo::new(par)?;
        let pub_k = pu.export_pub_keys();
        // ---------------------------------
        //  Cloudovo Scope
        let pc = ParmesanCloudovo::new(
            par,
            &pub_k,
        );
        // generate 10 random samples 
        for _i in 0..10 {
        // check for mul overflow
            let mut mul_check = None ; 
            let mut m1: i64 = 0 ; 
            let mut m2: i64 = 0 ;
            let mut rng = rand::thread_rng();
            while mul_check == None {
                m1  = rng.gen::<i64>() ; 
                m2  = rng.gen::<i64>() ; 
                mul_check = m1.checked_mul(m2); }
            let nb_enc_bits = rng.gen_range(1..20) ;
            let enc_r1 = pu.encrypt(m1, nb_enc_bits)?; 
            let enc_r2 = pu.encrypt(m2, nb_enc_bits)?; 
            let enc_r1 = ParmArithmetics::mul(&pc,&enc_r1,&enc_r2) ; 
            let r1:i64 = pu.decrypt(&enc_r1)?; 
            if (m1 * m2  - r1 )% nb_enc_bits as i64 ==0  {
                    println!("valid test for add op of {} and {}", m1,m2) ; 
                    } 
                    else {
                    println!("problem with the add operation of {} and {}",m1,m2)
        }
        println!("multiplication of {} and {}",m1,m2) ; 
        assert_eq! ((m1 * m2  - r1) % nb_enc_bits as i64, 0   ); }
        Ok(())  
    }
    #[test]
    fn test_scalar_mul()-> Result<(), Box<dyn Error>> {
        // =================================
        //  Initialization
        // ---------------------------------
        //  Global Scope
        let par = &params::PARM90__PI_5__D_20__LEN_32;   //     PARM90__PI_5__D_20__LEN_32      PARMXX__TRIVIAL
        // ---------------------------------
        //  Userovo Scope
        let pu = ParmesanUserovo::new(par)?;
        let pub_k = pu.export_pub_keys();
        // ---------------------------------
        //  Cloudovo Scope
        let pc = ParmesanCloudovo::new(par,
                &pub_k,
            );
        // check for mul overflow
        let mut mul_check = None ; 
        let mut m1: i64 = 0 ; 
        let mut m2: i32 = 0 ;
        let mut rng = rand::thread_rng();
        // generate 10 random samples to test 
        for _i in 0..10 {
        while mul_check == None {
            m1  = rng.gen::<i64>() ; 
            m2  = rng.gen::<i32>() ; 
            mul_check = m1.checked_mul(m2 as i64); }
        let nb_enc_bits = rng.gen_range(1..20) ;
        let enc_r1 = pu.encrypt(m1, nb_enc_bits)?; 
        let enc_r1 = ParmArithmetics::scalar_mul(&pc,m2,&enc_r1); 
        let r1:i64 = pu.decrypt(&enc_r1)?; 
        if (m1 as i64 * m2 as i64  - r1 )% nb_enc_bits as i64 ==0  {
            println!("valid test for add op of {} and {}", m1,m2) ; 
        } 
            else {
                println!("problem with the add operation of {} and {}",m1,m2)
            }
        println!("multiplication of {} and {}",m1,m2) ; 
        assert_eq! ((m1 as i64 * m2 as i64  - r1 ) % nb_enc_bits as i64 , 0   ); }
        Ok(())  

   }

   #[test]
   fn addition_corner_case_1()-> Result<(), Box<dyn Error>>{
       // =================================
       // Addition Corner Case 1 : r_triv != 0   
       //  Initialization
       // ---------------------------------
       //  Global Scope
        let par = &params::PARM90__PI_5__D_20__LEN_32;   //     PARM90__PI_5__D_20__LEN_32      PARMXX__TRIVIAL
        // ---------------------------------
        //  Userovo Scope
        let pu = ParmesanUserovo::new(par)?;
        let pub_k = pu.export_pub_keys();
        // ---------------------------------
        //  Cloudovo Scope
        let pc = ParmesanCloudovo::new(par,
                &pub_k,
            );
        for _i in 0..10 {
        let mut add_check = None ; 
        while add_check ==None { 
        let mut rng = rand::thread_rng() ;     
        let x_length = rng.gen_range(50..62) ;
        let x_wlen = rng.gen_range(49..x_length) ; 
        // generate x and y ciphertexts 
        let ct_x: ParmCiphertext =gen_ct_rtriv_custom(&pu,x_length,x_wlen)? ;
        let m_x = pu.decrypt(&ct_x) ?; 
        let y_length = rng.gen_range(50..62) ; 
        let y_wlen = rng.gen_range(49..y_length) ; 
        let ct_y:ParmCiphertext = gen_ct_rtriv_custom(&pu,y_length,y_wlen)?  ; 
        let m_y = pu.decrypt(&ct_y) ?; 
        add_check = m_x.checked_add(m_y); 
        if add_check != None  {
            let enc_add_res = ParmArithmetics::add(&pc,&ct_x,&ct_y) ;
            let add_res = pu.decrypt(&enc_add_res)? ;  
            if m_x+m_y  - add_res ==0  {
                println!("valid test for addition corner case of {} and {}", m_x,m_y) ; 
            } 
            else {
                println!("problem with the addition corner case with {} and {}",m_x,m_y)
             }
        println!("addition corner cases test for {} {} ",m_x,m_y) ; 
        assert_eq! ((m_x as i64 + m_y as i64 - add_res) , 0   ); }
    }
}
        Ok(()) 
   }
   #[test]
   fn addition_corner_case_2()-> Result<(), Box<dyn Error>>{
       // =================================
       // Addition Corner Case 1 : |x|> wlen > |y|  
       //  Initialization
       // ---------------------------------
       //  Global Scope
        let par = &params::PARM90__PI_5__D_20__LEN_32;   //     PARM90__PI_5__D_20__LEN_32      PARMXX__TRIVIAL
        // ---------------------------------
        //  Userovo Scope
        let pu = ParmesanUserovo::new(par)?;
        let pub_k = pu.export_pub_keys();
        // ---------------------------------
        //  Cloudovo Scope
        let pc = ParmesanCloudovo::new(par,
                &pub_k,
            );
        // generate 10 random samples 
        for _i in 0..10 { 
        let mut add_check = None ; 
        while add_check ==None { 
        let mut rng = rand::thread_rng() ;     
        let x_length = rng.gen_range(50..62) ;
        let x_wlen = rng.gen_range(49..x_length) ; 
        let x_r_triv_len = rng.gen_range(10..x_wlen) ;  
        let ct_x: ParmCiphertext =gen_ct_rtriv_zero(&pu,x_length,x_wlen,x_r_triv_len)? ;
        let m_x = pu.decrypt(&ct_x) ?; 
        let y_length = rng.gen_range(40..x_wlen) ; 
        let y_wlen = rng.gen_range(39..y_length) ; 
        let ct_y:ParmCiphertext = gen_ct_rtriv_custom(&pu,y_length,y_wlen)?  ; 
        let m_y = pu.decrypt(&ct_y) ?; 
        add_check = m_x.checked_add(m_y); 
        if add_check != None  {
            let enc_add_res = ParmArithmetics::add(&pc,&ct_x,&ct_y) ;
            let add_res = pu.decrypt(&enc_add_res)? ;  
            if (m_x+m_y  - add_res )% 4096 ==0  {
                println!("valid test for addition corner case of {} and {}", m_x,m_y) ; 
            } 
            else {
                println!("problem with the addition corner case with {} and {}",m_x,m_y)
             }
        println!("addition corner cases test for {} {} ",m_x,m_y) ; 
        assert_eq! ((m_x as i64 + m_y as i64 - add_res) , 0   ); }}
    }

        
        Ok(()) 
   }

   #[test]
   fn addition_corner_case_3()-> Result<(), Box<dyn Error>>{
       // =================================
       // Addition corner case 3 : |y| > |x| > wlen 
       //  Initialization
       // ---------------------------------
       //  Global Scope
        let par = &params::PARM90__PI_5__D_20__LEN_32;   //     PARM90__PI_5__D_20__LEN_32      PARMXX__TRIVIAL
        // ---------------------------------
        //  Userovo Scope
        let pu = ParmesanUserovo::new(par)?;
        let pub_k = pu.export_pub_keys();
        // ---------------------------------
        //  Cloudovo Scope
        let pc = ParmesanCloudovo::new(par,
                &pub_k,
            );
        // generate 10 random samples 
        for _i in 0..10 {         
        let mut add_check = None ; 
        while add_check ==None { 
            let mut rng = rand::thread_rng() ; 
            let y_length = rng.gen_range(50..62) ; 
            let x_length = rng.gen_range(40..y_length) ;
            let x_wlen = rng.gen_range(39..x_length) ; 
            let y_wlen = rng.gen_range(38..x_wlen) ; 
            let x_r_triv_len = rng.gen_range(10..x_wlen) ;   
            let ct_x: ParmCiphertext =gen_ct_rtriv_zero(&pu,x_length,x_wlen,x_r_triv_len)? ;
            let mx = pu.decrypt(&ct_x) ?; 
            let ct_y:ParmCiphertext = gen_ct_rtriv_custom(&pu,y_length,y_wlen)?  ; 
            let my = pu.decrypt(&ct_y) ?; 
            add_check = mx.checked_add(my); 
            if add_check != None  {
                let enc_add_res = ParmArithmetics::add(&pc,&ct_x,&ct_y) ;
                let add_res = pu.decrypt(&enc_add_res)? ;  
                if mx+my  - add_res  ==0  {
                    println!("valid test for add op of {} and {}", mx,my) ; 
                } 
                else {
                    println!("problem with the add operation of {} and {}",mx,my)
                }
            println!("add test for {} {}",mx,my) ; 
            assert_eq! ((mx as i64 +my as i64 - add_res) , 0   ); }}
        }
            Ok(()) 
   }
   #[test]
   fn addition_corner_case_4()-> Result<(), Box<dyn Error>>{
       // =================================
       // Addition corner case 4 : |x| > |y| > wlen  
       //  Initialization
       // ---------------------------------
       //  Global Scope
        let par = &params::PARM90__PI_5__D_20__LEN_32;   //     PARM90__PI_5__D_20__LEN_32      PARMXX__TRIVIAL
        // ---------------------------------
        //  Userovo Scope
        let pu = ParmesanUserovo::new(par)?;
        let pub_k = pu.export_pub_keys();
        // ---------------------------------
        //  Cloudovo Scope
        let pc = ParmesanCloudovo::new(par,
                &pub_k,
            );
        for _i in 0..10 {
        let mut add_check = None ; 
        while add_check ==None { 
            let mut rng = rand::thread_rng() ; 
            let x_length = rng.gen_range(50..62) ; 
            let y_length = rng.gen_range(49..x_length) ; 
            let y_wlen = rng.gen_range(10..y_length) ; 
            let x_wlen = rng.gen_range(9..y_wlen) ; 
            let x_r_triv_len = rng.gen_range(8..x_wlen) ; 
            let ct_x: ParmCiphertext =gen_ct_rtriv_zero(&pu,x_length,x_wlen,x_r_triv_len)? ;
            let mx = pu.decrypt(&ct_x) ?; 
            let ct_y:ParmCiphertext = gen_ct_rtriv_custom(&pu,y_length,y_wlen)?  ; 
            let my = pu.decrypt(&ct_y) ?; 
            add_check = mx.checked_add(my); 
            if add_check != None  {
                let enc_add_res = ParmArithmetics::add(&pc,&ct_x,&ct_y) ;
                let add_res = pu.decrypt(&enc_add_res)? ;  
                if mx+my  - add_res  ==0  {
                    println!("valid test for add op of {} and {}", mx,my) ; 
                } 
                else {
                    println!("problem with the add operation of {} and {}",mx,my)
                }
            println!("add test for {} {}",mx,my) ; 
            assert_eq! ((mx as i64 +my as i64 - add_res) , 0   ); }}
        }
            Ok(()) 
   }
   #[test]
   fn addition_corner_case_5()-> Result<(), Box<dyn Error>>{
       // =================================
       // Addition corner case 4 : |y| > wlen > |x|  
       //  Initialization
       // ---------------------------------
       //  Global Scope
        let par = &params::PARM90__PI_5__D_20__LEN_32;   //     PARM90__PI_5__D_20__LEN_32      PARMXX__TRIVIAL
        // ---------------------------------
        //  Userovo Scope
        let pu = ParmesanUserovo::new(par)?;
        let pub_k = pu.export_pub_keys();
        // ---------------------------------
        //  Cloudovo Scope
        let pc = ParmesanCloudovo::new(par,
                &pub_k,
            );
        for _i in 0..10 {
        let mut add_check = None ; 
        while add_check ==None { 
            let mut rng = rand::thread_rng() ; 
            let x_length = rng.gen_range(50..61) ; 
            let x_wlen = rng.gen_range(49..x_length) ; 
            let x_r_triv_len = rng.gen_range(10..x_wlen) ;  
            let y_length = rng.gen_range(x_length..62) ; 
            let y_wlen = rng.gen_range(x_wlen..y_length) ; 
            let ct_x: ParmCiphertext =gen_ct_rtriv_zero(&pu,x_length,x_wlen,x_r_triv_len)? ;
            let mx = pu.decrypt(&ct_x) ?; 
            let ct_y:ParmCiphertext = gen_ct_rtriv_custom(&pu,y_length,y_wlen)?  ; 
            let my = pu.decrypt(&ct_y) ?; 
            add_check = mx.checked_add(my); 
            if add_check != None  {
                let enc_add_res = ParmArithmetics::add(&pc,&ct_x,&ct_y) ;
                let add_res = pu.decrypt(&enc_add_res)? ;  
                if mx+my  - add_res  ==0  {
                    println!("valid test for add op of {} and {}", mx,my) ; 
                } 
                else {
                    println!("problem with the add operation of {} and {}",mx,my)
                }
            println!("add test for {} {}",mx,my) ; 
            assert_eq! ((mx as i64 +my as i64 - add_res) , 0   ); }}
        }
            Ok(()) 
   }
#[test]
fn nn() -> Result<(), Box<dyn Error>> {

    #[cfg(not(feature = "sequential"))]
    infobox!("Parallel Neural Network DEMO ({} threads)", rayon::current_num_threads());
    #[cfg(feature = "sequential")]
    infobox!("Sequential Neural Network DEMO");


    // =================================
    //  Initialization

    // ---------------------------------
    //  Global Scope
    let par = &params::PARM90__PI_5__D_20__LEN_32;   //     PARM90__PI_5__D_20__LEN_32      PARMXX__TRIVIAL

    // ---------------------------------
    //  Userovo Scope
    let pu = ParmesanUserovo::new(par)?;
    let pub_k = pu.export_pub_keys();

    const INPUT_BITLEN: usize =   8;
    const INPUT_SIZE:   usize =   6;

    // ---------------------------------
    //  Cloudovo Scope
    let pc = ParmesanCloudovo::new(
        par,
        &pub_k,
    );


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
    let mut intro_text = format!("{}: input layer ({} elements)", String::from("User").bold().yellow(), INPUT_SIZE);
    for (i, mi) in m_in.iter().enumerate() {
        intro_text = format!("{}\nIN[{}] = {}{:08b} ({:4})", intro_text, i, if *mi >= 0 {" "} else {"-"}, (*mi).abs(), mi);
    }
    infoln!("{}", intro_text);


    // =================================
    //  C: Evaluation

    let c_out       = demo_nn().eval(&pc, &c_in);
    let m_out_plain = demo_nn().eval(&pc, &m_in);


    // =================================
    //  U: Decryption

    let mut m_out_homo = Vec::new();
    for ci in c_out {
        m_out_homo.push(pu.decrypt(&ci)?);
    }
    assert_eq!(m_out_homo, m_out_plain) ; 
    Ok(())
}
