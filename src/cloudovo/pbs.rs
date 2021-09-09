use std::error::Error;

use concrete::LWE;
#[allow(unused_imports)]
use colored::Colorize;
use crate::userovo::keys::PubKeySet;

//TODO implement evaluation for dimension == 0 (should not be needed at the moment)

//
//  X (around zero)
//
pub fn id(
    pub_keys: &PubKeySet,
    c: &LWE,
) -> Result<LWE, Box<dyn Error>> {
    // resolve trivial case
    if c.dimension == 0 {
        return Ok(c.clone());
    }

    //~ measure_duration!(
        //~ ["PBS: Identity (around zero)"],
        //~ [
            let res = c.bootstrap_with_function(pub_keys.bsk, |x| [0.,1.,2.,3.,4.,5.,6.,7.,8.,7.,6.,5.,4.,3.,2.,1.][x as usize], pub_keys.encoder)?
                       .keyswitch(pub_keys.ksk)?;
        //~ ]
    //~ );

    Ok(res)
}

//
//  X (positive half)
//
pub fn pos_id(
    pub_keys: &PubKeySet,
    c: &LWE,
) -> Result<LWE, Box<dyn Error>> {
    // resolve trivial case
    if c.dimension == 0 {
        return Ok(c.clone());
    }

    //~ measure_duration!(
        //~ ["PBS: Positive identity"],
        //~ [
            let res = c.bootstrap_with_function(pub_keys.bsk, |x| x, pub_keys.encoder)?
                       .keyswitch(pub_keys.ksk)?;
        //~ ]
    //~ );

    Ok(res)
}

//
//  X ⋛ ±4
//
#[allow(non_snake_case)]
pub fn f_4__pi_5(
    pub_keys: &PubKeySet,
    c: &LWE,
) -> Result<LWE, Box<dyn Error>> {
    // resolve trivial case
    if c.dimension == 0 {
        return Ok(c.clone());
    }

    //~ measure_duration!(
        //~ ["PBS: X ⋛ ±4 (for π = 5)"],
        //~ [
            let res = c.bootstrap_with_function(pub_keys.bsk, |x| [0.,0.,0.,0.,1.,1.,1.,1.,1.,1.,1.,1.,1.,0.,0.,0.][x as usize], pub_keys.encoder)?
                       .keyswitch(pub_keys.ksk)?;
        //~ ]
    //~ );

    Ok(res)
}

//
//  X ⋛ ±1 (× val)
//
#[allow(non_snake_case)]
pub fn f_1__pi_5__with_val(
    pub_keys: &PubKeySet,
    c: &LWE,
    val: u32,
) -> Result<LWE, Box<dyn Error>> {
    // resolve trivial case
    if c.dimension == 0 {
        return Ok(c.clone());
    }

    let val_f = val as f64;
    //~ measure_duration!(
        //~ ["PBS: X ⋛ ±1 /sgn/ (× val, for π = 5)"],
        //~ [
            let res = c.bootstrap_with_function(pub_keys.bsk, |x| [0.,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f][x as usize], pub_keys.encoder)?
                       .keyswitch(pub_keys.ksk)?;
        //~ ]
    //~ );

    Ok(res)
}

//
//  X ≥ 0 /sgn+/ (× val)
//
#[allow(non_snake_case)]
pub fn f_0__pi_5__with_val(
    pub_keys: &PubKeySet,
    c: &LWE,
    val: u32,
) -> Result<LWE, Box<dyn Error>> {
    //TODO resolve trivial case
    //~ if c.dimension == 0 {
        //~ return Ok(LWE that trivially encrypts val_f);
    //~ }

    let val_f = val as f64;
    //~ measure_duration!(
        //~ ["PBS: X ≥ 0 /sgn+/ (× val, for π = 5)"],
        //~ [
            let res = c.bootstrap_with_function(pub_keys.bsk, |x| [val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f][x as usize], pub_keys.encoder)?
                       .keyswitch(pub_keys.ksk)?;
        //~ ]
    //~ );

    Ok(res)
}

//
//  |X| ≥ 2
//
#[allow(non_snake_case)]
pub fn a_2__pi_5(
    pub_keys: &PubKeySet,
    c: &LWE,
) -> Result<LWE, Box<dyn Error>> {
    // resolve trivial case
    if c.dimension == 0 {
        return Ok(c.clone());
    }

    //~ measure_duration!(
        //~ ["PBS: |X| ≥ 2 (for π = 5)"],
        //~ [
            let res = c.bootstrap_with_function(pub_keys.bsk, |x| [0.,0.,1.,1.,1.,1.,1.,1.,31.,31.,31.,31.,31.,31.,31.,0.][x as usize], pub_keys.encoder)?
                       .keyswitch(pub_keys.ksk)?;
        //~ ]
    //~ );

    Ok(res)
}

//
//  |X| ≥ 1   (i.e., squaring)
//
#[allow(non_snake_case)]
pub fn a_1__pi_5(
    pub_keys: &PubKeySet,
    c: &LWE,
) -> Result<LWE, Box<dyn Error>> {
    // resolve trivial case
    if c.dimension == 0 {
        return Ok(c.clone());
    }

    //~ measure_duration!(
        //~ ["PBS: |X| ≥ 1 (for π = 5)"],
        //~ [
            let res = c.bootstrap_with_function(pub_keys.bsk, |x| [0.,1.,1.,1.,1.,1.,1.,1.,31.,31.,31.,31.,31.,31.,31.,31.][x as usize], pub_keys.encoder)?
                       .keyswitch(pub_keys.ksk)?;
        //~ ]
    //~ );

    Ok(res)
}

//
//  ReLU+:
//
//      0   (X < 0)
//  X - 2   (X > 0)
//
#[allow(non_snake_case)]
pub fn relu_plus__pi_5(
    pub_keys: &PubKeySet,
    c: &LWE,
) -> Result<LWE, Box<dyn Error>> {
    //~ measure_duration!(
        //~ ["PBS: ReLU+ (for π = 5)"],
        //~ [
            let res = c.bootstrap_with_function(pub_keys.bsk, |x| [0.,31.,0.,1.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.][x as usize], pub_keys.encoder)?
                       .keyswitch(pub_keys.ksk)?;
        //~ ]
    //~ );

    Ok(res)
}

//
//  XOR
//
#[allow(non_snake_case)]
pub fn XOR(
    pub_keys: &PubKeySet,
    x: &LWE,
    y: &LWE,
) -> Result<LWE, Box<dyn Error>> {
    //~ measure_duration!(
        //~ ["PBS: XOR"],
        //~ [
            // t = 2x + 2y
            let mut t = x.mul_uint_constant(2)?;
            t.add_uint_inplace(y)?; t.add_uint_inplace(y)?;
            // bootstrap
            //FIXME resolve corner values: 1 1 1/-1 -1 .. shift by 1/16 .. pi = 4, change encoding
            let res = t.bootstrap_with_function(pub_keys.bsk, |x| [1.,1.,1.,7.,][x as usize], pub_keys.encoder)?
                       .keyswitch(pub_keys.ksk)?;
        //~ ]
    //~ );

    Ok(res)
}

//
//  AND
//
#[allow(non_snake_case)]
pub fn AND(
    pub_keys: &PubKeySet,
    x: &LWE,
    y: &LWE,
) -> Result<LWE, Box<dyn Error>> {
    //~ measure_duration!(
        //~ ["PBS: AND"],
        //~ [
            // t = x + y
            let t = x.add_uint(y)?;
            // bootstrap
            //FIXME resolve corner values: -1 -1/1 1 1 .. shift by 1/16 .. pi = 4, change encoding
            let res = t.bootstrap_with_function(pub_keys.bsk, |x| [7.,7.,1.,1.,][x as usize], pub_keys.encoder)?
                       .keyswitch(pub_keys.ksk)?;
        //~ ]
    //~ );

    Ok(res)
}

//
//  XOR3
//
#[allow(non_snake_case)]
pub fn XOR_THREE(
    pub_keys: &PubKeySet,
    x: &LWE,
    y: &LWE,
    z: &LWE,
) -> Result<LWE, Box<dyn Error>> {
    //~ measure_duration!(
        //~ ["PBS: XOR3"],
        //~ [
            // t = 2(x + y + z)
            let mut t = x.mul_uint_constant(2)?;
            t.add_uint_inplace(y)?; t.add_uint_inplace(y)?;
            t.add_uint_inplace(z)?; t.add_uint_inplace(z)?;
            // bootstrap
            //FIXME resolve corner values: 1/-1 -1 -1 -1 .. shift by 1/16 .. pi = 4, change encoding
            let res = t.bootstrap_with_function(pub_keys.bsk, |x| [7.,7.,7.,7.,][x as usize], pub_keys.encoder)?
                       .keyswitch(pub_keys.ksk)?;
        //~ ]
    //~ );

    Ok(res)
}

//
//  2OF3
//
#[allow(non_snake_case)]
pub fn TWO_OF_THREE(
    pub_keys: &PubKeySet,
    x: &LWE,
    y: &LWE,
    z: &LWE,
) -> Result<LWE, Box<dyn Error>> {
    //~ measure_duration!(
        //~ ["PBS: 2OF3"],
        //~ [
            // t = x + y + z
            let mut t = x.add_uint(y)?;
            t.add_uint_inplace(z)?;
            // bootstrap
            //FIXME resolve corner values: 1/-1 -1 -1 -1 .. shift by 1/16 .. pi = 4, change encoding
            let res = t.bootstrap_with_function(pub_keys.bsk, |x| [1.,1.,1.,1.,][x as usize], pub_keys.encoder)?
                       .keyswitch(pub_keys.ksk)?;
        //~ ]
    //~ );

    Ok(res)
}

//
//  X ≥ 2*4
//
#[allow(non_snake_case)]
pub fn c_4__pi_2x4(
    pub_keys: &PubKeySet,
    c: &LWE,
) -> Result<LWE, Box<dyn Error>> {
    // resolve trivial case
    if c.dimension == 0 {
        return Ok(c.clone());
    }

    //~ measure_duration!(
        //~ ["PBS: X ≥ 2*4 (for π = 4)"],
        //~ [
            let mut res = c.bootstrap_with_function(pub_keys.bsk, |x| [15.,15.,15.,15.,15.,15.,15.,15.,][x as usize], pub_keys.encoder)?
                           .keyswitch(pub_keys.ksk)?;
        //~ ]
    //~ );

    Ok(res)
}



// zasrane, zamrdane ... http://milujupraci.cz/#29

//~ pub struct Lut<'a> {
    //~ pub title:  String,
    //~ pub lut:    &'a (dyn Fn(f64) -> f64),
//~ }

//~ const lut_ID: dyn Fn(f64) -> f64 = |x| x;

//~ pub const ID: Lut = Lut {
    //~ title:  "Identity",
    //~ lut:    &lut_ID,
//~ };
//~ pub const F_1: Lut = Lut {
    //~ title:  "X ⋛ ±1",
    //~ lut:    |x| x * x,
//~ };
//~ pub const MY_LUT: Lut = Lut {
    //~ title:  "My LUT",
    //~ lut:    |x| [4.,3.,2.,1.,0.,5.,6.,7.,8.,9.,10.,11.,12.,13.,14.,15.][x as usize],
//~ };

//~ pub fn with_lut(
    //~ lut: &Lut,
    //~ pub_keys: &PubKeySet,
    //~ c: &LWE,
//~ ) -> LWE {
    //~ measure_duration!(
        //~ ["PBS: Identity"],
        //~ [let res = c.bootstrap_with_function(pub_keys.bsk, |x| x*x, pub_keys.encoder)?
                    //~ .keyswitch(pub_keys.ksk)?;]
    //~ );

    //~ res
//~ }

// try LUT
//~ let lut = |x| [1, 2, 3, 4, 5][x];
//~ let var = 3;
//~ println!("LUT({}) = {}", var, lut(var));
