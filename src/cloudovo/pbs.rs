use std::error::Error;

#[allow(unused_imports)]
use colored::Colorize;

use concrete_core::prelude::*;

use crate::userovo::keys::PubKeySet;

//
//  X (positive half)
//
pub fn pos_id(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    //TODO resolve trivial case
    if c.dimension == 0 {
        return Ok(c.clone());
    }

    let res = c.bootstrap_with_function(pub_keys.bsk, |x| x, pub_keys.encoder)?
               .keyswitch(pub_keys.ksk)?;

    Ok(res)
}


// =============================================================================
//
//  PI = 5
//

//
//  X (around zero)
//
#[allow(non_snake_case)]
pub fn id__pi_5(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    eval_LUT_5(
        pub_keys,
        c,
        [0.,1.,2.,3.,4.,5.,6.,7.,8.,7.,6.,5.,4.,3.,2.,1.]
    )
}

//
//  X ⋛ ±3
//
#[allow(non_snake_case)]
pub fn f_3__pi_5(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    eval_LUT_5(
        pub_keys,
        c,
        [0.,0.,0.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,0.,0.]
    )
}

//
//  X ⋛ ±4
//
#[allow(non_snake_case)]
pub fn f_4__pi_5(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    eval_LUT_5(
        pub_keys,
        c,
        [0.,0.,0.,0.,1.,1.,1.,1.,1.,1.,1.,1.,1.,0.,0.,0.]
    )
}

//
//  X ⋛ ±5
//
#[allow(non_snake_case)]
pub fn f_5__pi_5(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    eval_LUT_5(
        pub_keys,
        c,
        [0.,0.,0.,0.,0.,1.,1.,1.,1.,1.,1.,1.,0.,0.,0.,0.]
    )
}

//
//  X ≡ ±2 (× val)
//
#[allow(non_snake_case)]
pub fn g_2__pi_5__with_val(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
    val: u32,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    let vf = val as f64;
    eval_LUT_5(
        pub_keys,
        c,
        [0.,0.,vf,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,vf,0.,]
    )
}

//
//  X ⋛ ±1 (× val)
//
#[allow(non_snake_case)]
pub fn f_1__pi_5__with_val(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
    val: u32,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    let vf = val as f64;
    eval_LUT_5(
        pub_keys,
        c,
        [0.,vf,vf,vf,vf,vf,vf,vf,vf,vf,vf,vf,vf,vf,vf,vf]
    )
}

//
//  X ≥ 0 /sgn+/ (× val)
//
#[allow(non_snake_case)]
pub fn f_0__pi_5__with_val(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
    val: u32,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    let vf = val as f64;
    eval_LUT_5(
        pub_keys,
        c,
        [vf,vf,vf,vf,vf,vf,vf,vf,vf,vf,vf,vf,vf,vf,vf,vf]
    )
}

//
//  |X| ≥ 2
//
#[allow(non_snake_case)]
pub fn a_2__pi_5(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    eval_LUT_5(
        pub_keys,
        c,
        [0.,0.,1.,1.,1.,1.,1.,1.,31.,31.,31.,31.,31.,31.,31.,0.]
    )
}

//
//  |X| ≥ 1   (i.e., squaring in {-1,0,1})
//
#[allow(non_snake_case)]
pub fn a_1__pi_5(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    eval_LUT_5(
        pub_keys,
        c,
        [0.,1.,1.,1.,1.,1.,1.,1.,31.,31.,31.,31.,31.,31.,31.,31.]
    )
}

//
//  Multiplication table serialized for 3X + Y
//
//  X·Y | -1 |  0 |  1 |
//  --------------------
//    1 | -1 |  0 |  1 |
//    0 |  0 |  0 |  0 |
//   -1 |  1 |  0 | -1 |
//  --------------------
//
#[allow(non_snake_case)]
pub fn mul_bit__pi_5(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    eval_LUT_5(
        pub_keys,
        c,
        [0.,0.,31.,0.,1.,0.,0.,0.,0.,0.,0.,0.,31.,0.,1.,0.]
    )
}

//
//  ReLU+:
//
//      0   (X ≤ 0)
//  X - 2   (X > 0)
//
#[allow(non_snake_case)]
pub fn relu_plus__pi_5(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    eval_LUT_5(
        pub_keys,
        c,
        [0.,31.,0.,1.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.]
    )
}

//
//  Rounding PBS for 2y + s:
//
//  -1   (2y + s == -3)
//   0   (2y + s \in -2..1)
//   1   (2y + s == 2, 3)
//
#[allow(non_snake_case)]
pub fn round_2y_s__pi_5(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    eval_LUT_5(
        pub_keys,
        c,
        [0.,0.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,0.,0.]
    )
}

//
//  Non-negative
//
//   0   (X < 0)
//   1   (X ≥ 0)
//
#[allow(non_snake_case)]
pub fn nonneg__pi_5(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    let mut h = eval_LUT_5(
        pub_keys,
        c,
        [0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,]      // [1/2, ..., 1/2, -1/2, ..., -1/2]
    )?;
    h.add_half_to_uint_inplace()?;                                              // [  1, ...,   1,    0, ...,    0]
    Ok(h)
}

//
//  Selector for max
//
#[allow(non_snake_case)]
pub fn max_s_2x_6y__pi_5(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    eval_LUT_5(
        pub_keys,
        c,
        //           1            |ovrlap|
        [0.,0.,0.,1.,1.,31.,1.,0., 1.,1., 1.,0.,1.,31.,0.,1.,]
    )
}


// =============================================================================
//
//  Logical (represented with pi = 3)
//

//
//  XOR
//
#[allow(non_snake_case)]
pub fn XOR(
    pub_keys: &PubKeySet,
    x: &LweCiphertext64,
    y: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    // t = 2x + 2y
    let mut t = x.mul_uint_constant(2)?;
    t.add_uint_inplace(y)?; t.add_uint_inplace(y)?;
    // bootstrap
    //FIXME resolve corner values: 1 1 1/-1 -1 .. shift by 1/16 .. pi = 4, change encoding
    let res = t.bootstrap_with_function(pub_keys.bsk, |x| [1.,1.,1.,7.,][x as usize], pub_keys.encoder)?
               .keyswitch(pub_keys.ksk)?;

    Ok(res)
}

//
//  AND
//
#[allow(non_snake_case)]
pub fn AND(
    pub_keys: &PubKeySet,
    x: &LweCiphertext64,
    y: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    // t = x + y
    let t = x.add_uint(y)?;
    // bootstrap
    //FIXME resolve corner values: -1 -1/1 1 1 .. shift by 1/16 .. pi = 4, change encoding
    let res = t.bootstrap_with_function(pub_keys.bsk, |x| [7.,7.,1.,1.,][x as usize], pub_keys.encoder)?
               .keyswitch(pub_keys.ksk)?;

    Ok(res)
}

//
//  XOR3
//
#[allow(non_snake_case)]
pub fn XOR_THREE(
    pub_keys: &PubKeySet,
    x: &LweCiphertext64,
    y: &LweCiphertext64,
    z: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    // t = 2(x + y + z)
    let mut t = x.mul_uint_constant(2)?;
    t.add_uint_inplace(y)?; t.add_uint_inplace(y)?;
    t.add_uint_inplace(z)?; t.add_uint_inplace(z)?;
    // bootstrap
    //FIXME resolve corner values: 1/-1 -1 -1 -1 .. shift by 1/16 .. pi = 4, change encoding
    let res = t.bootstrap_with_function(pub_keys.bsk, |x| [7.,7.,7.,7.,][x as usize], pub_keys.encoder)?
               .keyswitch(pub_keys.ksk)?;

    Ok(res)
}

//
//  2OF3
//
#[allow(non_snake_case)]
pub fn TWO_OF_THREE(
    pub_keys: &PubKeySet,
    x: &LweCiphertext64,
    y: &LweCiphertext64,
    z: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    // t = x + y + z
    let mut t = x.add_uint(y)?;
    t.add_uint_inplace(z)?;
    // bootstrap
    //FIXME resolve corner values: 1/-1 -1 -1 -1 .. shift by 1/16 .. pi = 4, change encoding
    let res = t.bootstrap_with_function(pub_keys.bsk, |x| [1.,1.,1.,1.,][x as usize], pub_keys.encoder)?
               .keyswitch(pub_keys.ksk)?;

    Ok(res)
}


// =============================================================================
//
//  Special function for Scenario C
//

//
//  X ≥ 2*4
//
#[allow(non_snake_case)]
pub fn c_4__pi_2x4(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    //TODO resolve trivial case
    if c.dimension == 0 {
        return Ok(c.clone());
    }

    let res = c.bootstrap_with_function(pub_keys.bsk, |x| [15.,15.,15.,15.,15.,15.,15.,15.,][x as usize], pub_keys.encoder)?
               .keyswitch(pub_keys.ksk)?;

    Ok(res)
}


// =============================================================================
//
//  PI = 3
//

//
//  X (around zero)
//
#[allow(non_snake_case)]
pub fn id__pi_3(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    //TODO resolve trivial case
    if c.dimension == 0 {
        return Ok(c.clone());
    }

    let res = c.bootstrap_with_function(pub_keys.bsk, |x| [0.,1.,2.,1.][x as usize], pub_keys.encoder)?
               .keyswitch(pub_keys.ksk)?;

    Ok(res)
}

//
//  X ⋛ ±1
//
#[allow(non_snake_case)]
pub fn f_1__pi_3(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    //TODO resolve trivial case
    if c.dimension == 0 {
        return Ok(c.clone());
    }

    let res = c.bootstrap_with_function(pub_keys.bsk, |x| [0.,1.,1.,1.,][x as usize], pub_keys.encoder)?
               .keyswitch(pub_keys.ksk)?;

    Ok(res)
}

//
//  X ⋛ ±2
//
#[allow(non_snake_case)]
pub fn f_2__pi_3(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    //TODO resolve trivial case
    if c.dimension == 0 {
        return Ok(c.clone());
    }

    let res = c.bootstrap_with_function(pub_keys.bsk, |x| [0.,0.,1.,0.,][x as usize], pub_keys.encoder)?
               .keyswitch(pub_keys.ksk)?;

    Ok(res)
}

//
//  X ≡ ±1
//
#[allow(non_snake_case)]
pub fn g_1__pi_3(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    //TODO resolve trivial case
    if c.dimension == 0 {
        return Ok(c.clone());
    }

    let res = c.bootstrap_with_function(pub_keys.bsk, |x| [0.,1.,0.,1.,][x as usize], pub_keys.encoder)?
               .keyswitch(pub_keys.ksk)?;

    Ok(res)
}

//
//  X ≡ ±2
//
#[allow(non_snake_case)]
pub fn g_2__pi_3(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    // for π = 3 .. equivalent to X ⋛ ±2
    f_2__pi_3(pub_keys, c)
}


// =============================================================================
//
//  PI = 4
//

//
//  X (around zero)
//
#[allow(non_snake_case)]
pub fn id__pi_4(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    //TODO resolve trivial case
    if c.dimension == 0 {
        return Ok(c.clone());
    }

    let res = c.bootstrap_with_function(pub_keys.bsk, |x| [0.,1.,2.,3.,4.,3.,2.,1.][x as usize], pub_keys.encoder)?
               .keyswitch(pub_keys.ksk)?;

    Ok(res)
}

//
//  X ⋛ ±2
//
#[allow(non_snake_case)]
pub fn f_2__pi_4(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    //TODO resolve trivial case
    if c.dimension == 0 {
        return Ok(c.clone());
    }

    let res = c.bootstrap_with_function(pub_keys.bsk, |x| [0.,0.,1.,1.,1.,1.,1.,0.,][x as usize], pub_keys.encoder)?
               .keyswitch(pub_keys.ksk)?;

    Ok(res)
}

//
//  X ⋛ ±3
//
#[allow(non_snake_case)]
pub fn f_3__pi_4(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    //TODO resolve trivial case
    if c.dimension == 0 {
        return Ok(c.clone());
    }

    let res = c.bootstrap_with_function(pub_keys.bsk, |x| [0.,0.,0.,1.,1.,1.,0.,0.,][x as usize], pub_keys.encoder)?
               .keyswitch(pub_keys.ksk)?;

    Ok(res)
}

//
//  X ≡ ±2
//
#[allow(non_snake_case)]
pub fn g_2__pi_4(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    //TODO resolve trivial case
    if c.dimension == 0 {
        return Ok(c.clone());
    }

    let res = c.bootstrap_with_function(pub_keys.bsk, |x| [0.,0.,1.,0.,0.,0.,1.,0.,][x as usize], pub_keys.encoder)?
               .keyswitch(pub_keys.ksk)?;

    Ok(res)
}

//
//  X ≡ ±1 (× val)
//
#[allow(non_snake_case)]
pub fn g_1__pi_4__with_val(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
    val: u32,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    //TODO resolve trivial case
    if c.dimension == 0 {
        return Ok(c.clone());
    }

    let vf = val as f64;

    let res = c.bootstrap_with_function(pub_keys.bsk, |x| [0.,vf,0.,0.,0.,0.,0.,vf][x as usize], pub_keys.encoder)?
               .keyswitch(pub_keys.ksk)?;

    Ok(res)
}


// =============================================================================
//
//  PI = 7
//

//
//  X (around zero)
//
#[allow(non_snake_case)]
pub fn id__pi_7(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    //TODO resolve trivial case
    if c.dimension == 0 {
        return Ok(c.clone());
    }

    let res = c.bootstrap_with_function(pub_keys.bsk, |x| [0.,1.,2.,3.,4.,5.,6.,7.,8.,9.,10.,11.,12.,13.,14.,15.,16.,17.,18.,19.,20.,21.,22.,23.,24.,25.,26.,27.,28.,29.,30.,31.,32.,31.,30.,29.,28.,27.,26.,25.,24.,23.,22.,21.,20.,19.,18.,17.,16.,15.,14.,13.,12.,11.,10.,9.,8.,7.,6.,5.,4.,3.,2.,1.][x as usize], pub_keys.encoder)?
               .keyswitch(pub_keys.ksk)?;

    Ok(res)
}

//
//  X ⋛ ±14
//
#[allow(non_snake_case)]
pub fn f_14__pi_7(
    pub_keys: &PubKeySet,
    c: &LweCiphertext64,
) -> Result<LweCiphertext64, Box<dyn Error>> {
    //TODO resolve trivial case
    if c.dimension == 0 {
        return Ok(c.clone());
    }

    let res = c.bootstrap_with_function(pub_keys.bsk, |x| [0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,][x as usize], pub_keys.encoder)?
               .keyswitch(pub_keys.ksk)?;

    Ok(res)
}


// =============================================================================
//
//  Eval LUT
//

#[allow(non_snake_case)]
fn eval_LUT_5(
    pub_keys: &PubKeySet,
    ci: &LweCiphertext64,
    lut: [f64; 1 << (5-1)],
) -> Result<LweCiphertext64, Box<dyn Error>> {
    // resolve trivial case
    if ci.dimension == 0 {
        let  m = ci.decrypt_uint_triv()?;
        let fm = if m < (1 << (5-1)) { lut[m as usize] }
            else if m < (1 << 5) { -lut[(m as i32 - (1 << (5-1))) as usize] }
            else {return Err(format!("Word m = {} does not fit 5-bit LUT.", m).into())};
        // check if LUT value is "half-ish"
        let fm_half = (2.0 * fm) as i32 & 1 == 1;
                              // remove half
        let fm_u = ((if fm_half {fm - 0.5} else {fm} as i32) & ((1 << 5) - 1)) as u32;
        if fm_half {
            let mut res = LweCiphertext64::encrypt_uint_triv(fm_u, &pub_keys.encoder)?;
            // add half back
            res.add_half_to_uint_inplace()?;
            Ok(res)
        } else {
            Ok(LweCiphertext64::encrypt_uint_triv(fm_u, &pub_keys.encoder)?)
        }
    } else {
        //PBS unsafe { crate::NBS += 1; }

        //FIXME
        let accumulator = create_accum(func, &bootstrapping_key, bit_precision, &mut engine)?;

        let mut engine = CoreEngine::new(())?;
        let zero_plaintext = engine.create_plaintext(&0_u64)?;
        let mut buffer_lwe_after_pbs = engine.trivially_encrypt_lwe_ciphertext(
            key_switching_key.output_lwe_dimension().to_lwe_size(),
            &zero_plaintext,
        )?;
        // Compute a key switch
        engine.discard_keyswitch_lwe_ciphertext(
            &mut buffer_lwe_after_pbs,
            ci,
            &key_switching_key,
        )?;
        // Compute a bootstrap
        engine.discard_bootstrap_lwe_ciphertext(
            ci,
            &buffer_lwe_after_pbs,
            &accumulator,
            &bootstrapping_key,
        )?;

        //~ Ok(c.bootstrap_with_function(pub_keys.bsk, |x| lut[x as usize], pub_keys.encoder)?
            //~ .keyswitch(pub_keys.ksk)?)
    }
}

// create accumulator
fn create_accum<F>(
    func: F,
    bootstrapping_key: &FourierLweBootstrapKey64,
    bit_precision: usize,
) -> Result<GlweCiphertext64, Box<dyn std::error::Error>>
where F: Fn(u64) -> u64 {
    let mut engine = CoreEngine::new(())?;
    let delta = 1 << (64 - bit_precision);
    let mut accumulator_u64 = vec![0_u64; bootstrapping_key.polynomial_size().0];
    let modulus_sup = 1 << (bit_precision - 1);   // half of values is to be set .. 16
    let box_size = bootstrapping_key.polynomial_size().0 / modulus_sup;
    let half_box_size = box_size / 2;
    // fill accumulator
    for i in 0..modulus_sup {
        let index = i as usize * box_size;
        accumulator_u64[index..index + box_size]
            .iter_mut()
            .for_each(|a| *a = func(i as u64) * delta);
    }
    // Negate the first half_box_size coefficients
    for a_i in accumulator_u64[0..half_box_size].iter_mut() {
        *a_i = (*a_i).wrapping_neg();
    }
    // Rotate the accumulator
    accumulator_u64.rotate_left(half_box_size);
    // init accumulator as GLWE
    let accumulator_plaintext = engine.create_plaintext_vector(&accumulator_u64)?;

    let accumulator = engine.trivially_encrypt_glwe_ciphertext(
        bootstrapping_key.glwe_dimension().to_glwe_size(),
        &accumulator_plaintext,
    )?;

    Ok(accumulator)
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
    //~ c: &LweCiphertext64,
//~ ) -> LweCiphertext64 {
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
