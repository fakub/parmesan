use std::error::Error;

#[allow(unused_imports)]
use colored::Colorize;

use concrete_core::prelude::*;

use crate::ciphertexts::ParmEncrWord;
use crate::ParmesanCloudovo;

//~ //
//~ //  X (positive half)
//~ //
//~ pub fn pos_id(
    //~ pc: &ParmesanCloudovo,
    //~ c: &ParmEncrWord,
//~ ) -> Result<ParmEncrWord, Box<dyn Error>> {
    //~ //TODO resolve trivial case
    //~ if c.dimension == 0 {
        //~ return Ok(c.clone());
    //~ }

    //~ let res = c.bootstrap_with_function(pc.bsk, |x| x, pc.encoder)?
               //~ .keyswitch(pc.ksk)?;

    //~ Ok(res)
//~ }


// =============================================================================
//
//  Eval LUT 5
//

#[allow(non_snake_case)]
fn eval_LUT_5_uint(
    pc: &ParmesanCloudovo,
    ci: &ParmEncrWord,
    lut: [u64; 1 << (5-1)],
) -> Result<ParmEncrWord, Box<dyn Error>> {
    let mut lut_f = [0f64; 1 << (5-1)];
    for (lu, lf) in lut.iter().zip(lut_f.iter_mut()) {
        *lf = *lu as f64;
    }

    eval_LUT_5_float(
        pc,
        ci,
        lut_f,
    )
}

#[allow(non_snake_case)]
fn eval_LUT_5_float(
    pc: &ParmesanCloudovo,
    ci: &ParmEncrWord,
    lut: [f64; 1 << (5-1)],
) -> Result<ParmEncrWord, Box<dyn Error>> {
    // resolve trivial case
    //FIXME
    if ci.is_triv() {
        let  m = ci.decrypt_word_pos(&pc.params, None)?;
        let fm = if m < (1 << (5-1)) { lut[m as usize] }
            else if m < (1 << 5) { -lut[(m as i32 - (1 << (5-1))) as usize] }
            else {return Err(format!("Word m = {} does not fit 5-bit LUT.", m).into())};
        // check if LUT value is "half-ish"
        let fm_half = (2.0 * fm) as i32 & 1 == 1;
                              // remove half
        let fm_u = ((if fm_half {fm - 0.5} else {fm} as i32) & ((1 << 5) - 1)) as u32;
        if fm_half {
            let mut res = ParmEncrWord::encrypt_word_triv(&pc.params, fm_u as i32)?;
            // add half back
            res.add_half_inplace(&pc.params)?;
            Ok(res)
        } else {
            Ok(ParmEncrWord::encrypt_word_triv(&pc.params, fm_u as i32)?)
        }
    } else {
        //PBS unsafe { crate::NBS += 1; }

        let mut res = ci.0.clone();

        let mut engine = CoreEngine::new(())?;
        let accumulator = create_accum(|x| lut[x as usize], &pc.pub_keys.bsk, pc.params.bit_precision)?;

        let zero_plaintext = engine.create_plaintext(&0_u64)?;   //TODO : Plaintext64 needed?
        let mut buffer_lwe_after_pbs = engine.trivially_encrypt_lwe_ciphertext(
            pc.pub_keys.ksk.output_lwe_dimension().to_lwe_size(), // prepare space for the results
            &zero_plaintext,
        )?;
        // Compute a key switch
        engine.discard_keyswitch_lwe_ciphertext(
            &mut buffer_lwe_after_pbs,
            &mut res,
            &pc.pub_keys.ksk,
        )?;
        // Compute a bootstrap
        engine.discard_bootstrap_lwe_ciphertext(
            &mut res,
            &buffer_lwe_after_pbs,
            &accumulator,
            &pc.pub_keys.bsk,
        )?;

        Ok(ParmEncrWord(res))
    }
}

// create accumulator
fn create_accum<F>(
    func: F,
    bootstrapping_key: &FourierLweBootstrapKey64,
    bit_precision: usize,
) -> Result<GlweCiphertext64, Box<dyn std::error::Error>>
where F: Fn(usize) -> f64 {
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
            .for_each(|a| *a = (func(i) * delta as f64).round() as u64);
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
        bootstrapping_key.glwe_dimension().to_glwe_size(), // prepare space for the results
        &accumulator_plaintext,
    )?;

    Ok(accumulator)
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
    pc: &ParmesanCloudovo,
    c: &ParmEncrWord,
) -> Result<ParmEncrWord, Box<dyn Error>> {
    eval_LUT_5_uint(
        pc,
        c,
        [0,1,2,3,4,5,6,7,8,7,6,5,4,3,2,1]
    )
}

//
//  X ⋛ ±3
//
#[allow(non_snake_case)]
pub fn f_3__pi_5(
    pc: &ParmesanCloudovo,
    c: &ParmEncrWord,
) -> Result<ParmEncrWord, Box<dyn Error>> {
    eval_LUT_5_uint(
        pc,
        c,
        [0,0,0,1,1,1,1,1,1,1,1,1,1,1,0,0]
    )
}

//
//  X ⋛ ±4
//
#[allow(non_snake_case)]
pub fn f_4__pi_5(
    pc: &ParmesanCloudovo,
    c: &ParmEncrWord,
) -> Result<ParmEncrWord, Box<dyn Error>> {
    eval_LUT_5_uint(
        pc,
        c,
        [0,0,0,0,1,1,1,1,1,1,1,1,1,0,0,0]
    )
}

//
//  X ⋛ ±5
//
#[allow(non_snake_case)]
pub fn f_5__pi_5(
    pc: &ParmesanCloudovo,
    c: &ParmEncrWord,
) -> Result<ParmEncrWord, Box<dyn Error>> {
    eval_LUT_5_uint(
        pc,
        c,
        [0,0,0,0,0,1,1,1,1,1,1,1,0,0,0,0]
    )
}

//
//  X ≡ ±2 (× val)
//
#[allow(non_snake_case)]
pub fn g_2__pi_5__with_val(
    pc: &ParmesanCloudovo,
    c: &ParmEncrWord,
    val: u64,
) -> Result<ParmEncrWord, Box<dyn Error>> {
    eval_LUT_5_uint(
        pc,
        c,
        [0,0,val,0,0,0,0,0,0,0,0,0,0,0,val,0,]
    )
}

//
//  X ⋛ ±1 (× val)
//
#[allow(non_snake_case)]
pub fn f_1__pi_5__with_val(
    pc: &ParmesanCloudovo,
    c: &ParmEncrWord,
    val: u64,
) -> Result<ParmEncrWord, Box<dyn Error>> {
    eval_LUT_5_uint(
        pc,
        c,
        [0,val,val,val,val,val,val,val,val,val,val,val,val,val,val,val]
    )
}

//
//  X ≥ 0 /sgn+/ (× val)
//
#[allow(non_snake_case)]
pub fn f_0__pi_5__with_val(
    pc: &ParmesanCloudovo,
    c: &ParmEncrWord,
    val: u64,
) -> Result<ParmEncrWord, Box<dyn Error>> {
    eval_LUT_5_uint(
        pc,
        c,
        [val,val,val,val,val,val,val,val,val,val,val,val,val,val,val,val]
    )
}

//
//  |X| ≥ 2
//
#[allow(non_snake_case)]
pub fn a_2__pi_5(
    pc: &ParmesanCloudovo,
    c: &ParmEncrWord,
) -> Result<ParmEncrWord, Box<dyn Error>> {
    eval_LUT_5_uint(
        pc,
        c,
        [0,0,1,1,1,1,1,1,31,31,31,31,31,31,31,0]
    )
}

//
//  |X| ≥ 1   (i.e., squaring in {-1,0,1})
//
#[allow(non_snake_case)]
pub fn a_1__pi_5(
    pc: &ParmesanCloudovo,
    c: &ParmEncrWord,
) -> Result<ParmEncrWord, Box<dyn Error>> {
    eval_LUT_5_uint(
        pc,
        c,
        [0,1,1,1,1,1,1,1,31,31,31,31,31,31,31,31]
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
    pc: &ParmesanCloudovo,
    c: &ParmEncrWord,
) -> Result<ParmEncrWord, Box<dyn Error>> {
    eval_LUT_5_uint(
        pc,
        c,
        [0,0,31,0,1,0,0,0,0,0,0,0,31,0,1,0]
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
    pc: &ParmesanCloudovo,
    c: &ParmEncrWord,
) -> Result<ParmEncrWord, Box<dyn Error>> {
    eval_LUT_5_uint(
        pc,
        c,
        [0,31,0,1,0,0,0,0,0,0,0,0,0,0,0,0]
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
    pc: &ParmesanCloudovo,
    c: &ParmEncrWord,
) -> Result<ParmEncrWord, Box<dyn Error>> {
    eval_LUT_5_uint(
        pc,
        c,
        [0,0,1,1,1,1,1,1,1,1,1,1,1,1,0,0]
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
    pc: &ParmesanCloudovo,
    c: &ParmEncrWord,
) -> Result<ParmEncrWord, Box<dyn Error>> {
    let mut h = eval_LUT_5_float(
        pc,
        c,
        [0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,]      // [1/2, ..., 1/2, -1/2, ..., -1/2]
    )?;
    h.add_half_inplace(&pc.params)?;                                            // [  1, ...,   1,    0, ...,    0]
    Ok(h)
}

//
//  Selector for max
//
#[allow(non_snake_case)]
pub fn max_s_2x_6y__pi_5(
    pc: &ParmesanCloudovo,
    c: &ParmEncrWord,
) -> Result<ParmEncrWord, Box<dyn Error>> {
    eval_LUT_5_uint(
        pc,
        c,
        //           1            |ovrlap|
        [0,0,0,1,1,31,1,0, 1,1, 1,0,1,31,0,1,]
    )
}


//~ // =============================================================================
//~ //
//~ //  Logical (represented with pi = 3)
//~ //

//~ //
//~ //  XOR
//~ //
//~ #[allow(non_snake_case)]
//~ pub fn XOR(
    //~ pc: &ParmesanCloudovo,
    //~ x: &ParmEncrWord,
    //~ y: &ParmEncrWord,
//~ ) -> Result<ParmEncrWord, Box<dyn Error>> {
    //~ // t = 2x + 2y
    //~ let mut t = x.mul_uint_constant(2)?;
    //~ t.add_uint_inplace(y)?; t.add_uint_inplace(y)?;
    //~ // bootstrap
    //~ //FIXME resolve corner values: 1 1 1/-1 -1 .. shift by 1/16 .. pi = 4, change encoding
    //~ let res = t.bootstrap_with_function(pc.bsk, |x| [1.,1.,1.,7.,][x as usize], pc.encoder)?
               //~ .keyswitch(pc.ksk)?;

    //~ Ok(res)
//~ }

//~ //
//~ //  AND
//~ //
//~ #[allow(non_snake_case)]
//~ pub fn AND(
    //~ pc: &ParmesanCloudovo,
    //~ x: &ParmEncrWord,
    //~ y: &ParmEncrWord,
//~ ) -> Result<ParmEncrWord, Box<dyn Error>> {
    //~ // t = x + y
    //~ let t = x.add_uint(y)?;
    //~ // bootstrap
    //~ //FIXME resolve corner values: -1 -1/1 1 1 .. shift by 1/16 .. pi = 4, change encoding
    //~ let res = t.bootstrap_with_function(pc.bsk, |x| [7.,7.,1.,1.,][x as usize], pc.encoder)?
               //~ .keyswitch(pc.ksk)?;

    //~ Ok(res)
//~ }

//~ //
//~ //  XOR3
//~ //
//~ #[allow(non_snake_case)]
//~ pub fn XOR_THREE(
    //~ pc: &ParmesanCloudovo,
    //~ x: &ParmEncrWord,
    //~ y: &ParmEncrWord,
    //~ z: &ParmEncrWord,
//~ ) -> Result<ParmEncrWord, Box<dyn Error>> {
    //~ // t = 2(x + y + z)
    //~ let mut t = x.mul_uint_constant(2)?;
    //~ t.add_uint_inplace(y)?; t.add_uint_inplace(y)?;
    //~ t.add_uint_inplace(z)?; t.add_uint_inplace(z)?;
    //~ // bootstrap
    //~ //FIXME resolve corner values: 1/-1 -1 -1 -1 .. shift by 1/16 .. pi = 4, change encoding
    //~ let res = t.bootstrap_with_function(pc.bsk, |x| [7.,7.,7.,7.,][x as usize], pc.encoder)?
               //~ .keyswitch(pc.ksk)?;

    //~ Ok(res)
//~ }

//~ //
//~ //  2OF3
//~ //
//~ #[allow(non_snake_case)]
//~ pub fn TWO_OF_THREE(
    //~ pc: &ParmesanCloudovo,
    //~ x: &ParmEncrWord,
    //~ y: &ParmEncrWord,
    //~ z: &ParmEncrWord,
//~ ) -> Result<ParmEncrWord, Box<dyn Error>> {
    //~ // t = x + y + z
    //~ let mut t = x.add_uint(y)?;
    //~ t.add_uint_inplace(z)?;
    //~ // bootstrap
    //~ //FIXME resolve corner values: 1/-1 -1 -1 -1 .. shift by 1/16 .. pi = 4, change encoding
    //~ let res = t.bootstrap_with_function(pc.bsk, |x| [1.,1.,1.,1.,][x as usize], pc.encoder)?
               //~ .keyswitch(pc.ksk)?;

    //~ Ok(res)
//~ }


//~ // =============================================================================
//~ //
//~ //  Special function for Scenario C
//~ //

//~ //
//~ //  X ≥ 2*4
//~ //
//~ #[allow(non_snake_case)]
//~ pub fn c_4__pi_2x4(
    //~ pc: &ParmesanCloudovo,
    //~ c: &ParmEncrWord,
//~ ) -> Result<ParmEncrWord, Box<dyn Error>> {
    //~ //TODO resolve trivial case
    //~ if c.dimension == 0 {
        //~ return Ok(c.clone());
    //~ }

    //~ let res = c.bootstrap_with_function(pc.bsk, |x| [15.,15.,15.,15.,15.,15.,15.,15.,][x as usize], pc.encoder)?
               //~ .keyswitch(pc.ksk)?;

    //~ Ok(res)
//~ }


//~ // =============================================================================
//~ //
//~ //  PI = 3
//~ //

//~ //
//~ //  X (around zero)
//~ //
//~ #[allow(non_snake_case)]
//~ pub fn id__pi_3(
    //~ pc: &ParmesanCloudovo,
    //~ c: &ParmEncrWord,
//~ ) -> Result<ParmEncrWord, Box<dyn Error>> {
    //~ //TODO resolve trivial case
    //~ if c.dimension == 0 {
        //~ return Ok(c.clone());
    //~ }

    //~ let res = c.bootstrap_with_function(pc.bsk, |x| [0.,1.,2.,1.][x as usize], pc.encoder)?
               //~ .keyswitch(pc.ksk)?;

    //~ Ok(res)
//~ }

//~ //
//~ //  X ⋛ ±1
//~ //
//~ #[allow(non_snake_case)]
//~ pub fn f_1__pi_3(
    //~ pc: &ParmesanCloudovo,
    //~ c: &ParmEncrWord,
//~ ) -> Result<ParmEncrWord, Box<dyn Error>> {
    //~ //TODO resolve trivial case
    //~ if c.dimension == 0 {
        //~ return Ok(c.clone());
    //~ }

    //~ let res = c.bootstrap_with_function(pc.bsk, |x| [0.,1.,1.,1.,][x as usize], pc.encoder)?
               //~ .keyswitch(pc.ksk)?;

    //~ Ok(res)
//~ }

//~ //
//~ //  X ⋛ ±2
//~ //
//~ #[allow(non_snake_case)]
//~ pub fn f_2__pi_3(
    //~ pc: &ParmesanCloudovo,
    //~ c: &ParmEncrWord,
//~ ) -> Result<ParmEncrWord, Box<dyn Error>> {
    //~ //TODO resolve trivial case
    //~ if c.dimension == 0 {
        //~ return Ok(c.clone());
    //~ }

    //~ let res = c.bootstrap_with_function(pc.bsk, |x| [0.,0.,1.,0.,][x as usize], pc.encoder)?
               //~ .keyswitch(pc.ksk)?;

    //~ Ok(res)
//~ }

//~ //
//~ //  X ≡ ±1
//~ //
//~ #[allow(non_snake_case)]
//~ pub fn g_1__pi_3(
    //~ pc: &ParmesanCloudovo,
    //~ c: &ParmEncrWord,
//~ ) -> Result<ParmEncrWord, Box<dyn Error>> {
    //~ //TODO resolve trivial case
    //~ if c.dimension == 0 {
        //~ return Ok(c.clone());
    //~ }

    //~ let res = c.bootstrap_with_function(pc.bsk, |x| [0.,1.,0.,1.,][x as usize], pc.encoder)?
               //~ .keyswitch(pc.ksk)?;

    //~ Ok(res)
//~ }

//~ //
//~ //  X ≡ ±2
//~ //
//~ #[allow(non_snake_case)]
//~ pub fn g_2__pi_3(
    //~ pc: &ParmesanCloudovo,
    //~ c: &ParmEncrWord,
//~ ) -> Result<ParmEncrWord, Box<dyn Error>> {
    //~ // for π = 3 .. equivalent to X ⋛ ±2
    //~ f_2__pi_3(pc, c)
//~ }


//~ // =============================================================================
//~ //
//~ //  PI = 4
//~ //

//~ //
//~ //  X (around zero)
//~ //
//~ #[allow(non_snake_case)]
//~ pub fn id__pi_4(
    //~ pc: &ParmesanCloudovo,
    //~ c: &ParmEncrWord,
//~ ) -> Result<ParmEncrWord, Box<dyn Error>> {
    //~ //TODO resolve trivial case
    //~ if c.dimension == 0 {
        //~ return Ok(c.clone());
    //~ }

    //~ let res = c.bootstrap_with_function(pc.bsk, |x| [0.,1.,2.,3.,4.,3.,2.,1.][x as usize], pc.encoder)?
               //~ .keyswitch(pc.ksk)?;

    //~ Ok(res)
//~ }

//~ //
//~ //  X ⋛ ±2
//~ //
//~ #[allow(non_snake_case)]
//~ pub fn f_2__pi_4(
    //~ pc: &ParmesanCloudovo,
    //~ c: &ParmEncrWord,
//~ ) -> Result<ParmEncrWord, Box<dyn Error>> {
    //~ //TODO resolve trivial case
    //~ if c.dimension == 0 {
        //~ return Ok(c.clone());
    //~ }

    //~ let res = c.bootstrap_with_function(pc.bsk, |x| [0.,0.,1.,1.,1.,1.,1.,0.,][x as usize], pc.encoder)?
               //~ .keyswitch(pc.ksk)?;

    //~ Ok(res)
//~ }

//~ //
//~ //  X ⋛ ±3
//~ //
//~ #[allow(non_snake_case)]
//~ pub fn f_3__pi_4(
    //~ pc: &ParmesanCloudovo,
    //~ c: &ParmEncrWord,
//~ ) -> Result<ParmEncrWord, Box<dyn Error>> {
    //~ //TODO resolve trivial case
    //~ if c.dimension == 0 {
        //~ return Ok(c.clone());
    //~ }

    //~ let res = c.bootstrap_with_function(pc.bsk, |x| [0.,0.,0.,1.,1.,1.,0.,0.,][x as usize], pc.encoder)?
               //~ .keyswitch(pc.ksk)?;

    //~ Ok(res)
//~ }

//~ //
//~ //  X ≡ ±2
//~ //
//~ #[allow(non_snake_case)]
//~ pub fn g_2__pi_4(
    //~ pc: &ParmesanCloudovo,
    //~ c: &ParmEncrWord,
//~ ) -> Result<ParmEncrWord, Box<dyn Error>> {
    //~ //TODO resolve trivial case
    //~ if c.dimension == 0 {
        //~ return Ok(c.clone());
    //~ }

    //~ let res = c.bootstrap_with_function(pc.bsk, |x| [0.,0.,1.,0.,0.,0.,1.,0.,][x as usize], pc.encoder)?
               //~ .keyswitch(pc.ksk)?;

    //~ Ok(res)
//~ }

//~ //
//~ //  X ≡ ±1 (× val)
//~ //
//~ #[allow(non_snake_case)]
//~ pub fn g_1__pi_4__with_val(
    //~ pc: &ParmesanCloudovo,
    //~ c: &ParmEncrWord,
    //~ val: u32,
//~ ) -> Result<ParmEncrWord, Box<dyn Error>> {
    //~ //TODO resolve trivial case
    //~ if c.dimension == 0 {
        //~ return Ok(c.clone());
    //~ }

    //~ let vf = val as f64;

    //~ let res = c.bootstrap_with_function(pc.bsk, |x| [0.,vf,0.,0.,0.,0.,0.,vf][x as usize], pc.encoder)?
               //~ .keyswitch(pc.ksk)?;

    //~ Ok(res)
//~ }


//~ // =============================================================================
//~ //
//~ //  PI = 7
//~ //

//~ //
//~ //  X (around zero)
//~ //
//~ #[allow(non_snake_case)]
//~ pub fn id__pi_7(
    //~ pc: &ParmesanCloudovo,
    //~ c: &ParmEncrWord,
//~ ) -> Result<ParmEncrWord, Box<dyn Error>> {
    //~ //TODO resolve trivial case
    //~ if c.dimension == 0 {
        //~ return Ok(c.clone());
    //~ }

    //~ let res = c.bootstrap_with_function(pc.bsk, |x| [0.,1.,2.,3.,4.,5.,6.,7.,8.,9.,10.,11.,12.,13.,14.,15.,16.,17.,18.,19.,20.,21.,22.,23.,24.,25.,26.,27.,28.,29.,30.,31.,32.,31.,30.,29.,28.,27.,26.,25.,24.,23.,22.,21.,20.,19.,18.,17.,16.,15.,14.,13.,12.,11.,10.,9.,8.,7.,6.,5.,4.,3.,2.,1.][x as usize], pc.encoder)?
               //~ .keyswitch(pc.ksk)?;

    //~ Ok(res)
//~ }

//~ //
//~ //  X ⋛ ±14
//~ //
//~ #[allow(non_snake_case)]
//~ pub fn f_14__pi_7(
    //~ pc: &ParmesanCloudovo,
    //~ c: &ParmEncrWord,
//~ ) -> Result<ParmEncrWord, Box<dyn Error>> {
    //~ //TODO resolve trivial case
    //~ if c.dimension == 0 {
        //~ return Ok(c.clone());
    //~ }

    //~ let res = c.bootstrap_with_function(pc.bsk, |x| [0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,1.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,][x as usize], pc.encoder)?
               //~ .keyswitch(pc.ksk)?;

    //~ Ok(res)
//~ }


// =============================================================================


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
    //~ pc: &ParmesanCloudovo,
    //~ c: &ParmEncrWord,
//~ ) -> ParmEncrWord {
    //~ measure_duration!(
        //~ ["PBS: Identity"],
        //~ [let res = c.bootstrap_with_function(pc.bsk, |x| x*x, pc.encoder)?
                    //~ .keyswitch(pc.ksk)?;]
    //~ );

    //~ res
//~ }

// try LUT
//~ let lut = |x| [1, 2, 3, 4, 5][x];
//~ let var = 3;
//~ println!("LUT({}) = {}", var, lut(var));
