use concrete::LWE;
#[allow(unused_imports)]
use colored::Colorize;
use crate::userovo::keys::PubKeySet;

pub fn id(
    pub_keys: &PubKeySet,
    c: &LWE,
) -> LWE {
    crate::measure_duration!(
        "PBS: Identity",
        [let res = c.bootstrap_with_function(pub_keys.bsk, |x| x, pub_keys.encoder)
                    .expect("Identity PBS failed.")
                    .keyswitch(pub_keys.ksk)
                    .expect("KS failed (in identity).");]
    );

    res
}

#[allow(non_snake_case)]
pub fn f_4__pi_5(
    pub_keys: &PubKeySet,
    c: &LWE,
) -> LWE {
    crate::measure_duration!(
        "PBS: X ⋛ ±4 (for π = 5)",
        [let res = c.bootstrap_with_function(pub_keys.bsk, |x| [0.,0.,0.,0.,1.,1.,1.,1.,1.,1.,1.,1.,1.,0.,0.,0.][x as usize], pub_keys.encoder)
                    .expect("___ PBS failed.")
                    .keyswitch(pub_keys.ksk)
                    .expect("KS failed (in ___).");]
    );

    res
}

#[allow(non_snake_case)]
pub fn f_1__pi_5__with_val(
    pub_keys: &PubKeySet,
    c: &LWE,
    val: u32,
) -> LWE {
    let val_f = val as f64;
    crate::measure_duration!(
        "PBS: X ⋛ ±1 (times val, for π = 5)",
        [let res = c.bootstrap_with_function(pub_keys.bsk, |x| [0.,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f,val_f][x as usize], pub_keys.encoder)
                    .expect("___ PBS failed.")
                    .keyswitch(pub_keys.ksk)
                    .expect("KS failed (in ___).");]
    );

    res
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
    //~ lut:    |x| x * x,   //TODO
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
    //~ crate::measure_duration!(
        //~ "PBS: Identity",
        //~ [let res = c.bootstrap_with_function(pub_keys.bsk, |x| x*x, pub_keys.encoder)
                    //~ .expect("Identity PBS failed.")
                    //~ .keyswitch(pub_keys.ksk)
                    //~ .expect("KS failed (in identity).");]
    //~ );

    //~ res
//~ }

// try LUT
//~ let lut = |x| [1, 2, 3, 4, 5][x];
//~ let var = 3;
//~ println!("LUT({}) = {}", var, lut(var));
