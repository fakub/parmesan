use tfhe::shortint::parameters::*;

/// # Parmesan Parameters
/// Contains
/// * maximum bit-length of encrypted integers
/// * plaintext precision
/// * quadratic weights
/// * THFE parameters
#[derive(Clone, Debug)]   //WISH Serialize, Deserialize (also elsewhere)
pub struct Params {
    pub concrete_pars:  ClassicPBSParameters,
    pub bit_precision:  usize,          // aka. pi
    pub   quad_weight:  usize,          // aka. 2^2Δ
    //~ pub    lwe_params:  LWEParams,
    //~ pub   rlwe_params:  RLWEParams,
}

impl Params {

    /// Get mask of plaintext length, e.g., `0001'1111` for `pi = 5`
    /// * corresponds with -1 in plaintext space
    pub fn plaintext_mask(&self) -> u32 {
        (1u32 << self.bit_precision) - 1
    }

    /// Get upper (positive) bound on plaintext space, e.g., `0001'0000` for `pi = 5`
    /// * corresponds with +- maximum (unused value)
    pub fn plaintext_pos_max(&self) -> u32 {
        1u32 << (self.bit_precision - 1)
    }

    /// Get size of plaintext space, e.g., `0010'0000` for `pi = 5`
    pub fn plaintext_space_size(&self) -> i32 {
        1i32 << self.bit_precision
    }


    // -------------------------------------------------------------------------
    //  Accessors

    /// Access LWE dimensoin (aka. n)
    pub fn lwe_dimension(&self) -> usize {
        self.concrete_pars.lwe_dimension.0
    }

    /// Access GLWE dimensoin (aka. k; usually 1)
    pub fn glwe_dimension(&self) -> usize {
        self.concrete_pars.glwe_dimension.0
    }

    /// Access reduction polynomial degree (aka. N)
    pub fn polynomial_size(&self) -> usize {
        self.concrete_pars.polynomial_size.0
    }

    /// Access LWE std. dev.
    pub fn lwe_modular_std_dev(&self) -> f64 {
        self.concrete_pars.lwe_modular_std_dev.0
    }

    /// Access LWE variance
    pub fn lwe_var_f64(&self) -> f64 {
        self.concrete_pars.lwe_modular_std_dev.get_variance()
    }

    /// Access GLWE std. dev.
    pub fn glwe_modular_std_dev(&self) -> f64 {
        self.concrete_pars.glwe_modular_std_dev.0
    }

    /// Access GLWE variance
    pub fn glwe_var_f64(&self) -> f64 {
        self.concrete_pars.glwe_modular_std_dev.get_variance()
    }

    /// Access PBS base log (aka. gamma)
    pub fn pbs_base_log(&self) -> usize {
        self.concrete_pars.pbs_base_log.0
    }

    /// Access PBS level (aka. l)
    pub fn pbs_level(&self) -> usize {
        self.concrete_pars.pbs_level.0
    }

    /// Access KS base log (aka. kappa)
    pub fn ks_base_log(&self) -> usize {
        self.concrete_pars.ks_base_log.0
    }

    /// Access KS level (aka. t)
    pub fn ks_level(&self) -> usize {
        self.concrete_pars.ks_level.0
    }

    //~ /// Calc Concrete's delta
    //~ pub fn delta_concrete(&self) -> usize {
        //~ 1 << (64 - self.bit_precision)
    //~ }
}

#[allow(dead_code)]
pub const PAR_TFHE_V0_5__M4_C0: Params = Params {
    concrete_pars:  ClassicPBSParameters {
        message_modulus: MessageModulus(1 << 5),
        ..PARAM_MESSAGE_4_CARRY_0_KS_PBS
        //TODO make it work with PARAM_MESSAGE_1_CARRY_3_KS_PBS
    },
    //TODO assert_eq!(server_key.carry_modulus.0, 1)
    //TODO use message_modulus from tfhe-rs instead (or do not implement custom params at all)
    bit_precision:    5,
    // derived as follows: greatest message = 3, fits within carry multiplied by 10 (3x10 = 30 < 2^5)
    // i.e., the error must fit even when sample is multiplied by 10
    // => QW = 10^2
    quad_weight:    100,
};
