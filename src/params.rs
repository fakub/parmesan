use concrete_core::prelude::*;

/// # Parmesan Parameters
/// Contains
/// * maximum bit-length of encrypted integers
/// * plaintext precision
/// * quadratic weights
/// * THFE parameters
#[derive(Clone, Debug)]   //WISH Serialize, Deserialize (also elsewhere)
pub struct Params {
    pub concrete_pars:  Parameters,
    pub bit_precision:  usize,          // aka. pi
    pub   quad_weight:  usize,          // aka. 2^2Δ
    //~ pub    lwe_params:  LWEParams,
    //~ pub   rlwe_params:  RLWEParams,
}

impl Params {

    /// Get mask of plaintext length, e.g., `0001'1111` for `pi = 5`
    /// * corresponds with -1 in plaintext space
    pub fn plaintext_mask(&self) -> i32 {
        (1i32 << self.bit_precision) - 1
    }

    /// Get upper (positive) bound on plaintext space, e.g., `0001'0000` for `pi = 5`
    /// * corresponds with +- maximum (unused value)
    pub fn plaintext_pos_max(&self) -> i32 {
        1i32 << (self.bit_precision - 1)
    }

    /// Get size of plaintext space, e.g., `0010'0000` for `pi = 5`
    pub fn plaintext_space_size(&self) -> i32 {
        1i32 << self.bit_precision
    }

    /// Access PBS base log (aka. gamma)
    pub fn bs_base_log(&self) -> usize {
        self.concrete_pars.pbs_base_log.0
    }

    /// Access PBS level (aka. l)
    pub fn bs_level(&self) -> usize {
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

    /// Calc variance
    pub fn var_lwe(&self) -> Variance {
        Variance(self.concrete_pars.lwe_modular_std_dev.get_variance())
    }

    /// Calc Concrete's delta
    pub fn delta_concrete(&self) -> usize {
        //FIXME replace 64
        1 << (64 - self.bit_precision)
    }
}

//~ #[allow(dead_code)]
//~ pub const PARMXX__TRIVIAL: Params = Params {
           //~ maxlen: 8,
    //~ bit_precision: 2,
      //~ quad_weight: 2,
    //~ lwe_params: LWEParams {
        //~ dimension: 64,
        //~ log2_std_dev: -8,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 256,
        //~ dimension: 1,
        //~ log2_std_dev: -10,
    //~ },
    //~ bs_base_log: 2,
       //~ bs_level: 2,
    //~ ks_base_log: 1,
       //~ ks_level: 3,
//~ };


//~ // =============================================================================
//~ //
//~ //  Concrete's Parameters (taken from v0.2)
//~ //

//~ /// TFHE Parameter Set `concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_3`
//~ // max value of 2 bits is 3 => before the overflow of 3+2 bits ~ value 31, scalar mul by 10 must be supported ~ quadratic weight of 100
//~ // which prefectly fine for Parmesan, which needs 22
//~ #[allow(dead_code)]
//~ pub const CONCR__M_2__C_3: Params = Params {
           //~ maxlen: 0,
    //~ bit_precision: 5,
      //~ quad_weight: 100,
       //~ lwe_params: LWEParams {
        //~ dimension: 776,
     //~ log2_std_dev: -19, // 0.00000278330461375383057442 ~ -18.45
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 2048,
              //~ dimension: 1,
           //~ log2_std_dev: -52, // 0.00000000000000022148688116005568513645324585951 ~ -52.00
    //~ },
    //~ bs_base_log: 23,
       //~ bs_level: 1,
    //~ ks_base_log: 4,
       //~ ks_level: 5,
//~ };


//~ // =============================================================================
//~ //
//~ //  NEW 80, 112 & 128-bit security, (pi, qw) = (5, 22)
//~ //

//~ /// TFHE Parameter Set (80.9-bit)
//~ #[allow(dead_code)]
//~ pub const PARM80__PI_5__D_22: Params = Params {
           //~ maxlen: 0,
    //~ bit_precision: 5,
      //~ quad_weight: 22,
       //~ lwe_params: LWEParams {
        //~ dimension: 473,
     //~ log2_std_dev: -18,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 1024,
              //~ dimension: 1,
           //~ log2_std_dev: -39,
    //~ },
    //~ bs_base_log: 19,
       //~ bs_level: 1,
    //~ ks_base_log: 3,
       //~ ks_level: 5,
//~ };

//~ /// TFHE Parameter Set (111.7-bit)
//~ #[allow(dead_code)]
//~ pub const PARM112__PI_5__D_22: Params = Params {
           //~ maxlen: 0,
    //~ bit_precision: 5,
      //~ quad_weight: 22,
       //~ lwe_params: LWEParams {
        //~ dimension: 655,
     //~ log2_std_dev: -18,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 1024,
              //~ dimension: 1,
           //~ log2_std_dev: -28,
    //~ },
    //~ bs_base_log: 7,
       //~ bs_level: 3,
    //~ ks_base_log: 3,
       //~ ks_level: 5,
//~ };

//~ /// TFHE Parameter Set (129.1-bit)
//~ #[allow(dead_code)]
//~ pub const PARM128__PI_5__D_22: Params = Params {
           //~ maxlen: 0,
    //~ bit_precision: 5,
      //~ quad_weight: 22,
       //~ lwe_params: LWEParams {
        //~ dimension: 754,
     //~ log2_std_dev: -18,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 2048,
              //~ dimension: 1,
           //~ log2_std_dev: -48,
    //~ },
    //~ bs_base_log: 24,
       //~ bs_level: 1,
    //~ ks_base_log: 3,
       //~ ks_level: 5,
//~ };


//~ // =============================================================================
//~ //
//~ //  !! UNUSED / DEPRECATED !! NEW 80, 112 & 128-bit security, (pi, qw) = (5, 20)
//~ //

//~ /// TFHE Parameter Set (81.2-bit)
//~ #[allow(dead_code, non_upper_case_globals)]
//~ pub const __deprecated__PARM80__PI_5__D_20: Params = Params {
           //~ maxlen: 0,
    //~ bit_precision: 5,
      //~ quad_weight: 20,
       //~ lwe_params: LWEParams {
        //~ dimension: 474,
     //~ log2_std_dev: -18,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 1024,
              //~ dimension: 1,
           //~ log2_std_dev: -38,
    //~ },
    //~ bs_base_log: 19,
       //~ bs_level: 1,
    //~ ks_base_log: 3,
       //~ ks_level: 5,
//~ };

//~ /// TFHE Parameter Set (112.0-bit)
//~ #[allow(dead_code, non_upper_case_globals)]
//~ pub const __deprecated__PARM112__PI_5__D_20: Params = Params {
           //~ maxlen: 0,
    //~ bit_precision: 5,
      //~ quad_weight: 20,
       //~ lwe_params: LWEParams {
        //~ dimension: 657,
     //~ log2_std_dev: -18,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 1024,
              //~ dimension: 1,
           //~ log2_std_dev: -28,
    //~ },
    //~ bs_base_log: 7,
       //~ bs_level: 3,
    //~ ks_base_log: 3,
       //~ ks_level: 5,
//~ };

//~ /// TFHE Parameter Set (128-bit)
//~ #[allow(dead_code, non_upper_case_globals)]
//~ pub const __deprecated__PARM128__PI_5__D_20: Params = Params {
           //~ maxlen: 0,
    //~ bit_precision: 5,
      //~ quad_weight: 20,
       //~ lwe_params: LWEParams {
        //~ dimension: 747,
     //~ log2_std_dev: -18,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 2048,
              //~ dimension: 1,
           //~ log2_std_dev: -49,
    //~ },
    //~ bs_base_log: 24,
       //~ bs_level: 1,
    //~ ks_base_log: 3,
       //~ ks_level: 5,
//~ };



//~ // #############################################################################
//~ //
//~ //  Parameters for comparison of different addition algorithms
//~ //


//~ // =============================================================================
//~ //
//~ //  112-bit security
//~ //

//~ /// TFHE Parameter Set A (112.4-bit security)
//~ #[allow(dead_code)]
//~ pub const PARM112__PI_2__D_02__A: Params = Params {
           //~ maxlen: 32,
    //~ bit_precision: 2,
      //~ quad_weight: 2,
       //~ lwe_params: LWEParams {
        //~ dimension: 500,
     //~ log2_std_dev: -13, // -13.31,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 1024,
              //~ dimension: 1,
           //~ log2_std_dev: -24, // -24.86,
    //~ },
    //~ bs_base_log: 8,
       //~ bs_level: 2,
    //~ ks_base_log: 1,
       //~ ks_level: 11,
//~ };

//~ /// TFHE Parameter Set B (112.5-bit security)
//~ #[allow(dead_code)]
//~ pub const PARM112__PI_2__D_03__B: Params = Params {
           //~ maxlen: 32,
    //~ bit_precision: 2,
      //~ quad_weight: 3,
       //~ lwe_params: LWEParams {
        //~ dimension: 510,
     //~ log2_std_dev: -13, // -13.61,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 1024,
              //~ dimension: 1,
           //~ log2_std_dev: -25, // -25.17,
    //~ },
    //~ bs_base_log: 8,
       //~ bs_level: 2,
    //~ ks_base_log: 1,
       //~ ks_level: 11,
//~ };

//~ /// TFHE Parameter Set C (111.5-bit security)
//~ #[allow(dead_code)]
//~ pub const PARM112__PI_3__D_19__C: Params = Params {
           //~ maxlen: 32,
    //~ bit_precision: 3,
      //~ quad_weight: 19,
       //~ lwe_params: LWEParams {
        //~ dimension: 590,
     //~ log2_std_dev: -16, // -16.11,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 1024,
              //~ dimension: 1,
           //~ log2_std_dev: -28, // -28.60,
    //~ },
    //~ bs_base_log: 9,
       //~ bs_level: 2,
    //~ ks_base_log: 1,
       //~ ks_level: 14,
//~ };


//~ // -----------------------------------------------------------------------------

//~ /// TFHE Parameter Set D (112.1-bit security)
//~ #[allow(dead_code)]
//~ pub const PARM112__PI_3__D_12__D: Params = Params {
           //~ maxlen: 32,
    //~ bit_precision: 3,
      //~ quad_weight: 12,
       //~ lwe_params: LWEParams {
        //~ dimension: 580,
     //~ log2_std_dev: -15, // -15.73,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 1024,
              //~ dimension: 1,
           //~ log2_std_dev: -28, // -28.26,
    //~ },
    //~ bs_base_log: 9,
       //~ bs_level: 2,
    //~ ks_base_log: 1,
       //~ ks_level: 13,
//~ };

//~ /// TFHE Parameter Set E (112.8-bit security)
//~ #[allow(dead_code)]
//~ pub const PARM112__PI_4__D_12__E: Params = Params {
           //~ maxlen: 32,
    //~ bit_precision: 4,
      //~ quad_weight: 12,
       //~ lwe_params: LWEParams {
        //~ dimension: 620,
     //~ log2_std_dev: -16, // -16.78,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 1024,
              //~ dimension: 1,
           //~ log2_std_dev: -27, // -27.60,
    //~ },
    //~ bs_base_log: 7,
       //~ bs_level: 3,
    //~ ks_base_log: 1,
       //~ ks_level: 14,
//~ };

//~ /// TFHE Parameter Set F (111.5-bit security)
//~ #[allow(dead_code)]
//~ pub const PARM112__PI_5__D_20__F: Params = Params {
           //~ maxlen: 32,
    //~ bit_precision: 5,
      //~ quad_weight: 20,
       //~ lwe_params: LWEParams {
        //~ dimension: 680,
     //~ log2_std_dev: -18, // -18.25,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 1024,
              //~ dimension: 1,
           //~ log2_std_dev: -29, // -29.04,
    //~ },
    //~ bs_base_log: 7,
       //~ bs_level: 3,
    //~ ks_base_log: 1,
       //~ ks_level: 16,
//~ };

//~ // -----------------------------------------------------------------------------

//~ /// TFHE Parameter Set G (113.1-bit security)
//~ #[allow(dead_code)]
//~ pub const PARM112__PI_4__D_36__G: Params = Params {
           //~ maxlen: 32,
    //~ bit_precision: 4,
      //~ quad_weight: 36,
       //~ lwe_params: LWEParams {
        //~ dimension: 650,
     //~ log2_std_dev: -17, // -17.62,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 1024,
              //~ dimension: 1,
           //~ log2_std_dev: -28, // -28.42,
    //~ },
    //~ bs_base_log: 7,
       //~ bs_level: 3,
    //~ ks_base_log: 1,
       //~ ks_level: 15,
//~ };

//~ /// TFHE Parameter Set H (112.1-bit security)
//~ #[allow(dead_code)]
//~ pub const PARM112__PI_5__D_36__H: Params = Params {
           //~ maxlen: 32,
    //~ bit_precision: 5,
      //~ quad_weight: 36,
       //~ lwe_params: LWEParams {
        //~ dimension: 680,
     //~ log2_std_dev: -18, // -18.67,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 1024,
              //~ dimension: 1,
           //~ log2_std_dev: -28, // -28.67,
    //~ },
    //~ bs_base_log: 6,
       //~ bs_level: 4,
    //~ ks_base_log: 1,
       //~ ks_level: 16,
//~ };

//~ /// TFHE Parameter Set I (112.0-bit security)
//~ #[allow(dead_code)]
//~ pub const PARM112__PI_7__D_74__I: Params = Params {
           //~ maxlen: 32,
    //~ bit_precision: 7,
      //~ quad_weight: 74,
       //~ lwe_params: LWEParams {
        //~ dimension: 820,
     //~ log2_std_dev: -22, // -22.85,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 8192,
              //~ dimension: 1,
           //~ log2_std_dev: -50, // -50.82,
    //~ },
    //~ bs_base_log: 25,
       //~ bs_level: 1,
    //~ ks_base_log: 1,
       //~ ks_level: 20,
//~ };


//~ // =============================================================================
//~ //
//~ //  90-bit security
//~ //

//~ /// TFHE Parameter Set A (90-bit security)
//~ #[allow(dead_code)]
//~ pub const PARM90__PI_2__D_02__A: Params = Params {
           //~ maxlen: 32,
    //~ bit_precision: 3,   // other params correspond with pi = 2, one more bit is needed to simulate logic operations, which work with halves
      //~ quad_weight: 2,
       //~ lwe_params: LWEParams {
        //~ dimension: 400,
     //~ log2_std_dev: -13, // -13.31,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 1024,
              //~ dimension: 1,
           //~ log2_std_dev: -31, // -31.20,
    //~ },
    //~ bs_base_log: 15,
       //~ bs_level: 1,
    //~ ks_base_log: 1,
       //~ ks_level: 11,
//~ };

//~ /// TFHE Parameter Set B (90-bit security)
//~ #[allow(dead_code)]
//~ pub const PARM90__PI_2__D_03__B: Params = Params {
           //~ maxlen: 32,
    //~ bit_precision: 3,   // other params correspond with pi = 2, one more bit is needed to simulate logic operations, which work with halves
      //~ quad_weight: 3,
       //~ lwe_params: LWEParams {
        //~ dimension: 420,
     //~ log2_std_dev: -13, // -13.61,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 1024,
              //~ dimension: 1,
           //~ log2_std_dev: -32, // -32.53,
    //~ },
    //~ bs_base_log: 16,
       //~ bs_level: 1,
    //~ ks_base_log: 1,
       //~ ks_level: 11,
//~ };

//~ /// TFHE Parameter Set C (90-bit security)
//~ #[allow(dead_code)]
//~ pub const PARM90__PI_3__D_19__C: Params = Params {
           //~ maxlen: 32,
    //~ bit_precision: 4,   // other params correspond with pi = 3, one more bit is needed to simulate halves that are used in scenario C
      //~ quad_weight: 19,
       //~ lwe_params: LWEParams {
        //~ dimension: 490,
     //~ log2_std_dev: -16, // -16.11,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 1024,
              //~ dimension: 1,
           //~ log2_std_dev: -28, // -28.47,
    //~ },
    //~ bs_base_log: 9,
       //~ bs_level: 2,
    //~ ks_base_log: 1,
       //~ ks_level: 14,
//~ };

//~ // -----------------------------------------------------------------------------

//~ /// TFHE Parameter Set D (90-bit security)
//~ #[allow(dead_code)]
//~ pub const PARM90__PI_3__D_12__D: Params = Params {
           //~ maxlen: 32,
    //~ bit_precision: 3,
      //~ quad_weight: 12,
       //~ lwe_params: LWEParams {
        //~ dimension: 480,
     //~ log2_std_dev: -15, // -15.73,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 1024,
              //~ dimension: 1,
           //~ log2_std_dev: -28, // -28.12,
    //~ },
    //~ bs_base_log: 9,
       //~ bs_level: 2,
    //~ ks_base_log: 1,
       //~ ks_level: 13,
//~ };

//~ /// TFHE Parameter Set E (90-bit security)
//~ #[allow(dead_code)]
//~ pub const PARM90__PI_4__D_12__E: Params = Params {
           //~ maxlen: 32,
    //~ bit_precision: 4,
      //~ quad_weight: 12,
       //~ lwe_params: LWEParams {
        //~ dimension: 510,
     //~ log2_std_dev: -16, // -16.78,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 1024,
              //~ dimension: 1,
           //~ log2_std_dev: -30, // -30.17,
    //~ },
    //~ bs_base_log: 10,
       //~ bs_level: 2,
    //~ ks_base_log: 1,
       //~ ks_level: 14,
//~ };

//~ /// TFHE Parameter Set F (90-bit security)
//~ #[allow(dead_code)]
//~ pub const PARM90__PI_5__D_20__F: Params = Params {
           //~ maxlen: 32,
    //~ bit_precision: 5,
      //~ quad_weight: 20,
       //~ lwe_params: LWEParams {
        //~ dimension: 560,
     //~ log2_std_dev: -18, // -18.25,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 1024,
              //~ dimension: 1,
           //~ log2_std_dev: -31, // -31.60,
    //~ },
    //~ bs_base_log: 10,
       //~ bs_level: 2,
    //~ ks_base_log: 1,
       //~ ks_level: 16,
//~ };

//~ // -----------------------------------------------------------------------------

//~ /// TFHE Parameter Set G (90-bit security)
//~ #[allow(dead_code)]
//~ pub const PARM90__PI_4__D_36__G: Params = Params {
           //~ maxlen: 32,
    //~ bit_precision: 4,
      //~ quad_weight: 36,
       //~ lwe_params: LWEParams {
        //~ dimension: 540,
     //~ log2_std_dev: -17, // -17.62,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 1024,
              //~ dimension: 1,
           //~ log2_std_dev: -31, // -31.00,
    //~ },
    //~ bs_base_log: 10,
       //~ bs_level: 2,
    //~ ks_base_log: 1,
       //~ ks_level: 15,
//~ };

//~ /// TFHE Parameter Set H (90-bit security)
//~ #[allow(dead_code)]
//~ pub const PARM90__PI_5__D_36__H: Params = Params {
           //~ maxlen: 32,
    //~ bit_precision: 5,
      //~ quad_weight: 36,
       //~ lwe_params: LWEParams {
        //~ dimension: 570,
     //~ log2_std_dev: -18, // -18.67,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 1024,
              //~ dimension: 1,
           //~ log2_std_dev: -33, // -33.04,
    //~ },
    //~ bs_base_log: 11,
       //~ bs_level: 2,
    //~ ks_base_log: 1,
       //~ ks_level: 16,
//~ };

//~ /// TFHE Parameter Set I (90-bit security)
//~ #[allow(dead_code)]
//~ pub const PARM90__PI_7__D_74__I: Params = Params {
           //~ maxlen: 32,
    //~ bit_precision: 7,
      //~ quad_weight: 74,
       //~ lwe_params: LWEParams {
        //~ dimension: 680,
     //~ log2_std_dev: -22, // -22.35,
    //~ },
    //~ rlwe_params: RLWEParams {
        //~ polynomial_size: 4096,
              //~ dimension: 1,
           //~ log2_std_dev: -49, // -49.19,
    //~ },
    //~ bs_base_log: 24,
       //~ bs_level: 1,
    //~ ks_base_log: 1,
       //~ ks_level: 20,
//~ };
