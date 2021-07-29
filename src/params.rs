use concrete::*;

pub struct Params {
    pub  lwe_params: LWEParams,
    pub rlwe_params: RLWEParams,
    pub bs_base_log: usize,         // aka. gamma
    pub    bs_level: usize,         // aka. l
    pub ks_base_log: usize,         // usually equals 1 (base = 2), now named kappa
    pub    ks_level: usize,         // aka. t
    //TODO add pi (and other params)
}

#[allow(dead_code)]
pub const PARMXX__TRIVIAL: Params = Params {
    lwe_params: LWEParams {
        dimension: 64,
        log2_std_dev: -8,
    },
    rlwe_params: RLWEParams {
        polynomial_size: 256,
        dimension: 1,
        log2_std_dev: -10,
    },
    bs_base_log: 2,
       bs_level: 2,
    ks_base_log: 1,
       ks_level: 3,
};
#[allow(dead_code)]
pub const PARM90__PI_5__D_20: Params = Params {
    lwe_params: LWEParams {
        dimension: 560,
        log2_std_dev: -18,
    },
    rlwe_params: RLWEParams {
        polynomial_size: 1024,
        dimension: 1,
        log2_std_dev: -31,
    },
    bs_base_log: 10,
       bs_level: 2,
    ks_base_log: 1,
       ks_level: 16,
};
#[allow(dead_code)]
pub const PARM90__PI_5__D_36: Params = Params {
    lwe_params: LWEParams {
        dimension: 570,
        log2_std_dev: -18,
    },
    rlwe_params: RLWEParams {
        polynomial_size: 1024,
        dimension: 1,
        log2_std_dev: -33,
    },
    bs_base_log: 11,
       bs_level: 2,
    ks_base_log: 1,
       ks_level: 16,
};
