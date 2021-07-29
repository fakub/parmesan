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
