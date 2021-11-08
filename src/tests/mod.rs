use crate::params::{self,Params};
use crate::userovo::keys::PrivKeySet;

// declare global test constants
static REPEAT_ENCR_TESTS: usize = 100;
static PLAIN_BITLEN_TESTS: usize = 62;

// load & share keys across tests
static PARAMS: &Params = &params::PARM90__PI_5__D_20__F;   //     PARM90__PI_5__D_20__F      PARMXX__TRIVIAL
// to evaluate code in static declaration, lazy_static must be used
// cf. https://stackoverflow.com/questions/46378637/how-to-make-a-variable-with-a-scope-lifecycle-for-all-test-functions-in-a-rust-t
lazy_static! {
    static ref PRIV_KEYS: PrivKeySet = PrivKeySet::new(PARAMS).expect("PrivKeySet::new failed.");
}

// tested modules
pub mod test_addition;
pub mod test_addition_cc;
pub mod test_encryption;
pub mod test_maximum;
pub mod test_multiplication;
pub mod test_nn;
pub mod test_scalar_multiplication;
pub mod test_signum;

// enums
pub enum EncrTrivWords {
    // all words encrypted
    ENCR,
    // all words trivial
    TRIV,
    // randomly mixed trivial & encrypted
    ENCRTRIV,
}
