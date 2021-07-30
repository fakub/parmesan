use concrete::LWE;
use crate::userovo::keys::PubKeySet;

pub fn id(
    pub_keys: &PubKeySet,
    c: &LWE,
) -> LWE {
    c.bootstrap_with_function(pub_keys.bsk, |x| x, pub_keys.encoder).expect("Identity PBS failed.")
}
