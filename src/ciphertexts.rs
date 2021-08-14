use std::error::Error;

use concrete::LWE;

use crate::params::Params;
use crate::userovo::keys::PubKeySet;

//TODO ciphertext should be more standalone type: it should hold a reference to its public keys & params to that operations can be done with only this type parameter
#[derive(Clone, Debug)]
pub struct ParmCiphertext<'a> {
    pub c: Vec<LWE>,
    pub params: &'a Params,
    pub pub_keys: &'a PubKeySet,
}

impl ParmCiphertext<'_> {
    //WISH add initialization of empty one: vec![LWE::zero_with_encoder(dim, encoder)?; len];
    pub fn triv<'a>(
        params: &'a Params,
        pub_keys: &'a PubKeySet,
        len: usize,
    ) -> Result<ParmCiphertext<'a>, Box<dyn Error>> {
        Ok(ParmCiphertext {
            c: vec![LWE::zero(0)?; len],
            params,
            pub_keys,
        })
    }

    pub fn len(&self) -> usize {
        self.c.len()
    }

    //TODO push, append, ...
    //WISH iter (all flavours?)
}
