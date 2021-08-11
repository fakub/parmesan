//~ use std::error::Error;

use concrete::LWE;

//TODO ciphertext should be more standalone type: it should hold a reference to its public keys & params to that operations can be done with only this type parameter
pub type ParmCiphertext = Vec<LWE>;

//WISH add initialization of empty one: vec![LWE::zero_with_encoder(dim, encoder)?; len];

// this is not possible for type
//~ impl ParmCiphertext {
    //~ pub fn empty() -> Result<ParmCiphertext, Box<dyn Error>> {
        //~ vec![LWE::zero(0)?; 0]
    //~ }
//~ }
