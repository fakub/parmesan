//~ use std::error::Error;

use concrete::LWE;

pub type ParmCiphertext = Vec<LWE>;

//WISH add initialization of empty one: vec![LWE::zero_with_encoder(dim, encoder)?; len];

// this is not possible for type
//~ impl ParmCiphertext {
    //~ pub fn empty() -> Result<ParmCiphertext, Box<dyn Error>> {
        //~ vec![LWE::zero(0)?; 0]
    //~ }
//~ }
