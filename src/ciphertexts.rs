use concrete::LWE;

pub type ParmCiphertext = Vec<LWE>;

//WISH add initialization of empty one: vec![LWE::zero_with_encoder(dim, encoder)?; len];
