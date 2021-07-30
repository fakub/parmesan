use concrete::LWE;

pub struct ParmCiphertext {
    pub ctv: Vec<LWE>,
    pub maxlen: usize,
}
