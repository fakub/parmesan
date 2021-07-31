# Parmesan

*Parallel ARithMEticS on tfhe ENcrypted data*

Parmesan implements selected parallel algorithms for multi-digit arithmetics over TFHE ciphertexts. Namely:

- addition,
- signum, and
- maximum of two numbers.

## The Short Story

In the standard integer representation, parallel addition is not possible due to the carry, which can propagate all the way from the LSB to the MSB. However, using, e.g., an alphabet `{-1,0,1}` for base-2 integer representation, a parallel addition algorithm does exist.

## The Long Story

See our [full paper](https://eprint.iacr.org/2021/TODO).

## Use `parmesan`

Add a dependency to your `Cargo.toml` file in your Rust project.

```toml
[dependencies]
parmesan = "^0.1"
```

For the best performance, we recommend to compile & run with the `RUSTFLAGS="-C target-cpu=native" cargo run --release` command.

## Example

```rust
use std::error::Error;

// add use to what is missing

pub fn main() -> Result<(), Box<dyn Error>> {
    
    // =================================
    //  Initialization
    // ---------------------------------
    //  Global Scope
    let par = &params::PARMXX__TRIVIAL;
    // ---------------------------------
    //  Userovo Scope
    let pu = ParmesanUserovo::new(par)?;
    let pub_k = pu.export_pub_keys();
    // ---------------------------------
    //  Cloudovo Scope
    let pc = ParmesanCloudovo::new(par, &pub_k);

    // =================================
    //  U: Encryption
    let m1 =  0b00100111i32;
    let m2 =  0b00101110i32;
    let m3 = -0b00011001i32;
    let c1 = pu.encrypt(m1, 6)?;
    let c2 = pu.encrypt(m2, 6)?;
    let c3 = pu.encrypt(m3, 6)?;
    infoln!("{} messages\nm1 = {}{:b} ({})\nm2 = {}{:b} ({})m3 = {}{:b} ({})", 
            String::from("User:").bold().yellow(),
                                if m1 >= 0 {""} else {"-"}, m1.abs(), m1,
                                                  if m2 >= 0 {""} else {"-"}, m2.abs(), m2,
                                                                  if m3 >= 0 {""} else {"-"}, m3.abs(), m3);

    // =================================
    //  C: Evaluation
    let c_add = pc.add(&c1, &c2)?;
    let c_sub = pc.sub(&c1, &c2)?;
    let c_sgn = pc.sgn(&c3)?;
    let c_max = pc.max(&c1, &c2)?;

    // =================================
    //  U: Decryption
    let m_add  = pu.decrypt(&c_add)?;
    let m_sub  = pu.decrypt(&c_sub)?;
    let m_sgn  = pu.decrypt(&c_sgn)?;
    let m_max  = pu.decrypt(&c_max)?;

    infoln!("{} result\nm1 + m2 = {} :: {} (exp. {})\nm1 - m2 = {} :: {} (exp. {})\nsgn(m3) = {} :: {}\nmax{{m1, m2}} = {} :: {}",
              String::from("User:").bold().yellow(),
                    m_add,
                    if m_add - (m1+m2) % (1<<6) == 0 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                    (m1+m2) % (1<<6),
                            m_sub,
                            if m_sub - (m1-m2) % (1<<6) == 0 {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                            (m1-m2) % (1<<6),
                                    m_sgn,
                                    if m_sgn == m3.signum() {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()},
                                            m_max,
                                            if m_max == std::cmp::max(m1, m2) {String::from("PASS").bold().green()} else {String::from("FAIL").bold().red()});

    infobox!("Demo END");

    Ok(())
}
```

## License

Parmesan is licensed under AGPLv3.