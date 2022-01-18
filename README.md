# Parmesan

*Parallel ARithMEticS on tfhe ENcrypted data*

Parmesan implements selected parallel algorithms for multi-digit arithmetics over TFHE ciphertexts. Namely:

- addition/subtraction,
- scalar multiplication (i.e., multiplication by a known integer),
- multiplication,
- squaring,
- signum,
- maximum of two numbers, and
- evaluation of a simple neural network.

## The Short Story

In the standard integer representation, parallel addition is not possible due to the carry, which can propagate all the way from the LSB to the MSB. However, using, e.g., an alphabet `{-1,0,1}` for base-2 integer representation, a parallel addition algorithm does exist.

## The Long Story

See our [full paper](https://eprint.iacr.org/2022/067).

## Use `parmesan`

Add a dependency to your `Cargo.toml` file in your Rust project. (Currently only from git or locally.)

```toml
[dependencies]
parmesan = { git = "https://gitlab.fit.cvut.cz/klemsjak/parmesan" }
# or:
parmesan = { path = "../parmesan" }
```

For the best performance, we recommend to compile & run with the `RUSTFLAGS="-C target-cpu=native" cargo run --release` command.

## Example

```rust
use std::error::Error;

use parmesan::params;
use parmesan::userovo::*;
use parmesan::ParmesanUserovo;
use parmesan::ParmesanCloudovo;
use parmesan::arithmetics::ParmArithmetics;

pub fn main() -> Result<(), Box<dyn Error>> {

    // =================================
    //  Initialization
    // ---------------------------------
    //  Global Scope
    let par = &params::PARM90__PI_5__D_20__LEN_32;
    // ---------------------------------
    //  Userovo Scope
    let pu = ParmesanUserovo::new(par)?;
    let pub_k = pu.export_pub_keys();
    // ---------------------------------
    //  Cloudovo Scope
    let pc = ParmesanCloudovo::new(par, &pub_k);

    // =================================
    //  U: Encryption
    let a: Vec<i32> = vec![1,0,1,-1,-1,0,-1,1,1,-1,1,1,1,-1,-1,0,0,1,1,0,0,0,0,-1,0,0,0,0,0,-1,0,0,];
    let b: Vec<i32> = vec![-1,0,0,-1,1,1,-1,1,-1,0,0,1,0,1,1,0,0,0,-1,0,0,1,0,0,-1,0,-1,-1,-1,1,1,0,];
    let ca = pu.encrypt_vec(&a)?;
    let cb = pu.encrypt_vec(&b)?;
    // convert to actual numbers
    let a_val = encryption::convert(&a)?;
    let b_val = encryption::convert(&b)?;
    // print plain inputs
    println!("\nInputs:\n");
    println!("a   = {:12}", a_val);
    println!("b   = {:12}", b_val);

    // =================================
    //  C: Evaluation
    let c_add_a_b = ParmArithmetics::add(&pc, &ca, &cb);

    // =================================
    //  U: Decryption
    let add_a_b = pu.decrypt(&c_add_a_b)?;

    let mut summary_text = format!("\nResults:\n");
    summary_text = format!("{}\nAddition:", summary_text);
    summary_text = format!("{}\na + b         = {:12} :: {} (exp. {})", summary_text,
                            add_a_b,
                            if add_a_b == a_val + b_val {"PASS"} else {"FAIL"},
                            a_val + b_val
    );

    println!("{}", summary_text);

    println!("\nDemo END\n");

    Ok(())
}
```

## License

Parmesan is licensed under AGPLv3.