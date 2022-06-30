use crate::userovo::encryption;

pub fn wind_shifts(
    k: u32,
    bitlen: usize,
) -> Vec<(i32, usize)> {
    // pairs of window values and shifts, built-up from certain NAF (or other repre)
    let mut ws: Vec<(i32, usize)> = Vec::new();

    //TODO prospectively Koyama-Tsuruoka "NAF"
    let k_vec = naf_vec(k);

    //DBG
    println!("k = {:?} ({})", k_vec, k);

    // sliding window
    let mut sh = 0usize;
    loop {
        // find next non-zero (short circuit eval)
        while sh < k_vec.len() && k_vec[sh] == 0 {sh += 1;}

        // take window of size bitlen -> convert to scalar -> push to result (n.b.! Rust's ranges!)
        let w = k_vec[sh..=(if sh + bitlen - 1 >= k_vec.len() {k_vec.len()-1} else {sh + bitlen-1})].to_vec();

        //DBG
        println!("    window = {:?} << {}", w, sh);

        let wi = encryption::convert(&w).expect("encryption::convert failed.");

        //DBG
        println!("    w_val = {}", wi);

        ws.push((wi as i32,sh));

        // increment shift/index
        sh += bitlen;

        // whole vector processed
        if sh >= k_vec.len() {break;}
    }

    ws
}

pub fn naf_vec(k: u32) -> Vec<i32> {

    // resolve trivial cases
    if k == 0 {return vec![0];}
    if k == 1 {return vec![1];}

    // |k| < 2 resolved -> set len = 2 and continue from 0b100
    let mut k_len = 2usize;
    // 1 << 31 is indeed 0b100..00 (for u32)
    for i in 2..=31 {if k & (1 << i) != 0 {k_len = i + 1;}}   //TODO as macro?

    // k as a vector of bits
    // replace sequences of 1's with 1|zeros|-1
    //
    // index   11  10   9   8   7   6   5   4   3   2   1   0
    //
    //          0   1   1   1   0   1   1   1   1   0   1   1
    //          1   0   0  -1   1   0   0   0  -1   1   0  -1       first hit
    //          1   0   0   0  -1   0   0   0   0  -1   0  -1       second hit
    //
    // e.g.: k = 0b11001110011110011011101111;
    // first hit:   [-1, 0, 0, 0, 1, -1, 0, 0, 1, -1, 0, 1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 1, 0, -1, 0, 1]
    // second hit:  [-1, 0, 0, 0, -1, 0, 0, 0, -1, 0, 0, 1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 1, 0, -1, 0, 1]

    let mut k_vec: Vec<i32> = Vec::new();
    let mut low_1: usize = 0;
    for i in 0..=k_len {
        // add a bit of k to the vector (including a leading zero)
        k_vec.push(((k >> i) & 1) as i32);

        if (k >> i) & 1 == 0 {
            // at least two consecutive ones: i - low_1
            if i - low_1 > 1 {
                //  i             low_1
                //  0   1   1   1   1   0
                //  1   0   0   0  -1   0
                //
                // the new -1 can meet 1 from previous steps (if any): -1   1   0   =>  0  -1   0
                if low_1 > 0 && k_vec[low_1-1] == 1 {
                    k_vec[low_1-1] = -1;
                    k_vec[low_1] = 0;
                } else {
                    k_vec[low_1] = -1;
                }
                for j in low_1+1..i {
                    k_vec[j] = 0;
                }
                k_vec[i] = 1;
            }
            // move "pointer" forward
            low_1 = i + 1;
        }
        // k == 1 .. keep "pointer" at its current/previous position -> do nothing
    }

    k_vec
}

//TODO implement Koyama-Tsuruoka "NAF"
