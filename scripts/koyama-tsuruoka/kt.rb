#!/usr/bin/env ruby

val = ARGV[0].nil? ? rand(1 << 12) : ARGV[0].to_i.abs

def kt(k)

    # resolve trivial cases
    return [0] if k == 0
    return [1] if k == 1
    # |k| < 2 resolved

    #TODO implement as in ECC book
    k_len = Math::log2(k).floor + 1

    # grows max by 1 index
    k_vec = Array.new(k_len+1, 0);


    # =========================================================================
    #
    #  Koyama-Tsuruoka algorithm
    #
    j = 0;  m = 0;
    x = 0;  y = 0;  z = 0;
    u = 0;  v = 0;  w = 0;

    while x < k_len - 1 do   # orig: x < ⌊log_2 k⌋ .. which equals k_len - 1
        y = ((k >> x) & 1 == 1) ? y+1 : y-1
        x += 1
        if m == 0
            if y >= z+3
                while j < w do
                    k_vec[j] = ((k >> j) & 1)
                    j += 1
                end
                k_vec[j] = -1;  j += 1;
                v = y;  u = x;  m = 1;
            else
                if y < z
                    z = y; w = x;
                end
            end
        else
            if v >= y+3
                while j < u do
                    k_vec[j] = (((k >> j) & 1) - 1)
                    j += 1
                end
                k_vec[j] = 1;   j += 1;
                z = y;  w = x;  m = 0;
            else
                if y > v
                    v = y; u = x;
                end
            end
        end
    end

    if m == 0 || (m == 1 && v <= y)
        while j < x
            k_vec[j] = ((k >> j) & 1) - m
            j += 1
        end
        k_vec[j] = 1 - m
        k_vec[j+1] = m
    else
        while j < u do
            k_vec[j] = (((k >> j) & 1) - 1)
            j += 1
        end
        k_vec[j] = 1
        j += 1

        while j < x do
            k_vec[j] = ((k >> j) & 1)
            j += 1
        end
        k_vec[j] = 1
        k_vec[j+1] = 0
    end
    #
    # =========================================================================


    # get rid of leading zero, if any
    k_vec.pop if k_vec.last == 0

    k_vec
end

puts "#{val}: #{kt(val).reverse.to_s}"
