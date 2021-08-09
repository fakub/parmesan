#!/usr/bin/env ruby

class String
    def red
        "\e[31m#{self}\e[0m"
    end
    def green
        "\e[32m#{self}\e[0m"
    end
    def bold
        "\e[1m#{self}\e[22m"
    end
end

#   BS complexity of single addition
A = 2                                       # 1 + 1, but needed

#   BS complexity of single multiplication
M = 2                                       # 2 (+ 1), possibly not needed

# ------------------------------------------------------------------------------

#   BS complexity of schoolbook multiplication wrt parallel addition within resulting table (must be done manually or by some smart recursion / dynamic programming)
MP = {}
MP[0] = Float::NAN
MP[1] = 2
MP[2] = 2**2 * MP[1] + 1 * (2 * A)
MP[3] = 3**2 * MP[1] + 1 * (3 * A) + 3 * A                                      # (1 + 2) + 3 .. this saves most BS
MP[4] = 4**2 * MP[1] + 2 * (4 * A) + 6 * A                                      # (1 + 2) + (3 + 4)
MP[5] = 5**2 * MP[1] + 2 * (5 * A) + 7 * A + 6 * A                              # ((1 + 2) + (3 + 4)) + 5   ..   same #BS as (1 + 2) + ((3 + 4) + 5)
                                                                                # Karatsuba = 160 (for both 3|2 and 2|3 splittings)
MP[6] = 6**2 * MP[1] + 3 * (6 * A) + 8 * A + 8 * A                              # as M_3; Karatsuba > 160 (this is 140), i.e., still better
MP[7] = 7**2 * MP[1] + 3 * (7 * A) + 7 * A + 9 * A + 10 * A                     # top-bottom; Karatsuba = 260
MP[8] = 8**2 * MP[1] + 4 * (8 * A) + 2 * (10 * A) + 13 * A                      # Karatsuba > 260 (this is 258)
# ...

# ------------------------------------------------------------------------------

#   BS complexity of schoolbook multiplication
def m(n)
    2*n * (2*n - 1)
end

#   hash table for optimal BS complexity of multiplication
j = {}
j[0] = Float::NAN
j[1] = M
j[2] = 12
j[3] = 30
j[4] = 56

#   calc the optimal BS complexity of multiplication
(2..16).each do |n|
    # Karatsuba
    k0 = 2*j[n] + j[n+1] +          20*n +  2               # K_2n
    k1 =   j[n] + j[n+1] + j[n+2] + 20*n + 14               # K_2n+1
    # schoolbook
    m0 = m(2*n)
    m1 = m(2*n + 1)
    # optimal
    j[2*n] = [k0, m0].min
    j[2*n+1] = [k1, m1].min
    puts "J[#{2*n}] = #{j[2*n]} #{k0 < m0 ? "by " + "Karatsuba".bold + ": [#{n} | #{n} ; #{n+1}] (scb =" : "by schoolbook#{n <= 4 ? " /#{MP[2*n]} prl/" : ""} (Kar ="} #{[k0, m0].max})"
    puts "J[#{2*n+1}] = #{j[2*n+1]} #{k1 < m1 ? "by " + "Karatsuba".bold + ": [#{n} | #{n+1} ; #{n+2}] (scb =" : "by schoolbook#{n <= 3 ? " /#{MP[2*n+1]} prl/" : ""} (Kar ="} #{[k1, m1].max})"
end
