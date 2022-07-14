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

#   BS complexity of addition (per bit)
A = 2                                       # 1 + 1, but needed

#   BS complexity of single-bit multiplication & single-bit square
M = 1
S = 1

# ------------------------------------------------------------------------------

#   BS complexity of schoolbook multiplication wrt parallel addition within resulting table (must be done manually or by some smart recursion / dynamic programming)
#TODO why this?? why not m(n)?
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

#   BS complexity of schoolbook multiplication  (~ 3 n^2)
#   mulary reduction:
#       - 1st BS -> n active bits
#       - 2nd BS does not apply to carry -> n bits
def m(n)
    M*n**2 + A*n*(n-1)                      #TODO shish: 2n(2n-1)
end
#   BS complexity of schoolbook squaring        (~ 2.5 n^2)
#TODO why was A*n*(n-1)? why not A*(n+1)*(n-1)?
def s(n)
    M*n*(n-1)/2 + S*n + A*n*(n-1)           #TODO shish: n(3n-2)
end

#   hash table for optimal BS complexity of multiplication (Karatsuba for 4 gives a very large number)
jm = {}
jm[0] = Float::NAN
jm[1] = m(1)    # =  M = 1
jm[2] = m(2)    # =  8
jm[3] = m(3)    # = 21
jm[4] = m(4)    # = 40

#   hash table for optimal BS complexity of squaring (Div'n'Conq for 3 gives shish)
js = {}
js[0] = Float::NAN
js[1] = s(1)    # =  S = 1
js[2] = s(2)    # =  7
js[3] = s(3)    # = 18

#   calc the optimal BS complexity of multiplication
(2..16).each do |n|
    # Karatsuba
    #FIXME the values will be different after keeping the extra bit that comes from recursion
    k0 = 2*jm[n] + jm[n+1] +           A*(2*n     + 2*(n+1) + 3*n  )            # K_2n:     3 mul's, 3 add's
    k1 =   jm[n] + jm[n+1] + jm[n+2] + A*(2*(n+1) + 2*(n+2) + 3*n+1)            # K_2n+1:   3 mul's, 3 add's
    # schoolbook mult
    m0 = m(2*n)
    m1 = m(2*n + 1)
    # optimal mult
    jm[2*n] = [k0, m0].min
    jm[2*n+1] = [k1, m1].min
    # print out
    puts "Jm[#{2*n}] = #{jm[2*n]} #{k0 < m0 ? "by " + "Karatsuba".bold + ": [#{n} | #{n} ; #{n+1}] (scb =" : "by schoolbook#{n <= 4 ? " /??#{MP[2*n]} prl/" : ""} (Kar ="} #{[k0, m0].max})"
    puts "Jm[#{2*n+1}] = #{jm[2*n+1]} #{k1 < m1 ? "by " + "Karatsuba".bold + ": [#{n} | #{n+1} ; #{n+2}] (scb =" : "by schoolbook#{n <= 3 ? " /??#{MP[2*n+1]} prl/" : ""} (Kar ="} #{[k1, m1].max})"
end

puts "-" * 80

#   calc the optimal BS complexity of squaring
(2..16).each do |n|
    # divide-and-conquer
    d0 = 2*js[n] + jm[n] + A*(3*n-1)                # 3n-1 .. 2AB is shifted one bit (hence there occurs triv zero)
    d1 =   js[n] + js[n+1] + jm[n+1] + A*(3*n)
    # schoolbook square
    s0 = s(2*n)
    s1 = s(2*n + 1)
    # optimal square
    js[2*n] = [d0, s0].min
    js[2*n+1] = [d1, s1].min
    # print out
    puts "Js[#{2*n}] = #{js[2*n]} #{d0 < s0 ? "by " + "Div & Conq".bold + ": [sq-#{n} | sq-#{n} ; mul-#{n}] (scb =" : "by schoolbook (D&Q ="} #{[d0, s0].max})"
    puts "Js[#{2*n+1}] = #{js[2*n+1]} #{d1 < s1 ? "by " + "Div & Conq".bold + ": [sq-#{n} | sq-#{n+1} ; mul-#{n+1}] (scb =" : "by schoolbook (D&Q ="} #{[d1, s1].max})"
end
