#!/usr/bin/env ruby

LIMIT_WID = 12
#~ DBG = true
DBG = false

# equivalence class containing the only positive odd number as its representative
# !! n.b., non-overlapping 1's assumption !!
#   => this is only exhaustive for chains with 2 and less additions
#   for chains with 3 and more additions, it might worth using overlapping bits
#   e.g. (maybe) 1 -> 1001 -> 10010001001 -> 100100010100010001001 (overlap & 3 add's)
#        naively 1 -> 1001 -> 10010001    -> 1001000101 -> 10010001010001 -> 100100010100010001001 (no overlap & 5 add's)
class OddClass

    attr_reader :p, :p_pos, :q, :q_pos, :r, :val, :wid, :posi, :negi

    def initialize(p_pos = nil, p = nil, q_pos = nil, q = nil, r = nil)
        if p.nil?
            @p_pos  = nil   # +-
            @p      = nil   #    p
            @q_pos  = nil   # +-                ...   +-p +- 2^r q
            @q      = nil   #    q
            @r      = 0     #       2^r

            @val = 1
            @wid = 1

            @posi = [0]
            @negi = []
        else
            raise ArgumentError unless p.class == OddClass and q.class == OddClass and r.class == Integer and r > 0

            @p_pos  = p_pos ? true : false   # makes it boolean
            @p      = p
            @q_pos  = q_pos ? true : false   # makes it boolean
            @q      = q
            @r      = r

            @val = (p_pos ? 1 : -1) * @p.val + (q_pos ? 1 : -1) * @q.val * (1 << r)
            @wid = [p.wid, q.wid + r].max

            q_posi = q.posi.map{|e| e + r }
            q_negi = q.negi.map{|e| e + r }

            @posi = (p.posi + q_posi).sort
            @negi = (p.negi + q_negi).sort
            # this is the overlap check, which must not be applied for 3-add's and more
            # raise "[OddClass::new] Overlapping 1-positions." unless (@posi + @negi).uniq.size == p.posi.size + p.negi.size + q_posi.size + q_negi.size
        end
    end

    def unit?
        @p.nil?
    end

    def to_s
        "◖ #{@val}" + (@p.nil? ? "" : " = #{@p_pos ? ' ' : '-'}#{@p.val} #{@q_pos ? '+' : '-'} #{@q.val}·2^#{@r}") + " ◗"
    end
    alias inspect to_s

    #~ def val_calc
        #~ # binary calc
    #~ end

    #~ def wid_calc
        #~ # max posi/negi
    #~ end
end

class ASChain < Array

    #~ def initialize(*args)
        #~ super *args
        #~ raise "[ASChain::new] Invalid chain contents (expecting OddClass)." unless chain.map{|e| e.class == OddClass }.reduce(:&)
        #~ raise "[ASChain::new] Invalid chain contents (expecting OddClass)." unless chain
    #~ end

    # this is also problematic for longer chains (however, does not affect last round, useful only to generate all of the intermediates)
    # is it problematic for 3-chains? no.
    def merge(other)
        raise "[ASChain::#{__method__}] Merging with non-ASChain class." unless other.class == ASChain
        difi = self.size
        self.zip(other).each.with_index do |p,i|
            if p[0].nil? or p[1].nil? or p[0].val != p[1].val
                difi = i
                break
            end
        end
        raise "[ASChain::#{__method__}] Chains differ even in first element, which is supposed to be ◖ 1 ◗." if difi == 0
        ASChain[*(self + other[difi..])]
    end

    def to_s
        #~ "C:" + super
        super
    end
    alias inspect to_s

end

def extend_chains_ary(chains_arys, db)
    # check proper structure of chains array
    # expects [[ASChain[1]], [ASChain[1,3],ASChain[1,5],...]]
    raise "[#{__method__}] Invalid structure of array of arrays of chains (or wrong chains' length)." \
        unless chains_arys.map.with_index{|cary,ci| cary.map{|c| c.class == ASChain and c.size == ci+1 }.reduce(:&)}.reduce(:&)

    ecs = []
    lvl = chains_arys.last.last.size

    puts "Loop p ..." if DBG
    # loop p (in all existing chains)
    chains_arys.flatten(1).each do |cp|
        puts "  chain for p = #{cp}" if DBG
        # loop q
        chains_arys.flatten(1).each do |cq|
            puts "    chain for q = #{cq}" if DBG

            # check if the combination of chosen chains gives expected length
            cpq = cp.merge(cq)
            next if cpq.size != lvl

            #~ (1..LIMIT_WID).each do |r|
            # for 3-add's chains, it seems that deleting the leading 1 does not bring anything new
            # however, for 5-add's, there apparently is an example: 10110011011000110110011011
            (1..LIMIT_WID-cq.last.wid).each do |r|
                puts "      r = #{r}" if DBG
                [true, false].each do |p_pos|
                    [true, false].each do |q_pos|
                        begin
                            on = OddClass.new(p_pos, cp.last, q_pos, cq.last, r)
                            if on.val > 0 and db[on.val].nil?
                                puts "      Adding #{on}" if DBG
                                ecs << ASChain[*(cpq + [on])]
                                db[on.val] = ASChain[*(cpq + [on])]
                            end
                        rescue => error
                            puts "Skipping: #{error}" if DBG
                        end
                    end
                end
            end
        end
    end

    ecs
end

# init chains array with [[◖ 1 ◗]]
chains = [[ASChain[OddClass.new]]]
# init DB of values <=> chains
db = {1 => ASChain[OddClass.new]}

# 1st extend
chains << extend_chains_ary(chains, db)

# 2nd extend
chains << extend_chains_ary(chains, db)

# 3rd extend
chains << extend_chains_ary(chains, db)

# 4th extend
chains << extend_chains_ary(chains, db)

# print DB
i = 1
wpr = false
db.sort_by{|v,c| v }.each do |v, c|
    if v > i
        puts "----"
        i = v
    end
    if v > (1 << (LIMIT_WID-1)) and not wpr
        puts "====    no guarantee    ===="
        wpr = true
    end
    i += 2
    puts "#{wpr ? "  ? " : ""}#{"%5d" % [v]} /#{c.size-1}/ #{c}"
end
