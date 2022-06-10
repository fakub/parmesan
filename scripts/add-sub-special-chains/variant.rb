#!/usr/bin/env ruby

LIMIT_WID = 13
#~ DBG = true
DBG = false

# equivalence class containing the only positive odd number as its representative
# !! n.b., non-overlapping 1's assumption !!
#   => this is only exhaustive for chains with 2 and less additions
#   for chains with 3 and more additions, it might worth using overlapping bits
#   e.g. (maybe) 1 -> 1001 -> 10010001001 -> 100100010100010001001 (overlap & 3 add's)
#        naively 1 -> 1001 -> 10010001    -> 1001000101 -> 10010001010001 -> 100100010100010001001 (no overlap & 5 add's)
#   for sure this has shown for 805
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
            # this is the overlap check, which must not be applied for 3-add's and more (btw only place where posi/negi are used)
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
    # for longer: it should be safe to merge like set union
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

    def to_vals
        self.map do |on|
            on.val
        end
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

    #~ $stderr.puts "Loop p ..." if DBG
    # loop p (in all existing chains .. of the form [ASChain[1], ASChain[1,3], ASChain[1,5], ...])
    chains_arys.flatten(1).each do |cp|
        #~ $stderr.puts "  chain for p = #{cp}" if DBG
        # loop q
        chains_arys.flatten(1).each do |cq|
            #~ $stderr.puts "    chain for q = #{cq}" if DBG

            # check if the combination of chosen chains gives expected length
            cpq = cp.merge(cq)
            next if cpq.size != lvl

            #~ (1..LIMIT_WID).each do |r|
            # for 3-add's chains, it seems that deleting the leading 1 does not bring anything new
            # however, for 5-add's, there apparently is an example: 10110011011000110110011011

            # possible issues:
            #   1) only the 1st variant found is added to the DB and chain ary
            #   2) only the last elements of both chains are taken (indeed an issue? all subchains are in the chain ary)
            (1..LIMIT_WID-cq.last.wid).each do |r|
                #~ $stderr.puts "      r = #{r}" if DBG
                [true, false].each do |p_pos|
                    [true, false].each do |q_pos|
                        #~ begin   # when checking non-overlap condition
                            on = OddClass.new(p_pos, cp.last, q_pos, cq.last, r)
                            if on.val > 0
                                cand_chain = ASChain[*(cpq + [on])]
                                # add whenever chain is optimal (TODO check that intermediates differ !! implement ASChain comparison?)
                                if db[on.val].nil? or \
                                    (db[on.val].first.size == cand_chain.size and not db[on.val].map{|asc|asc.to_vals}.include?(cand_chain.to_vals))
                                    #~ $stderr.puts "      Adding #{on}" if DBG
                                    #~ puts "      Adding #{on} cause db[on.val].nil? #{db[on.val].nil?} ; db[on.val].first.size - 1 = #{db[on.val].nil? ? "NIL" : db[on.val].first.size - 1} ; lvl = #{lvl}" if on.val == 3
                                    ecs << cand_chain
                                    if db[on.val].nil?
                                        db[on.val] = [cand_chain]
                                    else
                                        db[on.val] << cand_chain
                                    end
                                end
                            end
                        #~ rescue => error
                            #~ $stderr.puts "Skipping: #{error}" if DBG
                        #~ end
                    end
                end
            end
        end
        $stderr.puts "----    Done with chain p = #{cp}"
    end

    ecs
end

# init chains array with [[◖ 1 ◗]]
chains = [[ASChain[OddClass.new]]]
# init DB of values <=> chains
db = {1 => [ASChain[OddClass.new]]}

# 1st extend
chains << extend_chains_ary(chains, db)
$stderr.puts "====    1st extend FINISHED    ===="

# 2nd extend
chains << extend_chains_ary(chains, db)
$stderr.puts "====    2nd extend FINISHED    ===="

# 3rd extend
chains << extend_chains_ary(chains, db)
$stderr.puts "====    3rd extend FINISHED    ===="

# 4th extend
chains << extend_chains_ary(chains, db)
$stderr.puts "====    4th extend FINISHED    ===="

# print DB
i = 1
wpr = false
db.sort_by{|v, ca| v }.each do |v, ca|
    if v > i
        puts "----"
        i = v
    end
    if v > (1 << (LIMIT_WID-1)) and not wpr
        puts "====    no guarantee    ===="
        wpr = true
    end
    i += 2
    puts "#{wpr ? "  ? " : ""}#{"%5d" % [v]} /#{ca.first.size-1}/ #{ca.first}"
    #~ puts "#{wpr ? "  ? " : ""}#{"%5d" % [v]} /#{ca.first.size-1}/ #{ca.first}#{ca.size > 1 ? " (other #{ca.size-1} chains)" : ""}"
end
