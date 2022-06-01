#!/usr/bin/env ruby

LIMIT_LOG = 10
DBG = false

# equivalence class containing the only positive odd number as its representative
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
            raise "[OddClass::new] Overlapping 1-positions." unless (@posi + @negi).uniq.size == p.posi.size + p.negi.size + q_posi.size + q_negi.size
        end
    end

    def to_s
        "( #{@val}" + (@p.nil? ? "" : " | #{@p_pos ? ' ' : '-'}#{@p.val} #{@q_pos ? '+' : '-'} #{@q.val}·2^#{@r}") + " )"
    end
    alias inspect to_s

    #~ def val_calc
        #~ # binary calc
    #~ end

    #~ def wid_calc
        #~ # max posi/negi
    #~ end
end

def extend_chain(chain, db)
    raise "[extend_chain] Invalid chain contents." unless chain.map{|e| e.class == OddClass }.reduce(:&)

    ecs = []

    puts "Loop p ..." if DBG
    # loop p
    chain.each do |p|
        puts "  p = #{p}" if DBG
        # loop q
        chain.each do |q|
            puts "    q = #{q}" if DBG
            #~ (1..LIMIT_LOG).each do |r|
            (1..LIMIT_LOG-q.wid+1).each do |r|
                puts "      r = #{r}" if DBG
                [true, false].each do |p_pos|
                    [true, false].each do |q_pos|
                        begin
                            on = OddClass.new(p_pos, p, q_pos, q, r)
                            if on.val > 0
                                puts "      Adding #{on}" if DBG
                                ecs << (chain + [on])
                                db[on.val] = chain + [on] if db[on.val].nil?
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

# init chain
chain = [OddClass.new]
db = {1 => [OddClass.new]}

# 1st extend
ecs = extend_chain chain, db

# 2nd extend
eccs = []
ecs.each do |ec|
    eccs += extend_chain ec, db
end

# 3rd extend
ecccs = []
eccs.each do |ecc|
    ecccs += extend_chain ecc, db
end

#~ # 4th extend
#~ # eccccs = []
#~ ecccs.each do |eccc|
    #~ # eccccs += extend_chain ecc, db
    #~ extend_chain eccc, db
#~ end

# print DB
i = 1
db.sort_by{|v,c| v }.each do |v, c|
    if v > i
        puts "---"
        i = v
    end
    i += 2
    puts "#{v}: #{c}"
end
