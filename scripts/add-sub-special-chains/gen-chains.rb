#!/usr/bin/env ruby

LIMIT_LOG = 10

class NumRepre

    attr_reader :BARY

    def initialize(bitary)
        raise "(!) NumRepre.new: bitary.len != #{LIMIT_LOG}." unless bitary.size == LIMIT_LOG
        raise "(!) NumRepre.new: out of alphabet {-1, 0, 1}." unless bitary.map{|e| e == 0 or e == 1 or e == -1 }.reduce(:&)

        @BARY = bitary.clone
    end

    def to_s
        "[#{self.eval}|#{@BARY.reverse.join(',')}]"
    end
    alias inspect to_s

    def eval
        v = 0
        @BARY.each.with_index do |e, ei|
            v += e * (1 << ei)
        end
        v
    end

    def add(other)
        raise "" unless other.class == self.class
        #TODO check that unit indexes are disjoint (little optimalization)

        self.class.new @BARY.zip(other.BARY).map{|e| e.first + e.last }
    end

    def NREP
        self
    end

    def nops
        0
    end

end

class ASPair

    attr_reader :NREP

    def initialize(pair)
        raise "(!) ASPair.new: not an Array/pair." unless pair.class == Array and pair.size == 2
        raise "(!) ASPair.new: wrong inner type(s)." unless pair.map{|e| e.class == NumRepre or e.class == ASPair }.reduce(:&)

        @PAIR = pair   # not clone!! keep links (?)
        @NREP = pair.first.NREP.add(pair.last.NREP)
    end

    def to_s
        "{#{@NREP}: #{@PAIR.first} + #{@PAIR.last} }"
    end
    alias inspect to_s

    def eval
        @NREP.eval
    end

    def nops
        @PAIR.first.nops + @PAIR.last.nops + 1
    end

end

# init DB .. TODO turn into Class
db = {}

# .. with trivial elements
LIMIT_LOG.times do |i|
    # gen i-th trivial +- elements
    posary = [0] * LIMIT_LOG
    posary[i] = 1
    negary = [0] * LIMIT_LOG
    negary[i] = -1

    pos = NumRepre.new posary
    neg = NumRepre.new negary

    db[pos.eval] = pos
    db[neg.eval] = neg
end

# do some magic: go through all pairs
prev_db = db.clone
prev_db.each do |u, pu|
    prev_db.each do |v, pv|
        # init ASPair
        begin
            p = ASPair.new [pu, pv]
            # if shorter than existing, update in db
            db[p.eval] = p if db[p.eval].nil? or db[p.eval].nops > p.nops
        rescue => error
            puts "Skipping #{pu.NREP} + #{pv.NREP}: #{error}"
        end
    end
end

# dump DB
puts "\n====    Dumping DB    ===="
db.sort_by{|v,pv| v }.each do |v, pv|
    puts "#{v}: #{pv}"
end

#~ do

#~ end while db.size < 1 << LIMIT_LOG
