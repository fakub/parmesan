require "yaml"

asc_ary = File.read("asc.dat").split("\n")

res = {}

asc_ary.each do |asc|
    n = asc.split.first.to_i
    res[n] = []

    vals = [1]

    asc.split("◖")[2..].each do |ads|
        ads = ads.split("◗").first.split
        # ads e.g.:   ["173", "=", "-3", "+", "11·2^4"]

        vals << ads.first.to_i

        l  = ads[2].to_i
        ra = ads.last.split(/[\s^·]/)
        r  = ra.first.to_i

        res[n] << {
            l_pos: (l > 0),
            l_idx: vals.find_index(l.abs),
            r_pos: (ads[3] == "+"),
            r_idx: vals.find_index(r),
            r_shift: ra.last.to_i,
        }
    end
end

File.write "asc-12.yaml", YAML.dump(res)
