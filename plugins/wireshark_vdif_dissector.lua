--[[
Copyright (c) 2023 Center for Astrophysics | Harvard & Smithsonian

This software is licensed for use as described in the LICENSE file in
the root directory of this distribution.

Originator: Lindy Blackburn 1 Jan 2024

This is a custom VDIF frame dissector script for Wireshark. It is placed
directly in the Wireshark user plugin folder.
]]

local p_vdif = Proto("VDIF", "VLBI Data Interchange Format")

-- header fields by word: https://github.com/difx/difx/blob/main/libraries/vdifio/src/vdifio.h
-- note that within each word, the byte (and bit) order is LSB to MSB
local vdif_header = {
    {{'seconds', 30}, {'legacymode', 1}, {'invalid', 1}},
    {{'frame', 24}, {'epoch', 6}, {'unassigned', 2}},
    {{'framelength8', 24}, {'nchan', 5}, {'version', 3}},
    {{'stationid', 16}, {'threadid', 10}, {'nbits', 5}, {'iscomplex', 1}},
    {{'extended1', 24}, {'eversion', 8}},
    {{'extended2', 32}},
    {{'extended3', 32}},
    {{'extended4', 32}}
}
local vdif_edv2_header = {
    {{'seconds', 30}, {'legacymode', 1}, {'invalid', 1}},
    {{'frame', 24}, {'epoch', 6}, {'unassigned', 2}},
    {{'framelength8', 24}, {'nchan', 5}, {'version', 3}},
    {{'stationid', 16}, {'threadid', 10}, {'nbits', 5}, {'iscomplex', 1}},
    {{'polblock', 1}, {'quadrantminus1', 2}, {'correlator', 1}, {'sync', 20}, {'eversion', 8}},
    {{'status', 32}},
    {{'psn_upper', 32}},  -- Upper 32 bits of the 64-bit psn
    {{'psn_lower', 32}}   -- Lower 32 bits of the 64-bit psn
}
local vdif_edv2_header_r2dbe = {
    {{'seconds', 30}, {'legacymode', 1}, {'invalid', 1}},
    {{'frame', 24}, {'epoch', 6}, {'unassigned', 2}},
    {{'framelength8', 24}, {'nchan', 5}, {'version', 3}},
    {{'stationid', 16}, {'threadid', 10}, {'nbits', 5}, {'iscomplex', 1}},
    {{'polblock', 1}, {'bdcsideband', 1}, {'rxsideband', 1}, {'undefined', 1}, {'subsubversion', 20}, {'eversion', 8}},
    {{'ppsdiff', 32}},
    {{'psn_upper', 32}},  -- Upper 32 bits of the 64-bit psn
    {{'psn_lower', 32}}   -- Lower 32 bits of the 64-bit psn
}

-- set a header table to use for parsing
local htable = vdif_edv2_header_r2dbe

p_vdif.fields.data = ProtoField.bytes("vdif.data", "Data", base.NONE)

-- the ProtoFields must be allocated here outside of the dissector function
for iword, flist in ipairs(htable) do
    local wstart = 4*(iword-1)
    local wname = "word" .. (iword-1)
    p_vdif.fields[wname] = ProtoField.bytes("vdif." .. wname, wname, base.NONE)

    local fstart = 0
    for ifield, fpar in ipairs(htable[iword]) do
        local fname, flen = unpack(fpar)
        -- bitmask is used to obtain the fields within each header word
        p_vdif.fields[fname] = ProtoField.uint32("vdif." .. fname, fname, base.DEC, nil, (2^flen-1)*2^fstart)
        fstart = fstart + flen
    end
end

function p_vdif.dissector(buffer, pinfo, tree)

    pinfo.cols.protocol = "VDIF"
    local vtree = tree:add(p_vdif, buffer())

    for iword, flist in ipairs(htable) do
        local wstart = 4*(iword-1)
        local wname = "word" .. (iword-1)
        local wtree = vtree:add(p_vdif.fields[wname], buffer(wstart, 4))

        local fstart = 0
        for ifield, fpar in ipairs(htable[iword]) do
            fname, flen = unpack(fpar)
            -- add_le each field as a subtree within the header word tree (little endian repr)
            wtree:add_le(p_vdif.fields[fname], buffer(wstart, 4))
        end
    end

    -- remaininng data array payload
    local hsize = 8*4
    local dsize = buffer:len() - hsize
    vtree:add(p_vdif.fields.data, buffer(hsize, dsize)):set_text("Data Array (" .. dsize .. " bytes)")

    return true
end

-- if restricted to a single send/recv port, it will be more efficient to select only that port here
-- local udp_dissector_table = DissectorTable.get("udp.port")
-- udp_dissector_table:add(4660, p_vdif)

-- otherwise we can have the dissector run on all UDP packets
-- if there are non-VDIF UDP packets, identify and return false at the top of the dissector function
p_vdif:register_heuristic("udp", p_vdif.dissector)

