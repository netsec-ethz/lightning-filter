lf_proto = Proto("LF", "LightningFilter Protocol")

local lf_isd = ProtoField.uint16("lf.isd", "ISD")
local lf_as = ProtoField.string("lf.as", "AS")
local lf_drkey_proto = ProtoField.uint16("lf.drkey_proto", "DRKey Protocol")
local lf_reserved = ProtoField.uint8("lf.reserved", "Reserved")
local lf_payload_proto = ProtoField.uint8("lf.payload_proto", "Payload Protocol")
local lf_timestamp = ProtoField.bytes("lf.time_stamp","Timestamp")
local lf_hash = ProtoField.bytes("lf.hash", "Packet Hash")
local lf_mac = ProtoField.bytes("lf.mac", "MAC")

lf_proto.fields = {
    lf_isd,
    lf_as,
    lf_drkey_proto,
    lf_reserved,
    lf_payload_proto,
    lf_timestamp,
    lf_hash,
    lf_mac
}

function lf_proto.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = lf_proto.name
    local subtree = tree:add(lf_proto, buffer(), "LightningFilter Protocol Data")

    subtree:add(lf_isd, buffer(0,2))
    subtree:add(lf_as, as_str(buffer(2,6)))
    subtree:add(lf_drkey_proto, buffer(8,2))
    subtree:add(lf_reserved, buffer(10,1))
    subtree:add(lf_payload_proto, buffer(11,1))
    subtree:add(lf_timestamp, buffer(12,8))
    subtree:add(lf_hash, buffer(20,20))
    subtree:add(lf_mac, buffer(40,16))
end

function as_str(as)
    local asDec = as:uint64():tonumber()
    if asDec <= 0xffffffff then
        return string.format("%d", asDec)
    end
    return string.format("%x:%x:%x", as(0, 2):uint(), as(2, 2):uint(), as(4, 2):uint())
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(49149, lf_proto)

