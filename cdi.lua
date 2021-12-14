--[[ Copyright 2021 Open Broadcast Systems Ltd.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. --]]

cdi_protocol = Proto("CDI", "AWS CDI Protocol")

version = ProtoField.int8("cdi.version", "version", base.DEC)
major = ProtoField.int8("cdi.major", "major", base.DEC)
probe = ProtoField.int8("cdi.probe", "probe", base.DEC)
cmd   = ProtoField.int32("cdi.cmd", "cmd", base.DEC, { "Reset", "Ping", "Connected", "Ack", "ProtocolVersion" })
senders_ip = ProtoField.string("cdi.senders_ip", "senders_ip")
senders_gid = ProtoField.ipv6("cdi.senders_gid", "senders_gid")
senders_qpn = ProtoField.ipv6("cdi.senders_qpn", "senders_qpn")
senders_name = ProtoField.string("cdi.senders_name", "senders_name")
ctrl_dst_port = ProtoField.uint16("cdi.ctrl_dstport", "ctrl_dstport", base.DEC)
ctrl_pkt_num = ProtoField.uint16("cdi.ctrl_pktnum", "ctrl_pktnum", base.DEC)
checksum = ProtoField.uint16("cdi.checksum", "checksum", base.HEX)
calculated_checksum = ProtoField.uint16("cdi.calculated_checksum", "calculated_checksum", base.HEX)
ack_cmd   = ProtoField.int32("cdi.ack_cmd", "ack_cmd", base.DEC, { "Reset", "Ping", "Connected", "Ack", "ProtocolVersion" })
ack_ctrl_pkt_num = ProtoField.uint16("cdi.ack_ctrl_pktnum", "ack_ctrl_pktnum", base.DEC)
requires_ack = ProtoField.bool("cdi.requires_ack", "requires_ack")

cdi_protocol.fields = { version, major, probe, cmd, senders_ip, senders_gid, senders_qpn, senders_name, ctrl_dst_port, ctrl_pkt_num, checksum, ack_cmd, ack_ctrl_pkt_num, requires_ack, calculated_checksum }

-- checksum field must be zero when calculating checksum itself
function read_buf(buffer, i, cksum_offset)
    if i == cksum_offset or i == cksum_offset + 1 then return 0 end
    return buffer:get_index(i)
end

function do_checksum(buffer, len, cksum_offset)
  local cksum = 0
  local i = 0

  while len > 1 do
    local a = read_buf(buffer, i, cksum_offset)
    local b = read_buf(buffer, i + 1, cksum_offset)
    cksum = cksum + a + b * 2^8
    len = len - 2
    i = i + 2
  end

  if len == 1 then
    cksum = cksum + read_buf(buffer, i, cksum_offset)
  end

  cksum = math.floor(cksum / 2^16) + (cksum % 2^16)
  cksum = cksum + math.floor(cksum / 2^16)
  cksum = (-1 - cksum) % 2^32

  return cksum % 2^16
end

local function heuristic_checker(buffer, pinfo, tree)
  local length = buffer:len()
  local expected_length = 247
  if length < expected_length then return end

  local i = 0
  local v = buffer(i, 1)
  local version = v:bytes():get_index(0)
  i = i + 1

  if version == 1 then expected_length = expected_length + 4 end
  if length < expected_length then return end

  i = i + 2
  cmd_val = buffer(i,4)
  i = i + 4

  local cksum_offset = expected_length - 2

  if cmd_val:le_uint() == 4 then -- ack
    expected_length = expected_length + 6
  else
    expected_length = expected_length + 1
  end
  if length ~= expected_length then return false end


  local c = do_checksum(buffer:bytes(0, length), length, cksum_offset)
  local c2 = buffer:bytes():get_index(cksum_offset) + buffer:bytes():get_index(cksum_offset+1) * 2^8
  if c ~= c2 then return false end

  cdi_protocol.dissector(buffer, pinfo, tree)
  return true
end

function cdi_protocol.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = cdi_protocol.name

  local subtree = tree:add(cdi_protocol, buffer(), "CDI Protocol Data")

  local i = 0
  local v = buffer(i, 1)
  subtree:add(version, v)
  local version = v:bytes():get_index(0)
  i = i + 1

  subtree:add(major, buffer(i,1))
  i = i + 1
  subtree:add(probe, buffer(i,1))
  i = i + 1
  cmd_val = buffer(i,4)
  i = i + 4
  subtree:add_le(cmd, cmd_val)

  subtree:add(senders_ip, buffer(i,64))
  i = i + 64

  subtree:add(senders_gid, buffer(i, 16))
  i = i + 16

  subtree:add(senders_qpn, buffer(i, 16))
  i = i + 16

  subtree:add(senders_name, buffer(i,138))
  i = i + 128 + 10

  if version == 1 then
    i = i + 4 -- senders_stream_identifier, removed in v2
  end

  subtree:add_le(ctrl_dst_port, buffer(i,2))
  i = i + 2

  subtree:add_le(ctrl_pkt_num, buffer(i,2))
  i = i + 2

  subtree:add_le(checksum, buffer(i,2))
  local cksum_offset = i
  i = i + 2

  if cmd_val:le_uint() == 4 then -- ack
    subtree:add_le(ack_cmd, buffer(i, 4))
    i = i + 4
    subtree:add_le(ack_ctrl_pkt_num, buffer(i, 2))
    i = i + 2
  else
    subtree:add(requires_ack, buffer(i, 1))
    i = i + 1
  end

  c = do_checksum(buffer:bytes(0, i), i, cksum_offset)
  subtree:add_le(calculated_checksum, c)
end

cdi_protocol:register_heuristic("udp", heuristic_checker)
