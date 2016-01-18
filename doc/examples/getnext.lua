require "snmp"

hub1 = assert(snmp.open{peer = "obelix"})

repeat
  vb, err = snmp.getnext (hub1, vb or {oid = "1"})
  if not err and vb.type ~= snmp.ENDOFMIBVIEW then
    print(snmp.sprintvar(vb))
  end
until vb.type == snmp.ENDOFMIBVIEW
