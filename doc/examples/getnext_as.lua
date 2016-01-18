require "snmp"

local count = 0

hub1 = assert(snmp.open{peer = "obelix"})

function next_cb(vb, err, _, _, session)
  if not err and vb.type ~= snmp.ENDOFMIBVIEW then
    count = count + 1
    print(snmp.sprintvar(vb))
    session:asynch_getnext(vb, next_cb)
  else
    print(string.format("%d object instances retrieved", count))
    os.exit(0)
  end
end

-- First call initialises retrieval of complete tree.
hub1:asynch_getnext("1", next_cb)
snmp.loop()

