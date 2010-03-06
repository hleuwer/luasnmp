#! /usr/local/bin/lua50
--
-- Function walk implements a MIB subtree traversal
--   It receives three parameters: 
--	the identification of an SNMP agent (a host name or IP address)
--	the community string
--	a MIB label identifying the subtree to be traversed (optional)
--
local snmp = require "snmp"
local mib=snmp.mib

function walk(host, commStr, subtree)

  -- Open an SNMP session with host using SNMPv1
  local s,err = snmp.open{peer = host, version = SNMPv2, community=commStr}
  if not s then
    print(string.format("walk: unable to open session with %s\n%s\n",err))
    return
  end
  
  -- Convert MIB label to its OID. 
  local root
  if subtree then
    root = mib.oid(subtree)
    if not root then
      print(string.format("walk: invalid subtree %s\n",subtree))
      return
    end
  else -- if no label is defined, traverse the entire MIB
    root = "1"
  end
  
  -- Traverse the subtree
  local vb={oid=root}
  local mibEnd
  repeat
--    print("#11# vb=",vb.oid, vb.type)
    vb,err = s:getnext(vb)
--    print("#22#", vb, err, root, vb.type)
    if not err then
      -- Check if the returned OID contains the OID associated 
      --   with the root of the subtree
      if string.find(vb.oid,root) == nil or 
	vb.type == snmp.ENDOFMIBVIEW then
	mibEnd = 1
      else
	-- print the returned varbind and request next var
	-- use LuaSNMP's sprintvar:
	-- print(snmp.sprintvar(vb))
	-- or NETSNMP's sprint_var via session
	-- print(session:sprintvar(vb))
	-- or simply rely on Lua's __tostring metamethod
	print(vb)
      end
    end
  until err or mibEnd
  
  -- Close the SNMP session
  s:close(s)
  
end

if table.getn(arg) < 3 then
  print("usage: lua walk.lua HOST COMMUNITY SUBTREE")
  os.exit(1)
end
walk(arg[1], arg[2], arg[3])
