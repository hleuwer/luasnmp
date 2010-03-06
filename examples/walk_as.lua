#! /usr/local/bin/lua50
--
-- This is an asynchronous version of the MIB traversal
--

local snmp = require "snmp"
local mib = snmp.mib
--
-- Callback function for handling the response to get-next
--

function walk_cb(vb, err, ind, reqid, session, root)

  if not err then
    -- Check if the returned OID contains the OID associated
    --   with the root of the subtree
    if string.find(vb.oid, root) == nil or 
      vb.type == snmp.ENDOFMIBVIEW then
      session:close()
      return
    else
      -- print the returned varbind and request next var
      -- use LuaSNMP's sprintvar:
      -- print(snmp.sprintvar(vb))
      -- or NETSNMP's sprint_var via session
      -- print(session:sprintvar(vb))
      -- or simply rely on Lua's __tostring metamethod
      print(vb)
      req, err, ind = session:asynch_getnext(vb, walk_cb, root)
    end
  else
    snmp.close(session)
  end
end

-- Function walk receives three parameters:
--  the identification of an SNMP agent (a host name or IP address)
--  the community string
--  a MIB label identifying the subtree to be traversed (optional)

function walk(host,commStr,subtree)
  -- Open an SNMP session with host using SNMPv1
  local s,err = snmp.open{peer = host, version = SNMPv1, community = commStr}
  if not s then
    print(string.format("walk: unable to open session with %s\n%s",
			host, err))
    return
  end

  -- Convert MIB label to its OID
  local root
  if subtree then
    root = mib.oid(subtree)
    if root == nil then
     print(string.format("walk: invalid subtree %s", subtree))
     return
   end
 else -- if no label is defined, traverse the entire MIB
   root = "1"
 end

 -- Start the traversal with the first asynchronous request
 --   (the callback function will issue the other requests)
 local vb={oid=root}
 req, err = snmp.asynch_getnext(s, vb, walk_cb, root)
 if err then
   s:close()
   return
 end
 s:wait()
 s:close()
end

if table.getn(arg) < 3 then
  print("usage: lua walk.lua HOST COMMUNITY SUBTREE")
  os.exit(1)
end
walk(arg[1], arg[2], arg[3])
