local snmp = require "snmp"
local mib = snmp.mib

--
-- We need this reference here for the finalizer
--
local sess

--
-- Finalize function
--
local function finalize()
  io.write("Cleanup handler: ")
  if sess then
    if rawget(sess, "internal") then
      print("closing session.")
      sess:close()
    else
      print("session already closed.")
    end
  else
    print("nothing to do.")
  end
end

local function pdoit()

  -- 
  -- Acquire a new exception handler
  --
  local try = snmp.newtry(finalize)

  --
  -- Do some work: no failure here
  --
  sess = try(snmp.open{peer = "obelix"})
  
  --
  -- Do some work: no failure here
  --
  local vl = try(sess:get{"sysContact.0","sysDescr.0"})
  table.foreach(vl, print)

  --
  -- Do some work: no failure here
  --
  local vl = try(snmp.walk(sess, "ifDescr"))
  table.foreach(vl, print)

  --
  -- Do some work: no failure here
  --
  local t = try(sess.ifDescr)
  for k,v in snmp.spairs(t) do print(k,v) end

  --
  -- Close the session orderly. Note this will delete the
  -- internal session. Following usage must fail.
  --
  try(sess:close())

  --
  -- Try to re-use the old session which should fail
  --
  local vl = try(snmp.walk(sess, "ifDescr"))
  table.foreach(vl, print)

  return "ok"
end

--
-- Execute the protected function 'pdoit'
--
local rv, err = snmp.protect(pdoit)()

-- 
-- Evaluate the result of error capturing
--
if not rv then
  print("doit error: '"..(err or "unknown").."'")
else
  print("doit o.k.")
end
