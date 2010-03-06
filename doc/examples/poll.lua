local snmp = require "snmp"

polled = {}
local count = 3

local function poll_cb(vb, err, index, reqid, session, magic)
  local agent = polled[reqid]
  polled[reqid] = nil
  if vb then
    agent.status = "alive"
  else
    if err == "snmp: timeout"  then
      agent.status = "no response"
    else
      agent.status = "?"
    end
  end
  count = count - 1
end

function poll(agents)
  local i, agent = next(agents,nil)
  while i do
    local reqid = snmp.asynch_get(agent.session, "sysUpTime.0", poll_cb)
    if reqid then
      polled[reqid] = agent
    end
    i, agent = next(agents,i)
  end
end

local agents = {
  { session = snmp.open{peer = "goofy"}, name = "goofy" },  
  { session = snmp.open{peer = "192.168.99.1"}, name = "192.168.99.1"},  
  { session = snmp.open{peer = "localhost"}, name = "localhost" }
}


poll(agents)
while count > 0 do 
  snmp.event()
end

for _, agent in ipairs(agents) do
  print(string.format("Agent status of %s: %s", agent.name, agent.status or 'failure'))
  agent.session:close()
end
