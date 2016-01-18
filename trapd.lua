local socket = require "socket"
local arg = {select(1, ...)}
local port = tonumber(arg[1] or os.getenv("LUASNMP_TRAPDPORT")) or 6000
local log
if _VERSION > "5.1" then
   local logger = require "logging.file"
   log = logger(arg[2])
else
   require "logging.file"
   log = logging.file(arg[2])
end
log:setLevel(arg[3] or "INFO")
log:info("TRAPD capture start")

--
-- Collect input from snmptrapd and optionally write into logfile
-- We do not care about contents!
--
local str = ""
for s in io.lines() do
   str = str .. " " .. s
   log:debug("captured: '".. s .."'")
end

--
-- Send the string to luasnmp
--
sk = socket:udp()
local ip = socket.dns.toip("localhost")
if sk then
   log:debug("sending input to "..ip..":"..port)
   sk:sendto(str, ip, port)
   sk:close()
else
   log:error("cannot open udp socket")
   os.exit(1)
end

--
-- Close the optional logfile.
--
log:info("TRAPD capture finished.")
