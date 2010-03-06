echo -n "Using sess:get(OBJECT) ..."
time lua examples/performance.lua -x $1
echo -n "Using sess.OBJECT ..."
time lua examples/performance.lua -o $1
echo -n "Calling snmpget in shell's for loop ..."
time lua examples/performance.lua -s1 $1
echo -n "Calling snmpget n time ..."
time lua examples/performance.lua -s2 $1
