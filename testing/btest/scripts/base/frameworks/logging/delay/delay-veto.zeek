# @TEST-DOC: Log::delay_finish() on a conn.log entry that was completely vetoed. Should not error, there's just nothing to do.

# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff .stderr
# @TEST-EXEC: test ! -f conn.log

@load base/protocols/conn

hook Conn::log_policy(rec: Conn::Info, id: Log::ID, filter: Log::Filter)
	{
	print "veto", rec$uid;
	break;
	}

event connection_state_remove(c: connection) &priority=0
	{
	print "delay", c$uid;
	Log::delay(c$conn);
	}

event connection_state_remove(c: connection) &priority=-10
	{
	print "delay_finish", c$uid;
	Log::delay_finish(c$conn);
	}
