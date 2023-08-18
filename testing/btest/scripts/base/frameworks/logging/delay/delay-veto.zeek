# @TEST-DOC: Log::delay_finish() on a conn.log entry that was completely vetoed. Should not error, there's just nothing to do.

# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff .stderr
# @TEST-EXEC: test ! -f conn.log

@load base/protocols/conn

hook Conn::log_policy(rec: Conn::Info, id: Log::ID, filter: Log::Filter)
	{
	print network_time(), "veto", rec$uid;
	break;
	}

hook Conn::log_policy(rec: Conn::Info, id: Log::ID, filter: Log::Filter) &priority=5
	{
	print network_time(), "delay", rec$uid;
	Log::delay(id, rec, function(rec2: Conn::Info, id2: Log::ID): bool {
		print network_time(), "post_delay_cb - not invoked", rec2;
	});
	}
