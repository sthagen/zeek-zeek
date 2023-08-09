# @TEST-DOC: Check usage delay in when statements.

# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace test.zeek %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff .stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# @TEST-EXEC: zeek-cut -m -F'|' < test.log > test.cut
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff test.cut

@TEST-START-FILE test.zeek
# Used by all tests below.

# Debug printing
global packet_count = 0;
event new_packet(c: connection, p: pkt_hdr)
	{
	++packet_count;
	print network_time(), "new_packet", packet_count;
	}

redef enum Log::ID += {
	LOG
};

type Info: record {
	ts: time &log;
	msg: string &log;
};

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="test"]);
	}

@TEST-END-FILE test.zeek

# Basic delay() test, no delay_finish()
event new_connection(c: connection)
	{
	print network_time(), "new_connection", c$uid;
	local info = Info($ts=network_time(), $msg="no-late-update");

	Log::delay(info);
	Log::write(LOG, info);

	when [info] ( T == F )
		{
		# never ever.
		}
	timeout 10msec
		{
		print network_time(), "when timeout";
		info$msg = fmt("delayed %s", network_time());
		}
	}

@TEST-START-NEXT

# Basic delay() test with delay_finish()
event new_connection(c: connection)
	{
	print network_time(), "new_connection", c$uid;
	local info = Info($ts=network_time(), $msg="no-late-update");

	Log::delay(info);
	Log::write(LOG, info);
	when [info] ( T == F )
		{
		# never ever.
		}
	timeout 10msec
		{
		print network_time(), "when timeout";
		info$msg = fmt("delayed %s", network_time());
		Log::delay_finish(info);
		}
	}

@TEST-START-NEXT

# Basic delay() calling delay_finish() before updating the record.
# This doesn't update the record.
event new_connection(c: connection)
	{
	print network_time(), "new_connection", c$uid;
	local info = Info($ts=network_time(), $msg="no-late-update (OK)");

	Log::delay(info);
	Log::write(LOG, info);
	when [info] ( T == F )
		{
		# never ever.
		}
	timeout 10msec
		{
		print network_time(), "when timeout";
		Log::delay_finish(info);
		# This update is lost, because above delay_finish() flushed
		# the record out.
		info$msg = fmt("delayed %s", network_time());
		}
	}
