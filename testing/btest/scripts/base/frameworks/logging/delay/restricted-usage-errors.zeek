# @TEST-DOC: Test some errors with Log::delay() usage.

# @TEST-EXEC: zeek -B logging,tm -b -r $TRACES/http/get.trace test.zeek %INPUT
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

event new_connection(c: connection)
	{
	print network_time(), "new_connection", c$uid;
	local info1 = Info($ts=network_time(), $msg="first");
	Log::write(LOG, info1);

	local info2 = Info($ts=network_time(), $msg="second");
	Log::write(LOG, info2);

	local info3 = Info($ts=network_time(), $msg="third");
	Log::write(LOG, info3);
	}
@TEST-END-FILE test.zeek

# Attempt to delay something that's not being written outside of a hook.
event new_connection(c: connection)
	{
	local info = Info($ts=network_time(), $msg="bad");
	Log::delay(LOG, info);
	}

# @TEST-START-NEXT

# Attempt to delay something that's not being written within a hook.
hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	local info = Info($ts=network_time(), $msg="bad");
	Log::delay(LOG, info);
	}
