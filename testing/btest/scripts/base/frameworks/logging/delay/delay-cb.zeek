# @TEST-DOC: Test the post delay callback.

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
	local info = Info($ts=network_time(), $msg="inital-value");
	Log::write(LOG, info);
	}
@TEST-END-FILE test.zeek

# Basic delay() test, no delay_finish()
hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	print network_time(), "log_stream_policy", id, rec;

	Log::delay(LOG, rec, function(rec2: Info, id2: Log::ID): bool {
		print network_time(), "post_delay_cb", rec2;
		return T;
	});

	when [rec] ( T == F ) { } timeout 10msec
		{
		print network_time(), "when timeout";
		rec$msg = fmt("%s delayed %s", rec$msg, network_time());
		}
	}

# @TEST-START-NEXT
# Basic delay() test with delay_finish(), expect callback to be invoked
# right at Log::delay_finish()
hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	print network_time(), "log_stream_policy", id, rec;

	local token = Log::delay(LOG, rec, function(rec2: Info, id2: Log::ID): bool {
		print network_time(), "post_delay_cb", rec2;
		return T;
	});

	when [id, rec, token] ( T == F ) { } timeout 10msec
		{
		print network_time(), "when timeout";
		rec$msg = fmt("%s delayed %s", rec$msg, network_time());
		Log::delay_finish(id, rec, token);
		}
	}

# @TEST-START-NEXT
# Basic delay() test with two callbacks but just one Log::delay_finish() call.
hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	print network_time(), "log_stream_policy", id, rec;

	local token1 = Log::delay(LOG, rec, function(rec2: Info, id2: Log::ID): bool {
		print network_time(), "post_delay_cb - 1", rec2;
		return T;
	});
	local token2 = Log::delay(LOG, rec, function(rec2: Info, id2: Log::ID): bool {
		print network_time(), "post_delay_cb - 2", rec2;
		return T;
	});

	when [id, rec, token1] ( T == F ) { } timeout 10msec
		{
		print network_time(), "when timeout";
		rec$msg = fmt("%s delayed %s", rec$msg, network_time());
		Log::delay_finish(id, rec, token1);
		}
	}

# @TEST-START-NEXT
# Basic delay() test two callbacks and two Log::delay_finish() calls
hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	print network_time(), "log_stream_policy", id, rec;

	local token1 = Log::delay(LOG, rec, function(rec2: Info, id2: Log::ID): bool {
		print network_time(), "post_delay_cb - 1", rec2;
		return T;
	});
	local token2 = Log::delay(LOG, rec, function(rec2: Info, id2: Log::ID): bool {
		print network_time(), "post_delay_cb - 2", rec2;
		return T;
	});

	when [id, rec, token1, token2] ( T == F ) { } timeout 10msec
		{
		print network_time(), "when timeout";
		rec$msg = fmt("%s delayed %s", rec$msg, network_time());
		Log::delay_finish(id, rec, token1);
		Log::delay_finish(id, rec, token2);
		}
	}
