# @TEST-DOC: Check usage delay in when statements.

# @TEST-EXEC: zeek -B tm,logging -b -r $TRACES/http/get.trace test.zeek %INPUT
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

hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	print network_time(), "log_stream_policy", id, rec;

	Log::delay(LOG, rec, function(rec2: Info, id2: Log::ID): bool {
		print network_time(), "post_delay_cb", rec2;
		rec2$msg = fmt("%s was delayed %s", rec2$msg, network_time());
		return T;
	});

	}

event new_connection(c: connection)
	{
	print network_time(), "new_connection", c$uid;

	# Using an anonymous record type with field reordering.
	#
	# This is quirky: Because internally this record is coerced
	# very early on, the hooks and delay pipeline work with a different
	# record val ptr. So an update of this record is not visible!
	local info = [$msg="initial-value", $ts=network_time()];

	Log::write(LOG, info);

	# Not visible due to coercion.
	print network_time(), "after write";
	info$msg = "after-write";
	}
