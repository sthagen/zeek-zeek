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

event new_connection(c: connection)
	{
	print network_time(), "new_connection", c$uid;

	# Using an anonymous record type with field reordering.
	#
	# This is quirky: Because internally this record is coerced
	# very early on, the delay pipeline works with a different
	# record an any modifications other then those in
	# a callback won't be visible.
	local info = [$msg="no-late-update", $ts=network_time()];

	Log::delay(info, function(rec: any, id: Log::ID): bool {
		print network_time(), "post_delay_cb", rec;
		return T;
	});

	Log::write(LOG, info);

	# Not visible (1)
	info$msg = "after-write";

	when [info] ( T == F )
		{
		# never ever.
		}
	timeout 10msec
		{
		print network_time(), "when timeout";
		# Not visible (2)
		info$msg = fmt("delayed %s", network_time());
		}
	}
