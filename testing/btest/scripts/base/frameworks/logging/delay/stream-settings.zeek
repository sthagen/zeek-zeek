# @TEST-DOC: Configure stream settings and observe behavior through post_delay_cb.

# @TEST-EXEC: zeek -B logging,tm -b -r $TRACES/http/get.trace test.zeek %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# @TEST-EXEC: zeek-cut -m -F'|' < test.log > test.cut
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff test.cut

@TEST-START-FILE test.zeek
# Used by all tests below.

# Debug printing
global packet_count = 0;

redef enum Log::ID += {
	LOG
};

type Info: record {
	ts: time &log;
	post_ts: time &log &optional;
	msg: string &log;
};

event new_packet(c: connection, p: pkt_hdr)
	{
	++packet_count;
	print network_time(), "new_packet", packet_count;
	local info = Info($ts=network_time(), $msg=fmt("packet number %s", packet_count));
	Log::write(LOG, info);
	}

event Pcap::file_done(p: string)
	{
	print network_time(), "file_done", p;
	}

@TEST-END-FILE test.zeek

# Delay every entry by 1msec.
event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="test", $max_delay_interval=1msec]);
	}

hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	Log::delay(id, rec, function(rec2: Info, id2: Log::ID): bool {
		rec2$post_ts = network_time();
		print network_time(), "post_delay_cb", rec2;
		return T;
	});

	}

# @TEST-START-NEXT

# Delay every entry by 10seconds, but set queue size to 5 such that
# entries are evicted when the queue size is reached.


event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="test",
	                         $max_delay_interval=10sec,
	                         $max_delay_queue_size=5]);
	}

hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	Log::delay(id, rec, function(rec2: Info, id2: Log::ID): bool {
		rec2$post_ts = network_time();
		print network_time(), "post_delay_cb", rec2;
		return T;
	});

	}


# @TEST-START-NEXT

redef Log::max_delay_queue_size = 1;
redef Log::max_delay_interval = 0.01msec;

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="test"]);

	# Manually set both...
	Log::set_max_delay_interval(LOG, 1msec);
	Log::set_max_delay_queue_size(LOG, 3);
	}

hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	Log::delay(id, rec, function(rec2: Info, id2: Log::ID): bool {
		rec2$post_ts = network_time();
		print network_time(), "post_delay_cb", rec2;
		return T;
	});

	}
