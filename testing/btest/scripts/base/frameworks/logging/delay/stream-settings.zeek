# @TEST-DOC: Configure stream settings and observe behavior through post_delay_cb.

# @TEST-REQUIRES: false
# @TEST-EXEC: zeek -B logging,tm -b -r $TRACES/http/get.trace test.zeek %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stdout
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

event Pcap::file_done(p: string)
	{
	print network_time(), "file_done", p;
	}

redef enum Log::ID += {
	LOG
};

type Info: record {
	ts: time &log;
	post_ts: time &log &optional;
	msg: string &log;
};

@TEST-END-FILE test.zeek

# Delay every entry by 1msec.

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="test", $max_delay_interval=1msec]);
	}

event new_packet(c: connection, p: pkt_hdr)
	{
	# Undelay any pending packet.
	local last_info = Info($ts=network_time(), $msg=fmt("packet number %s", packet_count));

	Log::delay(last_info, function(rec: Info, id: Log::ID): bool {
		rec$post_ts = network_time();
		print network_time(), "post_delay_cb", rec;
		return T;
	});

	Log::write(LOG, last_info);
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

event new_packet(c: connection, p: pkt_hdr)
	{
	local last_info = Info($ts=network_time(), $msg=fmt("packet number %s", packet_count));

	Log::delay(last_info, function(rec: Info, id: Log::ID): bool {
		rec$post_ts = network_time();
		print network_time(), "post_delay_cb", rec;
		return T;
	});

	Log::write(LOG, last_info);
	}

# @TEST-START-NEXT

# If we do not set these here, we can't force smaller values.
redef Log::max_delay_queue_size = 1;
redef Log::max_delay_interval = 0.01msec;

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="test"]);

	# Manually set both...
	Log::set_max_delay_interval(LOG, 1msec);
	Log::set_max_delay_queue_size(LOG, 3);
	}

event new_packet(c: connection, p: pkt_hdr)
	{
	local last_info = Info($ts=network_time(), $msg=fmt("packet number %s", packet_count));

	Log::delay(last_info, function(rec: Info, id: Log::ID): bool {
		rec$post_ts = network_time();
		print network_time(), "post_delay_cb", rec;
		return T;
	});

	Log::write(LOG, last_info);
	}
