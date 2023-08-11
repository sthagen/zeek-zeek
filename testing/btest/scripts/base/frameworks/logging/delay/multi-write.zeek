# @TEST-DOC: Test behavior when multiple writes/delays happen for the same record.

# @TEST-EXEC: zeek -B logging,tm -b -r $TRACES/http/get.trace test.zeek %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# @TEST-EXEC: zeek-cut -m -F'|' < test.log > test.cut
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff test.cut

# If a test-other.log is produced, also baseline it.
# @TEST-EXEC: ! test -f test-other.log || zeek-cut -m -F'|' < test-other.log > test-other.cut
# @TEST-EXEC: ! test -f test-other.cut || TEST_DIFF_CANONIFIER= btest-diff test-other.cut

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

# Just call Log::write() twice on the same record.

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="test", $max_delay_interval=1msec]);
	}

event new_packet(c: connection, p: pkt_hdr)
	{
	# Undelay any pending packet.
	local info = Info($ts=network_time(), $msg=fmt("packet number %s", packet_count));

	Log::delay(info, function(rec: Info, id: Log::ID): bool {
		rec$post_ts = network_time();
		print network_time(), "post_delay_cb", id, rec;
		return T;
	});

	Log::write(LOG, info);
	Log::write(LOG, info);
	}

# @TEST-START-NEXT
#
# Call Log::write() twice on the same record into different streams.
# The write to LOG_OTHER will be piggy backed on the Log::write() to
# LOG with the presumption about delaying the record, not the Log::write()


redef enum Log::ID += {
	LOG_OTHER
};

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="test", $max_delay_interval=1msec]);
	Log::create_stream(LOG_OTHER, [$columns=Info, $path="test-other"]);
	}

event new_packet(c: connection, p: pkt_hdr)
	{
	# Undelay any pending packet.
	local info = Info($ts=network_time(), $msg=fmt("packet number %s", packet_count));

	Log::delay(info, function(rec: Info, id: Log::ID): bool {
		rec$post_ts = network_time();
		print network_time(), "post_delay_cb", id, rec;
		return T;
	});

	Log::write(LOG, info);
	Log::write(LOG_OTHER, info);
	}


# @TEST-START-NEXT
#
# Same as above, but insert another callback.

redef enum Log::ID += {
	LOG_OTHER
};

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="test", $max_delay_interval=1msec]);
	Log::create_stream(LOG_OTHER, [$columns=Info, $path="test-other"]);
	}

event new_packet(c: connection, p: pkt_hdr)
	{
	# Undelay any pending packet.
	local info = Info($ts=network_time(), $msg=fmt("packet number %s", packet_count));

	Log::delay(info, function(rec: Info, id: Log::ID): bool {
		rec$post_ts = network_time();
		print network_time(), "post_delay_cb", id, rec;
		return T;
	});
	Log::write(LOG, info);

	# This delay_callback runs only for the write to LOG_OTHER.
	Log::delay(info, function(rec: Info, id: Log::ID): bool {
		rec$post_ts = network_time();
		rec$msg += " (other)";
		print network_time(), "post_delay_cb", id, rec;
		return T;
	});
	Log::write(LOG_OTHER, info);
	}
