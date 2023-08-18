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
global write_count = 0;

hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	++write_count;
	print network_time(), "log_stream_policy", id, write_count, rec;

	if ( write_count % 4 == 0 )
		{
		print network_time(), "do_delay", id, write_count, rec;
		Log::delay(id, rec, function(rec2: Info, id2: Log::ID): bool {
			print network_time(), "post_delay_cb", rec2;
			rec2$post_ts = network_time();
			return T;
		});

		when [rec] ( T == F ) { } timeout 10msec
			{
			print network_time(), "when timeout";
			rec$msg = fmt("%s delayed %s", rec$msg, network_time());
			}
		}
	}

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="test", $max_delay_interval=1msec]);
	}

event new_packet(c: connection, p: pkt_hdr)
	{
	# Undelay any pending packet.
	local info = Info($ts=network_time(), $msg=fmt("packet number %s", packet_count));

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

global write_count = 0;

hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG && id != LOG_OTHER )
		return;

	++write_count;
	print network_time(), "log_stream_policy", id, write_count, rec;

	if ( write_count % 4 == 0 ) {
		print network_time(), "do_delay", id, write_count, rec;
		Log::delay(id, rec, function(rec2: Info, id2: Log::ID): bool {
			print network_time(), "post_delay_cb", rec2;
			rec2$post_ts = network_time();
			return T;
		});

		when [rec] ( T == F ) { } timeout 10msec
			{
			print network_time(), "when timeout";
			rec$msg = fmt("%s delayed %s", rec$msg, network_time());
			}
		}
	}

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="test", $max_delay_interval=1msec]);
	Log::create_stream(LOG_OTHER, [$columns=Info, $path="test-other", $max_delay_interval=1msec]);
	}

event new_packet(c: connection, p: pkt_hdr)
	{
	local info = Info($ts=network_time(), $msg=fmt("packet number %s", packet_count));

	Log::write(LOG, info);
	Log::write(LOG_OTHER, info);
	}
