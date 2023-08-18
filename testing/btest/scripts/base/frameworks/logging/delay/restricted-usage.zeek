# @TEST-DOC: Idea to only allow Log::delay() during stream or filter hooks

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

hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	print network_time(), "log_stream_policy", id, rec;

	if ( rec$msg == "first" ) # Delay only the first record.
		{
		local token1 = Log::delay(id, rec, function(recx: Info, idx: Log::ID): bool {
			print network_time(), "callback first";
			return T;
		});

		# Do something asynchronously for the record.
		when [rec] ( T == F ) { }
		timeout 10msec
			{
			print network_time(), "when timeout";
			rec$msg = fmt("%s was delayed %s", rec$msg, network_time());
			}
		}

	if ( rec$msg == "third" ) # Delay and directly delay_finish the third record.
		{
		local token3 = Log::delay(id, rec, function[rec](recx: Info, idx: Log::ID): bool {
			print network_time(), "callback third";
			rec$msg = fmt("%s was delayed by %s", rec$msg, network_time() - rec$ts);
			return T;
		});

		print network_time(), "immediate finish";
		Log::delay_finish(id, rec, token3);
		}
	}

# @TEST-START-NEXT
hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	print network_time(), "log_stream_policy", id, rec;

	if ( rec$msg == "first" ) # Delay only the first record.
		{
		local token1 = Log::delay(id, rec, function[rec](recx: Info, idx: Log::ID): bool {
			print network_time(), "callback first";
			rec$msg = fmt("%s was delayed by %s", rec$msg, network_time() - rec$ts);
			return T;
		});

		# Do something asynchronously for the record.
		when [id, rec, token1] ( T == F ) { }
		timeout 100msec
			{
			print network_time(), "when timeout";
			Log::delay_finish(id, rec, token1);
			}
		}
	}
