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

@TEST-END-FILE test.zeek

# Basic delay() test, no delay_finish()
event new_connection(c: connection)
	{
	print network_time(), "new_connection", c$uid;
	local info = Info($ts=network_time(), $msg="no-late-update");

	Log::delay(info, function(rec: any, id: Log::ID): bool {
		print network_time(), "post_delay_cb";
		return T;
	});
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

# @TEST-START-NEXT
# Basic delay() test with delay_finish(), expect callback to be invoked
# right at Log::delay_finish()
event new_connection(c: connection)
	{
	print network_time(), "new_connection", c$uid;
	local info = Info($ts=network_time(), $msg="no-late-update");

	Log::delay(info, function(rec: any, id: Log::ID): bool {
		print network_time(), "post_delay_cb";
		return T;
	});
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

# @TEST-START-NEXT
# Basic delay() test with two callbacks but just one Log::delay_finish() call.
# Relies on the timeout for expiration.
event new_connection(c: connection)
	{
	print network_time(), "new_connection", c$uid;
	local info = Info($ts=network_time(), $msg="no-late-update");

	Log::delay(info, function(rec: any, id: Log::ID): bool {
		print network_time(), "post_delay_cb - 1";
		return T;
	});
	Log::delay(info, function(rec: any, id: Log::ID): bool {
		print network_time(), "post_delay_cb - 2";
		return T;
	});
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

# @TEST-START-NEXT
# Basic delay() test two callbacks and two Log::delay_finish() calls
event new_connection(c: connection)
	{
	print network_time(), "new_connection", c$uid;
	local info = Info($ts=network_time(), $msg="no-late-update");

	Log::delay(info, function(rec: any, id: Log::ID): bool {
		print network_time(), "post_delay_cb - 1";
		return T;
	});
	Log::delay(info, function(rec: any, id: Log::ID): bool {
		print network_time(), "post_delay_cb - 2";
		return T;
	});
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
		Log::delay_finish(info);
		}
	}

# @TEST-START-NEXT
# Create a log entry per packet, delay() each and delay_finish() it on the next packet.

global last_info: Info = Info($ts=double_to_time(0.0), $msg="init");

event new_packet(c: connection, p: pkt_hdr)
	{
	# Undelay any pending packet.
	if ( last_info$ts > double_to_time(0.0) )
		Log::delay_finish(last_info);

	last_info = Info($ts=network_time(), $msg=fmt("packet number %s", packet_count));

	local my_packet_count = packet_count;
	Log::delay(last_info, function [my_packet_count](rec: Info, id: Log::ID): bool {
		print network_time(), "post_delay_cb", rec;

		# Only log event numbered packets, but decide after delaying.
		return my_packet_count % 2 == 0;
	});

	Log::write(LOG, last_info);
	}
