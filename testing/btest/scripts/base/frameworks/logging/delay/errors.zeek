# @TEST-DOC: Test some error cases

# @TEST-EXEC: zeek  -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER='$SCRIPTS/diff-remove-abspath | sed -r "s/0x[0-9a-z]+/0x<...>/g"' btest-diff .stderr

redef enum Log::ID += { LOG };

event zeek_init()
	{
	# Not within a log write
	Log::delay(LOG, []);
	}

@TEST-START-NEXT
@load base/protocols/conn

hook Conn::log_policy(rec: Conn::Info, id: Log::ID, filter: Log::Filter)
	{
	# Not the same record as the one from the hook.
	Log::delay(id, copy(rec));
	}

@TEST-START-NEXT
@load base/protocols/conn
@load base/protocols/dns

hook Conn::log_policy(rec: Conn::Info, id: Log::ID, filter: Log::Filter)
	{
	# Wrong stream identifier
	Log::delay(DNS::LOG, rec);
	}

@TEST-START-NEXT
@load base/protocols/conn

hook Conn::log_policy(rec: Conn::Info, id: Log::ID, filter: Log::Filter)
	{
	# Wrong token for delay_finish()
	local token = Log::delay(id, rec);
	Log::delay_finish(id, rec, 42);
	}

@TEST-START-NEXT
@load base/protocols/conn

hook Conn::log_policy(rec: Conn::Info, id: Log::ID, filter: Log::Filter)
	{
	# Wrong token type for delay_finish()
	local token = Log::delay(id, rec);
	Log::delay_finish(id, rec, "42");
	}
