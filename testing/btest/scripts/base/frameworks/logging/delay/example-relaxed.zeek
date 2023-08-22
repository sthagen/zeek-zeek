# @TEST-DOC: Example of using lookup_addr() within connection_state_remove()

# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff .stderr
# @TEST-EXEC: zeek-cut -m ts uid id.orig_h orig_name id.resp_h resp_name < conn.log > conn.cut
# @TEST-EXEC: btest-diff conn.cut


# Enrich conn.log with lookup_addr() result
@load base/protocols/conn

redef record Conn::Info += {
	orig_name: string &log &optional;
	resp_name: string &log &optional;
};

event connection_state_remove(c: connection)
	{
	local info = c$conn;
	local token1 = Log::delay(Conn::LOG, info, function(rec: Conn::Info, id: Log::ID): bool {
		print network_time(), "token1 delay hook";
		return T;
	});

	local token2 = Log::delay(Conn::LOG, info, function(rec: Conn::Info, id: Log::ID): bool {
		print network_time(), "token2 delay hook";
		return T;
	});

	when [info, token1] ( local orig_name = lookup_addr(info$id$orig_h) )
		{
		info$orig_name = orig_name;
		Log::delay_finish(Conn::LOG, info, token1);
		}
	timeout 150msec
		{
		Reporter::warning(fmt("lookup_addr timeout for %s", info$id$orig_h));
		}

	when [info, token2] ( local resp_name = lookup_addr(info$id$resp_h) )
		{
		info$resp_name = resp_name;
		Log::delay_finish(Conn::LOG, info, token2);
		}
	timeout 150msec
		{
		Reporter::warning(fmt("lookup_addr timeout for %s", info$id$resp_h));
		}
	}

event zeek_init()
	{
	Log::set_max_delay_interval(Conn::LOG, 200msec);
	}
