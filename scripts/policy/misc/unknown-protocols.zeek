##! This script logs information about packet protocols that Zeek doesn't
##! know how to process. Mostly these come from packet analysis plugins when
##! they attempt to forward to the next analyzer, but they also can originate
##! from non-packet analyzers.

@load base/frameworks/notice

module UnknownProtocol;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	type Info: record {
		## Timestamp for when the measurement occurred.
		ts:           time     &log;

		## The string name of the analyzer attempting to forward the protocol.
		analyzer:     string   &log;

		## The identifier of the protocol being forwarded in hex notation.
		protocol_id:  string   &log;

		## The identifier of the protocol being forwarded as count.
		## Note: The count value is not logged by default. It is provided for
		## easy access in log policy hooks.
		protocol_id_num: count;

		## A certain number of bytes at the start of the unknown protocol's
		## header.
		first_bytes:  string   &log;

		## The chain of packet analyzers that processed the packet up to this
		## point. This includes the history of encapsulating packets in case
		## of tunneling.
		analyzer_history: vector of string &log;
	};
}

event unknown_protocol(analyzer_name: string, protocol: count, first_bytes: string,
	analyzer_history: string_vec)
	{
	local info : Info;
	info$ts = network_time();
	info$analyzer = analyzer_name;
	info$protocol_id = fmt("0x%x", protocol);
	info$protocol_id_num = protocol;
	info$first_bytes = bytestring_to_hexstr(first_bytes);
	info$analyzer_history = analyzer_history;

	Log::write(LOG, info);
	}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, Log::Stream($columns=Info, $path="unknown_protocols", $policy=log_policy));
	}
