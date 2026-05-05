# @TEST-DOC: global_ids() includes information about attributes of global identifiers.
#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

module Test;

export {
	global c: count = 42 &redef;
	global t: table[string] of string &write_expire=42sec &default_insert="hey!";
	global s: set[string] &ordered &redef &deprecated;
}

event zeek_init()
	{
	local a = global_ids();
	print "Test::c", a["Test::c"]$attributes;
	print "Test::t", a["Test::t"]$attributes;
	print "Test::s", a["Test::s"]$attributes;
	}
