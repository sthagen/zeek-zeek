# @TEST-EXEC: zeek -b %INPUT 1>out 2>err
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=${SCRIPTS}/diff-remove-abspath btest-diff err

event zeek_init()
	{
	print to_int("1");
	print to_int("-1");
	print to_int("10111100", 2);
	print to_int("47", 8);
	print to_int("F3", 16);
	print to_int("0xF3", 16);
	print to_int("4294967296");
	print to_int("not an int");
	# We automatically trim leading, but not trailing whitespace.
	print to_int(" 205"); # Okay.
	print to_int("206 "); # Error.

	local a: double = 3.14;
	print double_to_int(a);

	local b: double = 3.9;
	print double_to_int(b);

	local c: double = -3.14;
	print double_to_int(c);

	local d: double = -3.9;
	print double_to_int(d);
	}
