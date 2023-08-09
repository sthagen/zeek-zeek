# @TEST-DOC: Test some error cases

# @TEST-EXEC-FAIL: zeek  -b -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

event zeek_init()
	{
	if ( ! Log::delay(1) )
		exit(1);
	}

@TEST-START-NEXT
event zeek_init()
	{
	if ( ! Log::delay_finish(1) )
		exit(1);
	}

@TEST-START-NEXT
event zeek_init()
	{
	local x = [$a="a"];
	Log::delay(x);
	Log::delay(x);
	Log::delay(x);
	Log::delay(x);
	# TODO
	exit(1);
	}
