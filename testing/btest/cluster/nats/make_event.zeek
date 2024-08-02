# @TEST-DOC: Test make_event behavior.
#
# @TEST-EXEC: zeek -b %INPUT >out
#
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

@load frameworks/cluster/backend/nats

redef Cluster::backend = Cluster::CLUSTER_BACKEND_NATS;

function test_fun() { }
hook test_hook() { }
event test_event() { }
event test_event2(s: string) { }

function as_nats_event(e: any): Cluster::Backend::NATS::Event
	{
	assert e is Cluster::Backend::NATS::Event;
	return e as Cluster::Backend::NATS::Event;
	}


event zeek_init() &priority=10
	{
	local e1 = Cluster::make_event(test_event);
	local ne1 = as_nats_event(e1);
	print type_name(ne1$ev), ne1$args;

	local e2 = Cluster::make_event(test_event2, "abc");
	local ne2 = as_nats_event(e2);
	print type_name(ne2$ev), ne2$args;
	}

event zeek_init() &priority=-10
	{
	local e = Cluster::make_event();
	}

event zeek_init() &priority=-11
	{
	local e = Cluster::make_event("a");
	}

event zeek_init() &priority=-12
	{
	local e = Cluster::make_event(test_fun);
	}

event zeek_init() &priority=-13
	{
	local e = Cluster::make_event(test_hook);
	}

event zeek_init() &priority=-14
	{
	local e = Cluster::make_event(test_event2);
	}

event zeek_init() &priority=-15
	{
	local e = Cluster::make_event(test_event2, "a", "b");
	}
