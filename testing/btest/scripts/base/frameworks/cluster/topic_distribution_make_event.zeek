# @TEST-DOC: Broker::make_event() together with Cluster::publish_hrw() and Cluster::publish_rr()
# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3
# @TEST-PORT: BROKER_PORT4
# @TEST-PORT: BROKER_PORT5
#
# @TEST-EXEC: zeek -b --parse-only %INPUT
# @TEST-EXEC: btest-bg-run manager-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run proxy-1   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run proxy-2   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff manager-1/.stdout
# @TEST-EXEC: btest-diff proxy-1/.stdout
# @TEST-EXEC: btest-diff proxy-2/.stdout

@load policy/frameworks/cluster/experimental

# @TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["proxy-1"] = [$node_type=Cluster::PROXY,     $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1"],
	["proxy-2"] = [$node_type=Cluster::PROXY,     $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT3")), $manager="manager-1"],
};
# @TEST-END-FILE

global q = 0;

event go_away()
	{
	terminate();
	}

event distributed_event_hrw(c: count)
	{
	print "got distributed event hrw", c;
	}

event distributed_event_rr(c: count)
	{
	print "got distributed event rr", c;
	}

function send_stuff(heading: string)
	{
	print heading;

	local v: vector of count = vector(0, 1, 2, 3, 13, 37, 42, 101);
	local e: Broker::Event;

	for ( i in v )
		{
		e = Broker::make_event(distributed_event_hrw, v[i]);
		print "hrw", v[i], Cluster::publish_hrw(Cluster::proxy_pool, v[i], e);
		}

	local rr_key = "test";

	for ( i in v )
		{
		e = Broker::make_event(distributed_event_rr, v[i]);
		print "rr", Cluster::publish_rr(Cluster::proxy_pool, rr_key, e);
		}
	}

event Cluster::Experimental::cluster_started()
	{
	if ( Cluster::node != "manager-1" )
		return;

	send_stuff("1st stuff");
	local e = Broker::make_event(go_away);
	Broker::publish(Cluster::node_topic("proxy-1"), e);
	}

event Cluster::node_down(name: string, id: string)
	{
	if ( Cluster::node != "manager-1" )
		return;

	if ( name == "proxy-1" )
		{
		send_stuff("2nd stuff");
		local e = Broker::make_event(go_away);
		Broker::publish(Cluster::node_topic("proxy-2"), e);
		}

	if ( name == "proxy-2" )
		{
		send_stuff("no stuff");
		terminate();
		}
	}

event Cluster::node_down(name: string, id: string)
	{
	if ( name == "manager-1" )
		terminate();
	}
