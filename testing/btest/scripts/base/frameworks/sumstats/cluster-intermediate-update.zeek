# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: btest-bg-run manager   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-2  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff manager/.stdout

@load base/frameworks/cluster
@load base/frameworks/sumstats

redef Log::default_rotation_interval = 0secs;

event zeek_init() &priority=5
	{
	local r1: SumStats::Reducer = [$stream="test.metric", $apply=set(SumStats::SUM)];
	SumStats::create([$name="test",
	                  $epoch=15secs,
	                  $reducers=set(r1),
	                  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = 
	                  	{
	                  	print result["test.metric"]$sum;
	                  	},
	                  $epoch_finished(ts: time) = 
	                  	{
	                  	print "End of epoch handler was called";
	                  	terminate();
	                  	},
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["test.metric"]$sum;
	                  	},
	                  $threshold=100.0,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	print fmt("A test metric threshold was crossed with a value of: %.1f", result["test.metric"]$sum);
	                  	}]);
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

event do_stats(i: count)
	{
	# Worker-1 will trigger an intermediate update and then if everything
	# works correctly, the data from worker-2 will hit the threshold and
	# should trigger the notice.
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=i]);
	}

event Cluster::node_up(name: string, id: string)
	{
	if ( name == "manager" )
		{
		if ( Cluster::node == "worker-1" )
			{
			schedule 0.1sec { do_stats(1) };
			schedule 1secs { do_stats(60) };
			}
		if ( Cluster::node == "worker-2" )
			schedule 0.5sec { do_stats(40) };
		}
	}
