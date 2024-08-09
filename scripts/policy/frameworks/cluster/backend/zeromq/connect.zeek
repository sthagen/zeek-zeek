##! Establish ZeroMQ connectivity with the broker.

module Cluster::Backend::ZeroMQ;

event zeek_init()
	{
	if ( run_broker_thread )
		Cluster::Backend::ZeroMQ::spawn_broker_thread();

	# Connect to the broker thread, wherever it might run.
	Cluster::Backend::ZeroMQ::connect();

	Cluster::subscribe(Cluster::nodeid_topic(Cluster::node_id()));
	}
