##! ZeroMQ cluster backend support.
##!
##! One node in a Zeek cluster runs a broker thread (likely the manager) and
##! all other threads connect to it.
##!
##!                    broker thread
##!
##!         XPUB -> +-----------------+
##! worker          |  XPUB <-> XSUB  |
##!         XSUB <- +-----------------+
##!
##! How does this work conceptually? All workers subscribe using their
##! XSUB socket.
##!
##! How other nodes discover each other: We should see subscriptions
##! coming in on the XPUB socket and can work with those.
##!
module Cluster::Backend::ZeroMQ;

export {
	## On which endpoints should the broker thread listen?
	## This doesn't need to run in Zeek. It could also be
	## a separate process. But: All nodes need to connect
	## to the same broker thread.
	const listen_xsub_endpoint = "tcp://127.0.0.1:5556" &redef;
	const listen_xpub_endpoint = "tcp://127.0.0.1:5555" &redef;

	## A node connects with its XPUB socket to the XSUB socket
	## of the broker. And its XSUB socket to the XPUB socket
	## of the broker. So its the inverse compared to the above.
	const connect_xpub_endpoint = "tcp://127.0.0.1:5556" &redef;
	const connect_xsub_endpoint = "tcp://127.0.0.1:5555" &redef;

	const run_broker_thread: bool = F &redef;

	global node_topic_prefix = "zeek.cluster.node" &redef;
	global nodeid_topic_prefix = "zeek.cluster.nodeid" &redef;

	## Low level event when a subscription arrived on a node's
	## XPUB socket. This can be used to reply with Cluster::hello()
	## on that node.
	global subscription: event(topic: string);

	## Low level event when nodes jnsubscribe.
	global unsubscription: event(topic: string);

	global hello: event(name: string, id: string);

	## Type to support Cluster::make_event(). Seems to work.
	type Event: record {
		ev: any;
		args: vector of any;
	};
}

redef Cluster::backend = Cluster::CLUSTER_BACKEND_ZEROMQ;

function zeromq_node_topic(name: string): string {
	return node_topic_prefix + "." + name;
}

function zeromq_nodeid_topic(id: string): string {
	return nodeid_topic_prefix + "." + id;
}

# Unique identifier for this node with some debug information.
const my_node_id = fmt("zeromq_%s_%s_%s_%s",  Cluster::node, gethostname(), getpid(), unique_id("N"));

function zeromq_node_id(): string {
	return my_node_id;
}

# NATS uses subjects that are dot separated
# and not just prefix matching.
redef Cluster::node_topic = zeromq_node_topic;
redef Cluster::nodeid_topic = zeromq_nodeid_topic;
redef Cluster::node_id = zeromq_node_id;

redef Cluster::logger_topic = "zeek.cluster.logger";
redef Cluster::manager_topic = "zeek.cluster.manager";
redef Cluster::proxy_topic = "zeek.cluster.proxy";
redef Cluster::worker_topic = "zeek.cluster.worker";

redef Cluster::proxy_pool_spec = Cluster::PoolSpec(
	$topic = "zeek.cluster.pool.proxy",
	$node_type = Cluster::PROXY);

redef Cluster::logger_pool_spec = Cluster::PoolSpec(
	$topic = "zeek.cluster.pool.logger",
	$node_type = Cluster::LOGGER);

redef Cluster::worker_pool_spec = Cluster::PoolSpec(
	$topic = "zeek.cluster.pool.worker",
	$node_type = Cluster::WORKER);

# The ZeroMQ plugin notifies script land when a subscription arrived
# on the XPUB socket. If such a subscription starts with the node_topic_prefix,
# then send a ZeroMQ::hello() event to it, announcing our presence.
event Cluster::Backend::ZeroMQ::subscription(topic: string)
	{
	if ( starts_with(topic, node_topic_prefix + ".") )
		{
		Cluster::publish(topic, Cluster::Backend::ZeroMQ::hello, Cluster::node, Cluster::node_id());
		}
	}

# Receiving ZeroMQ::hello() from another node: Raise a Cluster::node_up()
# locally and if we never saw the node go away, log a warning.
event Cluster::Backend::ZeroMQ::hello(name: string, id: string)
	{
	if ( name in Cluster::nodes )
		{
		local n = Cluster::nodes[name];
		if ( n?$id )
			{
			Reporter::warning(fmt("node '%s' never said goodbye (old id:%s new id:%s",
			                  name, n$id, id));

			# We raise node_down() here for the old instance,
			# but it's obviously fake and somewhat lying.
			event Cluster::node_down(name, n$id);
			}
		}

	event Cluster::hello(name, id);
	}

event Cluster::Backend::ZeroMQ::unsubscription(topic: string)
	{
	print "ZeroMQ::unsubscription", topic;
	}
