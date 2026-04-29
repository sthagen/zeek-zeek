.. _conn-handling:

===================
Connection Handling
===================

Checksum Behavior
=================

By default, Zeek will mostly ignore packets that have invalid checksums.

When the IPv4 header checksum is invalid, Zeek produces a ``bad_IP_checksum`` weird and
discards the packet before proceeding with its connection lookup step.

As of Zeek 8.2, for L4 checksums (TCP, UDP, ICMP, ...), Zeek will only determine
if the L4 checksum is invalid *after* looking up or creating a connection using
information from the potentially corrupt L4 header.

This connection lookup is implemented in ``IPBasedAnalyzer::AnalyzePacket()``.
Checksum validation then happens in the concrete protocol specific analyzers within
``TCPAnalyzer::DeliverPacket()``, ``UDPAnalyzer::DeliverPacket()``, etc.

Packets with invalid checksums are not counted towards ``orig_pkts`` or ``resp_pkts``
of a connection and also not passed to a connection's analyzers.
However, a ``c`` or ``C`` is added to the history field in logarithmic fashion.

This behavior can result in ``conn.log`` entries that show zero ``orig_pkts`` and
``resp_pkts``, but do show ``c`` or ``C`` sequences in the history.

.. code:: console

    # zeek -D -b -r Traces/tcp/syn-bad.pcap base/protocols/conn LogAscii::use_json=T
    # jq < conn.log
    {
      "ts": 1362692526.869344,
      "uid": "CJKFoj4bpHEhTeaRoj",
      "id.orig_h": "141.142.228.5",
      "id.orig_p": 59856,
      "id.resp_h": "192.150.187.43",
      "id.resp_p": 80,
      "proto": "tcp",
      "conn_state": "OTH",
      "local_orig": false,
      "local_resp": false,
      "missed_bytes": 0,
      "history": "C",
      "orig_pkts": 0,
      "orig_ip_bytes": 0,
      "resp_pkts": 0,
      "resp_ip_bytes": 0,
      "ip_proto": 6
    }

    # zeek -b  -r Traces/dns/dns-corrupt.pcap base/protocols/conn LogAscii::use_json=T
    # jq < conn.log
    {
      "ts": 1777450586.006844,
      "uid": "CJKFoj4bpHEhTeaRoj",
      "id.orig_h": "192.168.0.109",
      "id.orig_p": 34357,
      "id.resp_h": "8.8.8.8",
      "id.resp_p": 53,
      "proto": "udp",
      "conn_state": "OTH",
      "local_orig": true,
      "local_resp": false,
      "missed_bytes": 0,
      "history": "Cc",
      "orig_pkts": 0,
      "orig_ip_bytes": 0,
      "resp_pkts": 0,
      "resp_ip_bytes": 0,
      "ip_proto": 17
    }


The ``history`` fields are ``C`` and ``cC`` for the respective test captures,
but ``orig_pkts`` and ``resp_pkts`` are zero.

See `issue #5277 <https://github.com/zeek/zeek/issues/5277>`_ on GitHub for some
discussion around this behavior.


Flipping Connections
====================

Zeek works with a concept of originator and responder for a connection. This
is visible in the Zeek scripting layer as the ``is_orig: bool`` event parameter,
but also on much lower-level C++ APIs like the various Analyzer APIs or accessors
on ``Connection`` instances (``OrigAddr()`` and ``RespAddr(), or ``OrigPort()``
and ``RespPort()``).

In certain scenarios, Zeek decides to flip the notion of originator and responder.
Usually, the first packet of a connection determines which endpoint is the originator
and which the responder. As a special case, when the first packet has a source port
that is set in :zeek:see:`likely_server_ports`, this notion is flipped and a ``^``
(caret) added to this connection's history.

This connection flipping permeates various layers. For example, there is a
:zeek:see:`connection_flipped` event that allows Zeek scripts to react on it.
Additionally, the Analyzer API offers a virtual ``FlipRoles()`` method that
is executed recursively on the analyzer tree when endpoint flipping happens.
All analyzers have to update their internal state upon such an event.
Consider the ``ConnSize_Analyzer`` analyzer: It tracks packet and byte counts
transferred by originator and responder endpoints. When the notion of these
endpoints changes, a ``ConnSize_Analyzer`` instance needs to update its own
internal state, as for any following ``DeliverPacket()`` calls, the meaning
of ``is_orig`` is inverted.

Luckily, this flipping usually happens before the first packet of connection
is processed. More recently, however, flipping on
`the second packet <https://github.com/zeek/zeek/pull/2191>`_ has been added.
Technically, flipping can be triggered by any analyzer or logic at any time,
but this results in the very unfortunate scenario that an in-flight ``ForwardStream()`` or
``ForwardPacket()`` invocation on a connection's analyzer tree ends-up using a
stale ``is_orig`` parameter. For example, this was observed with the ``ConnSize_Analyzer``
that is visited after a ``TCPSessionAdapter::Process()`` invocation. If ``Process()``
flipped the connection, the ``DeliverPacket()`` invocation on the ``ConnSize_Analyzer``
would use a stale ``is_orig`` stack variable resulting in miss-accounting
single packets.

In the future, it might make sense to re-design Zeek's lowest layers to be agnostic of
the originator and responder notion. That is, always sort endpoints deterministically
and name them, e.g., ``left`` and ``right``. The notion of originator and responder
shouldn't vanish from Zeek, but instead implemented on a higher-level instead.
For example, the ``IPBasedConnKey`` class currently holds a ``flipped`` member and
has a ``FlipRoles()`` API.
However, it seems unreasonable that the raw connection tracking layer should
have knowledge of the originator and responder concept, as it introduces quite
some complexity.
