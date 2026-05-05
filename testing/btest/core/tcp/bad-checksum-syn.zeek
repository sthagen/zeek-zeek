# @TEST-DOC: Baseline the behavior documented around corrupt TCP checksums, packet counts and history.
#
# @TEST-EXEC: zeek -b -r $TRACES/tcp/syn-bad.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m uid orig_pkts resp_pkts history conn_state conn.log

@load base/protocols/conn
