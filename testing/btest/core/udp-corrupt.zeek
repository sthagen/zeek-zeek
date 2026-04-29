# @TEST-DOC: Baseline the behavior documented around corrupt UDP checksums, packet counts and history.
#
# @TEST-EXEC: zeek -r $TRACES/dns/dns-corrupt.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m uid orig_pkts resp_pkts history conn_state conn.log

@load base/protocols/conn
