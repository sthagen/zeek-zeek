zeek_add_plugin(
    Zeek Syslog
    SOURCES Syslog.cc Plugin.cc
    BIFS events.bif
    PAC syslog.pac syslog-analyzer.pac syslog-protocol.pac)
