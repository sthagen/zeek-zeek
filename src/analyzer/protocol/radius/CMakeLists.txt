zeek_add_plugin(
    Zeek RADIUS
    SOURCES RADIUS.cc Plugin.cc
    BIFS events.bif
    PAC radius.pac radius-analyzer.pac radius-protocol.pac)
