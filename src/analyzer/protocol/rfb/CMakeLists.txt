zeek_add_plugin(
    Zeek RFB
    SOURCES RFB.cc Plugin.cc
    BIFS events.bif
    PAC rfb.pac rfb-analyzer.pac rfb-protocol.pac)
