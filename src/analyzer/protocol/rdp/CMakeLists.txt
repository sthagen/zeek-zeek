zeek_add_plugin(
    Zeek RDP
    SOURCES RDPEUDP.cc RDP.cc Plugin.cc
    BIFS events.bif types.bif
    PAC rdp.pac rdp-analyzer.pac rdp-protocol.pac
        ${PROJECT_SOURCE_DIR}/src/analyzer/protocol/asn1/asn1.pac
    PAC rdpeudp.pac rdpeudp-analyzer.pac rdpeudp-protocol.pac)
