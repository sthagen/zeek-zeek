zeek_add_plugin(
    Zeek GSSAPI
    SOURCES GSSAPI.cc Plugin.cc
    BIFS events.bif
    PAC gssapi.pac gssapi-protocol.pac gssapi-analyzer.pac
        ${PROJECT_SOURCE_DIR}/src/analyzer/protocol/asn1/asn1.pac)
