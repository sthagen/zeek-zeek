zeek_add_plugin(
    Zeek SSH
    SOURCES SSH.cc Plugin.cc
    BIFS types.bif events.bif
    PAC ssh.pac ssh-analyzer.pac ssh-protocol.pac consts.pac)
