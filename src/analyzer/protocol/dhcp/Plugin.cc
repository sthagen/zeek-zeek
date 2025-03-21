// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/dhcp/DHCP.h"

namespace zeek::plugin::detail::Zeek_DHCP {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(new zeek::analyzer::Component("DHCP", zeek::analyzer::dhcp::DHCP_Analyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::DHCP";
        config.description = "DHCP analyzer";
        return config;
    }
} plugin;

} // namespace zeek::plugin::detail::Zeek_DHCP
