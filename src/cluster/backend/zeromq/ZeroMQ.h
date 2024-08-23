// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>

#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Serializer.h"

namespace zeek::cluster::zeromq {

namespace detail {

class ZeroMQManagerImpl;

}

class ZeroMQBackend : public cluster::Backend {
public:
    ZeroMQBackend(Serializer* serializer);
    ~ZeroMQBackend();

    using cluster::Backend::PublishEvent;

    void InitPostScript() override;
    void Terminate() override;

    /**
     * Connect to the node running the broker thread.
     */
    bool Connect();

    /**
     * Spawns thread running zmq_proxy() or some reimplementation. Only one node in a
     * cluster should run the broker thread.
     */
    bool SpawnBrokerThread();

    bool PublishEvent(const std::string& topic, const cluster::detail::Event& event) override;

    bool Subscribe(const std::string& topic_prefix) override;

    bool Unsubscribe(const std::string& topic_prefix) override;

    bool PublishLogWrites(const cluster::detail::LogWriteHeader& header, cluster::detail::LogRecords records) override;

    static Backend* Instantiate(Serializer* serializer) { return new ZeroMQBackend(serializer); }

private:
    std::unique_ptr<detail::ZeroMQManagerImpl> impl;
};

} // namespace zeek::cluster::zeromq
