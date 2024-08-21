#include "ZeroMQ.h"

#include <cerrno>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <variant>
#include <zmq.hpp>

#include "zeek/DebugLogger.h"
#include "zeek/Flare.h"
#include "zeek/Func.h"
#include "zeek/Reporter.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/iosource/Manager.h"

#include "Event.h"
#include "EventRegistry.h"
#include "IntrusivePtr.h"
#include "Val.h"

namespace zeek {

namespace plugin {

class Plugin;

namespace Zeek_Cluster_Backend_ZeroMQ {

extern plugin::Plugin plugin;

}
} // namespace plugin

namespace cluster::zeromq {

#define ZEROMQ_DEBUG(...) PLUGIN_DBG_LOG(zeek::plugin::Zeek_Cluster_Backend_ZeroMQ::plugin, __VA_ARGS__)


namespace detail {


namespace {
struct BrokerThreadArgs {
    zmq::socket_t xpub;
    zmq::socket_t xsub;
};
void broker_thread_fun(void* arg) {
    // Running in thread - lets hope it goes fine.
    auto args = static_cast<BrokerThreadArgs*>(arg);
    std::fprintf(stderr, "running proxy\n");
    try {
        zmq::proxy(args->xsub, args->xpub, zmq::socket_ref{});
    } catch ( zmq::error_t& err ) {
        if ( err.num() != ETERM )
            throw;
    }
    std::fprintf(stderr, "proxy done\n");
}

void self_thread_fun(void* arg);
} // namespace


class ZeroMQManagerImpl : public zeek::iosource::IOSource {
public:
    /**
     * A subscription was created on the XPUB socket.
     */
    struct SubscriptionMessage {
        std::string topic;
    };

    struct UnSubscriptionMessage {
        std::string topic;
    };

    struct TopicMessage {
        std::string topic;
        std::string payload;
    };

    using RemoteMessage = std::variant<SubscriptionMessage, UnSubscriptionMessage, TopicMessage>;

    ZeroMQManagerImpl(cluster::Serializer* serializer) : serializer(serializer) {
        publish_buffer.reserve(4096); // magic
    }

    void InitPostScript() {
        listen_xpub_endpoint =
            zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::listen_xpub_endpoint")->ToStdString();
        listen_xsub_endpoint =
            zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::listen_xsub_endpoint")->ToStdString();
        connect_xpub_endpoint =
            zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::connect_xpub_endpoint")->ToStdString();
        connect_xsub_endpoint =
            zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::connect_xsub_endpoint")->ToStdString();


        event_unsubscription = zeek::event_registry->Register("Cluster::Backend::ZeroMQ::unsubscription");
        event_subscription = zeek::event_registry->Register("Cluster::Backend::ZeroMQ::subscription");

        zeek::iosource_mgr->Register(this, true /* dont count*/, false /*manage_lifetime*/);
        if ( ! zeek::iosource_mgr->RegisterFd(messages_flare.FD(), this) ) {
            zeek::reporter->Error("Failed to register messages_flare with IO manager");
            return;
        }
    }

    void Terminate() {
        ZEROMQ_DEBUG("Terminate");

        broker_thread_ctx.shutdown();
        ZEROMQ_DEBUG("Joining broker_thread");
        if ( broker_thread.joinable() )
            broker_thread.join();
        ZEROMQ_DEBUG("Joined broker_thread");

        self_thread_ctx.shutdown();
        ZEROMQ_DEBUG("Joining self_thread");
        if ( self_thread.joinable() )
            self_thread.join();

        ZEROMQ_DEBUG("Terminated");
    }

    bool Connect() {
        ZEROMQ_DEBUG("Connect");
        try {
            xsub = zmq::socket_t(self_thread_ctx, zmq::socket_type::xsub);
            xpub = zmq::socket_t(self_thread_ctx, zmq::socket_type::xpub);

            xsub.connect(connect_xsub_endpoint);
            xpub.connect(connect_xpub_endpoint);

        } catch ( zmq::error_t& err ) {
            zeek::reporter->Error("Failed to connect ZeroMQ: %s", err.what());
        }

        // We may not be connected yet, but there's no logging either unless
        // we hook into zmq_socket_monitor.
        //
        // Check the following if we wanted to add ZeroMQ into the IO loop without
        // the flare. Maybe?
        //
        // https://funcptr.net/2012/09/10/zeromq---edge-triggered-notification/
        self_thread = std::thread(self_thread_fun, this);

        return true;
    }

    /**
     * Function executed in a separate thread in the background.
     *
     * Communicates with the main thread through the messages
     * vector and the messages flare.
     *
     * XXX: Optimize and clean this!
     */
    void Run() {
        fprintf(stderr, "Self thread running!\n");

        while ( true ) {
            std::vector<zmq::pollitem_t> items = {
                {.socket = xsub.handle(), .fd = 0, .events = ZMQ_POLLIN | ZMQ_POLLERR},
                {.socket = xpub.handle(), .fd = 0, .events = ZMQ_POLLIN | ZMQ_POLLERR},
            };

            try {
                //                 std::fprintf(stderr, "polling\n");
                int r = zmq::poll(items, std::chrono::seconds(-1));
                //                std::fprintf(stderr, "poll done r=%d\n", r);

                for ( size_t i = 0; i < items.size(); i++ ) {
                    const auto& item = items[i];
                    // std::fprintf(stderr, "items[%lu]=%s %s %s\n", i, i == 0 ? "xsub" : "xpub",
                    //              item.revents & ZMQ_POLLIN ? "pollin " : "", item.revents & ZMQ_POLLERR ? "err" :
                    //              "");

                    // Nothing to do?
                    if ( item.revents == 0 )
                        continue;

                    std::vector<zmq::message_t> msgs;
                    zmq::socket_ref ref = i == 0 ? xsub : xpub;

                    do {
                        msgs.emplace_back(); // make space for a message part.
                        auto& msg = msgs.back();
                        auto r = ref.recv(msg, zmq::recv_flags::none);
                        // std::fprintf(stderr, "size=%lu more=%d %s\n", msg.size(), msg.more(), msg.str().c_str());

                        if ( ! r )
                            continue;

                    } while ( msgs.back().more() );

                    // XXX: Could we try reading with nowait once more to see if there's more messages?

                    RemoteMessage rm;

                    if ( i == 0 ) {
                        // two messages, topic and payload
                        if ( msgs.size() == 2 ) {
                            std::string topic(msgs[0].data<const char>(), msgs[0].size());
                            std::string payload(msgs[1].data<const char>(), msgs[1].size());
                            rm = TopicMessage{std::move(topic), std::move(payload)};
                        }
                        else {
                            std::fprintf(stderr, " UNEXPECTED msgs %lu\n", msgs.size());
                        }
                    }
                    else if ( i == 1 ) {
                        // XPUB socket should only see subscribe/unsubscribe requests
                        auto first = *reinterpret_cast<const uint8_t*>(msgs[0].data());
                        if ( first == 0 || first == 1 ) {
                            auto* start = msgs[0].data<const char>() + 1;
                            std::string topic(start, msgs[0].size() - 1);
                            if ( first == 1 )
                                rm = SubscriptionMessage{topic};
                            else if ( first == 0 )
                                rm = UnSubscriptionMessage{topic};
                            else
                                assert(false);
                        }
                    }
                    else {
                        fprintf(stderr, "Unexpected message i=%zu", i);
                    }

                    if ( rm.index() != std::variant_npos ) {
                        std::scoped_lock sl(messages_mtx);
                        messages.emplace_back(std::move(rm));
                        if ( messages.size() == 1 )
                            messages_flare.Fire();
                    }
                }
            } catch ( zmq::error_t& err ) {
                if ( err.num() == ETERM )
                    return;

                if ( err.num() == EINTR )
                    continue;

                std::fprintf(stderr, "zmq::poll() error %s\n", err.what());
                throw;
            }
        }
    }

    bool SpawnBrokerThread() {
        ZEROMQ_DEBUG("Spawning thread listening on xsub=%s xpub=%s", listen_xsub_endpoint.c_str(),
                     listen_xpub_endpoint.c_str());

        try {
            zmq::socket_t bxsub(broker_thread_ctx, zmq::socket_type::xsub);
            zmq::socket_t bxpub(broker_thread_ctx, zmq::socket_type::xpub);

            bxsub.bind(listen_xsub_endpoint);
            bxpub.bind(listen_xpub_endpoint);

            broker_thread_args = {std::move(bxsub), std::move(bxpub)};

        } catch ( const zmq::error_t& err ) {
            zeek::reporter->Error("Failed to spawn ZeroMQ broker thread: %s", err.what());
            return false;
        }

        broker_thread = std::thread(broker_thread_fun, &broker_thread_args);

        return true;
    }

    bool PublishEvent(const std::string& topic, const cluster::detail::Event& event) {
        if ( ! serializer->SerializeEventInto(publish_buffer, event) )
            return false;

        try {
            while ( true ) {
                auto r = xpub.send(zmq::const_buffer(topic.data(), topic.size()), zmq::send_flags::sndmore);
                if ( r )
                    break;
                // handle EEAGAIN, not pretty
            }
            while ( true ) {
                auto r = xpub.send(zmq::const_buffer(publish_buffer.data(), publish_buffer.size()));
                if ( r )
                    break;
                // handle EEAGAIN, not pretty
            }
        } catch ( zmq::error_t& err ) {
            zeek::reporter->Error("Failed to publish to %s: %s", topic.c_str(), err.what());
            return false;
        }

        return true;
    }

    bool Subscribe(const std::string& topic_prefix) {
        ZEROMQ_DEBUG("Subscribing to %s", topic_prefix.c_str());
        try {
            std::string msg = "\x01" + topic_prefix;
            xsub.send(zmq::const_buffer(msg.data(), msg.size()));
        } catch ( zmq::error_t& err ) {
            zeek::reporter->Error("Failed to subscribe to topic %s: %s", topic_prefix.c_str(), err.what());
            return false;
        }

        return true;
    };

    bool Unsubscribe(const std::string& topic_prefix) {
        std::fprintf(stderr, "Unsubscribe not implemented\n");
        return false;
    };

    /**
     * This is the same pattern as for NATS.
     */
    void Process() override {
        // ZEROMQ_DEBUG("Process()");
        std::vector<RemoteMessage> to_process;
        {
            std::scoped_lock lock(messages_mtx);
            messages_flare.Extinguish();
            to_process = std::move(messages);
            messages.clear();
        }

        for ( const auto& msg : to_process ) {
            if ( auto* sm = std::get_if<SubscriptionMessage>(&msg) ) {
                ZEROMQ_DEBUG("Enqueueing subscription event for %s ptr=%p name=%s have_handlers=%d", sm->topic.c_str(),
                             event_subscription.Ptr(), event_subscription->Name(), bool(event_subscription));
                zeek::event_mgr.Enqueue(event_subscription, zeek::make_intrusive<zeek::StringVal>(sm->topic));
            }
            else if ( auto* tm = std::get_if<TopicMessage>(&msg) ) {
                auto* payload = reinterpret_cast<const std::byte*>(tm->payload.data());
                auto payload_size = tm->payload.size();
                auto r = serializer->UnserializeEvent(payload, payload_size);

                if ( ! r ) {
                    zeek::reporter->Error("Failed to unserialize message");
                    continue;
                }

                auto& event = *r;
                zeek::event_mgr.Enqueue(event.Handler(), std::move(event.args), util::detail::SOURCE_BROKER, 0, nullptr,
                                        event.timestamp);
            }
            else {
                ZEROMQ_DEBUG("Unhandled to process!");
            }
        }
    }

    double GetNextTimeout() override { return -1; }

    const char* Tag() override { return "ZeroMQ"; }

private:
    std::unique_ptr<Serializer> serializer;
    cluster::detail::byte_buffer publish_buffer;

    std::string connect_xsub_endpoint;
    std::string connect_xpub_endpoint;
    std::string listen_xsub_endpoint;
    std::string listen_xpub_endpoint;

    EventHandlerPtr event_subscription;
    EventHandlerPtr event_unsubscription;

    BrokerThreadArgs broker_thread_args;
    zmq::context_t broker_thread_ctx;
    std::thread broker_thread;

    zmq::context_t self_thread_ctx;
    zmq::socket_t xsub;
    zmq::socket_t xpub;
    std::thread self_thread;

    std::mutex messages_mtx;
    std::vector<RemoteMessage> messages;
    zeek::detail::Flare messages_flare;
};

namespace {
void self_thread_fun(void* arg) {
    auto* self = static_cast<ZeroMQManagerImpl*>(arg);
    self->Run();
}
} // namespace

} // namespace detail


ZeroMQBackend::ZeroMQBackend(Serializer* serializer) { impl = std::make_unique<detail::ZeroMQManagerImpl>(serializer); }
ZeroMQBackend::~ZeroMQBackend() {}

void ZeroMQBackend::InitPostScript() { impl->InitPostScript(); }
void ZeroMQBackend::Terminate() { impl->Terminate(); }

bool ZeroMQBackend::Connect() { return impl->Connect(); }
bool ZeroMQBackend::SpawnBrokerThread() { return impl->SpawnBrokerThread(); }

bool ZeroMQBackend::PublishEvent(const std::string& topic, const cluster::detail::Event& event) {
    return impl->PublishEvent(topic, event);
}

bool ZeroMQBackend::Subscribe(const std::string& topic_prefix) { return impl->Subscribe(topic_prefix); }

bool ZeroMQBackend::Unsubscribe(const std::string& topic_prefix) { return impl->Unsubscribe(topic_prefix); }


} // namespace cluster::zeromq
} // namespace zeek
