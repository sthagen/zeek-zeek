#include "ZeroMQ.h"

#include <array>
#include <cerrno>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <variant>
#include <zmq.hpp>

#include "zeek/DebugLogger.h"
#include "zeek/Event.h"
#include "zeek/EventRegistry.h"
#include "zeek/Flare.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Reporter.h"
#include "zeek/Val.h"
#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/cluster/serializer/binary-serialization-format/Serializer.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/iosource/Manager.h"
#include "zeek/logging/Manager.h"
#include "zeek/util.h"

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
    std::fprintf(stderr, "[zeromq] running broker thread\n");

    util::detail::set_thread_name("zmq-broker");
    try {
        zmq::proxy(args->xsub, args->xpub, zmq::socket_ref{});
    } catch ( zmq::error_t& err ) {
        if ( err.num() != ETERM )
            throw;
    }
    std::fprintf(stderr, "[zeromq] broker thread done\n");
}

void self_thread_fun(void* arg);
} // namespace


class ZeroMQManagerImpl : public zeek::iosource::IOSource {
public:
    using MultipartMessage = std::vector<zmq::message_t>;

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

    struct LogMessage {
        std::string format;
        std::string payload;
    };

    using RemoteMessage = std::variant<SubscriptionMessage, UnSubscriptionMessage, TopicMessage, LogMessage>;

    ZeroMQManagerImpl(cluster::Serializer* serializer) : serializer(serializer) {
        publish_buffer.reserve(4096); // magic

        log_serializer = std::make_unique<zeek::cluster::detail::BinarySerializationFormatLogSerializer>();
    }

    // Populate C++ side variables from script land.
    void InitPostScript() {
        my_node_id = zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::my_node_id")->ToStdString();
        listen_xpub_endpoint =
            zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::listen_xpub_endpoint")->ToStdString();
        listen_xsub_endpoint =
            zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::listen_xsub_endpoint")->ToStdString();
        connect_xpub_endpoint =
            zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::connect_xpub_endpoint")->ToStdString();
        connect_xsub_endpoint =
            zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::connect_xsub_endpoint")->ToStdString();

        listen_log_endpoint =
            zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::listen_log_endpoint")->ToStdString();

        const auto& log_endpoints =
            zeek::id::find_val<zeek::VectorVal>("Cluster::Backend::ZeroMQ::connect_log_endpoints");
        for ( unsigned int i = 0; i < log_endpoints->Size(); i++ )
            connect_log_endpoints.push_back(log_endpoints->StringValAt(i)->ToStdString());

        event_unsubscription = zeek::event_registry->Register("Cluster::Backend::ZeroMQ::unsubscription");
        event_subscription = zeek::event_registry->Register("Cluster::Backend::ZeroMQ::subscription");

        zeek::iosource_mgr->Register(this, true /* dont count*/, false /*manage_lifetime*/);
        if ( ! zeek::iosource_mgr->RegisterFd(messages_flare.FD(), this) ) {
            zeek::reporter->Error("Failed to register messages_flare with IO manager");
            return;
        }
    }

    void Terminate() {
        if ( broker_thread.joinable() ) {
            ZEROMQ_DEBUG("Shutting down broker_thread_ctx");
            broker_thread_ctx.shutdown();
            ZEROMQ_DEBUG("Joining broker_thread");
            broker_thread.join();
            ZEROMQ_DEBUG("Joined broker_thread");
        }

        ZEROMQ_DEBUG("Shutting down ctx");
        ctx.shutdown();
        ZEROMQ_DEBUG("Joining self_thread");
        if ( self_thread.joinable() )
            self_thread.join();

        ZEROMQ_DEBUG("Terminated");
    }

    bool Connect() {
        ZEROMQ_DEBUG("Connect");
        try {
            xsub = zmq::socket_t(ctx, zmq::socket_type::xsub);

            // XXX: Should we set ZMQ_XPUB_NODROP ?
            xpub = zmq::socket_t(ctx, zmq::socket_type::xpub);

            xsub.connect(connect_xsub_endpoint);
            xpub.connect(connect_xpub_endpoint);

        } catch ( zmq::error_t& err ) {
            zeek::reporter->Error("Failed to connect ZeroMQ: %s", err.what());
        }


        log_push = zmq::socket_t(ctx, zmq::socket_type::push);
        log_pull = zmq::socket_t(ctx, zmq::socket_type::pull);

        auto log_sndhwm =
            static_cast<int>(zeek::id::find_val<zeek::CountVal>("Cluster::Backend::ZeroMQ::log_sndhwm")->AsInt());

        auto log_sndbuf =
            static_cast<int>(zeek::id::find_val<zeek::CountVal>("Cluster::Backend::ZeroMQ::log_sndbuf")->AsInt());

        auto log_rcvhwm =
            static_cast<int>(zeek::id::find_val<zeek::CountVal>("Cluster::Backend::ZeroMQ::log_rcvhwm")->AsInt());

        auto log_rcvbuf =
            static_cast<int>(zeek::id::find_val<zeek::CountVal>("Cluster::Backend::ZeroMQ::log_rcvbuf")->AsInt());

        ZEROMQ_DEBUG("Setting log_sndhwm=%d log_sndbuf=%d log_rcvhwm=%d log_rcvbuf=%d", log_sndhwm, log_sndbuf,
                     log_rcvhwm, log_rcvbuf);
        log_push.set(zmq::sockopt::sndhwm, log_sndhwm);
        log_push.set(zmq::sockopt::sndbuf, log_sndbuf);
        log_pull.set(zmq::sockopt::rcvhwm, log_rcvhwm);
        log_pull.set(zmq::sockopt::rcvbuf, log_rcvbuf);

        zmq::message_t msg;

        for ( const auto& endp : connect_log_endpoints ) {
            ZEROMQ_DEBUG("Connecting log_push socket with %s", endp.c_str());
            log_push.connect(endp);
        }

        if ( ! listen_log_endpoint.empty() ) {
            ZEROMQ_DEBUG("Listening on log pull socket: %s", listen_log_endpoint.c_str());
            log_pull.bind(listen_log_endpoint);
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
        fprintf(stderr, "[zeromq] background thread running!\n");

        struct SocketInfo {
            zmq::socket_ref socket;
            std::string name;
            std::function<void(const std::vector<MultipartMessage>&)> handler;
        };

        // Could also store the handler function.
        std::vector<SocketInfo> sockets = {
            {.socket = xsub,
             .name = "xsub",
             .handler = std::bind(&ZeroMQManagerImpl::HandleXSubMessages, this, std::placeholders::_1)},
            {.socket = xpub,
             .name = "xpub",
             .handler = std::bind(&ZeroMQManagerImpl::HandleXPubMessages, this, std::placeholders::_1)},
            {.socket = log_pull,
             .name = "log_pull",
             .handler = std::bind(&ZeroMQManagerImpl::HandleLogMessages, this, std::placeholders::_1)},
        };
        std::vector<zmq::pollitem_t> items(sockets.size());
        // For each socket, store a list of multipart messages.

        std::vector<std::vector<MultipartMessage>> rcv_messages(sockets.size());

        while ( true ) {
            for ( size_t i = 0; i < sockets.size(); i++ )
                items[i] = {.socket = sockets[i].socket.handle(), .fd = 0, .events = ZMQ_POLLIN | ZMQ_POLLERR};

            // Awkward.
            std::array<std::vector<std::vector<zmq::message_t>>, 3> rcv_messages = {};
            try {
                // std::fprintf(stderr, "polling\n");
                int r = zmq::poll(items, std::chrono::seconds(-1));
                // std::fprintf(stderr, "poll done r=%d\n", r);

                for ( size_t i = 0; i < items.size(); i++ ) {
                    const auto& item = items[i];


                    // std::fprintf(stderr, "items[%lu]=%s %s %s\n", i, sockets[i].name.c_str(),
                    //            item.revents & ZMQ_POLLIN ? "pollin " : "", item.revents & ZMQ_POLLERR ? "err" : "");

                    if ( item.revents & ZMQ_POLLERR ) {
                        // What should we be doing? Re-open sockets? Terminate?
                        fprintf(stderr, "[zeromq] ERROR on socket %zu %p\n", i, item.socket);
                    }

                    // Nothing to do?
                    if ( (item.revents & ZMQ_POLLIN) == 0 )
                        continue;

                    zmq::socket_ref ref = sockets[i].socket;

                    bool consumed_one = false;

                    // Read as many messages as possible.
                    do {
                        zmq::message_t msg;
                        rcv_messages[i].emplace_back(); // make room for a multiparte message

                        auto& into = rcv_messages[i].back();

                        consumed_one = false;
                        bool more = false;

                        // Read a multi-part message.
                        do {
                            auto r = ref.recv(msg, zmq::recv_flags::dontwait);
                            if ( r ) {
                                consumed_one = true;
                                more = msg.more();
                                into.emplace_back(std::move(msg));
                            }
                            else {
                                // EAGAIN and more flag set? Loop!
                                if ( more )
                                    continue;
                            }
                        } while ( more );
                    } while ( consumed_one );

                    assert(rcv_messages[i].back().size() == 0);
                    rcv_messages[i].pop_back();
                }
            } catch ( zmq::error_t& err ) {
                if ( err.num() == ETERM )
                    return;
            }

            // At this point, we've received anything that was readable from the sockets.
            // Now interpret and enqueue it into messages.
            for ( size_t i = 0; i < sockets.size(); i++ ) {
                if ( rcv_messages[i].empty() )
                    continue;

                sockets[i].handler(rcv_messages[i]);
            }
        }
    }

    void PushMessages(std::vector<RemoteMessage>&& msgs) {
        std::scoped_lock sl(messages_mtx);

        bool fire_flare = messages.empty() && ! msgs.empty();

        // std::fprintf(stderr, "Pushing %zu messages fire=%d\n", msgs.size(), fire_flare);

        for ( auto&& m : msgs )
            messages.emplace_back(std::move(m));

        if ( fire_flare )
            messages_flare.Fire();
    }

    void HandleLogMessages(const std::vector<MultipartMessage>& msgs) {
        std::vector<RemoteMessage> rmsgs;
        rmsgs.reserve(msgs.size());

        for ( const auto& msg : msgs ) {
            if ( msg.size() != 4 ) {
                std::fprintf(stderr, "[zeromq] log: expected 4 parts, have %zu!\n", msg.size());
                continue;
            }
            // sender, format, type,  payload
            rmsgs.emplace_back(LogMessage{.format = std::string(msg[1].data<const char>(), msg[1].size()),
                                          .payload = std::string(msg[3].data<const char>(), msg[3].size())});
        }

        PushMessages(std::move(rmsgs));
    }

    void HandleXPubMessages(const std::vector<MultipartMessage>& msgs) {
        std::vector<RemoteMessage> rmsgs;
        rmsgs.reserve(msgs.size());

        for ( const auto& msg : msgs ) {
            if ( msg.size() != 1 ) {
                std::fprintf(stderr, "[zeromq] xpub: expected 1 part, have %zu!\n", msg.size());
                continue;
            }

            // Check if the messages starts with \x00 or \x01 to understand if it's
            // a subscription or unsubscription message.
            auto first = *reinterpret_cast<const uint8_t*>(msg[0].data());
            if ( first == 0 || first == 1 ) {
                RemoteMessage rm;
                auto* start = msg[0].data<const char>() + 1;
                std::string topic(start, msg[0].size() - 1);
                if ( first == 1 )
                    rm = SubscriptionMessage{std::move(topic)};
                else if ( first == 0 )
                    rm = UnSubscriptionMessage{std::move(topic)};
                else {
                    std::fprintf(stderr, "[zeromq] xpub: unexpected first char: have '0x%02x'", first);
                    continue;
                }

                // topic, payload for now.
                rmsgs.emplace_back(std::move(rm));
            }
        }

        PushMessages(std::move(rmsgs));
    }
    void HandleXSubMessages(const std::vector<MultipartMessage>& msgs) {
        std::vector<RemoteMessage> rmsgs;
        rmsgs.reserve(msgs.size());

        for ( const auto& msg : msgs ) {
            if ( msg.size() != 2 ) {
                std::fprintf(stderr, "[zeromq] xsub: expected 2 parts, have %zu!\n", msg.size());
                continue;
            }

            // topic, payload for now.
            rmsgs.emplace_back(TopicMessage{.topic = std::string(msg[0].data<const char>(), msg[0].size()),
                                            .payload = std::string(msg[1].data<const char>(), msg[1].size())});
        }

        PushMessages(std::move(rmsgs));
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
            broker_thread_args = {};
            zeek::reporter->Error("Failed to spawn ZeroMQ broker thread: %s", err.what());
            return false;
        }

        broker_thread = std::thread(broker_thread_fun, &broker_thread_args);

        return true;
    }

    bool PublishEvent(const std::string& topic, const cluster::detail::Event& event) {
        publish_buffer.clear();
        if ( ! serializer->SerializeEventInto(publish_buffer, event) )
            return false;

        // XXX: xpub is polled from the background thread. Not sure it's safe to publish
        // while we're polling it in parallel :-/
        //
        // We could instead use a pair or inproc socket to forward the Publish() to the
        // background thread which would then do the actual publishing.
        //
        // Or could attempt to remove the background thread.
        //
        // So far, there haven't been crashes though...
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

    bool PublishLogWrite(const logging::detail::LogWriteHeader& header,
                         zeek::Span<logging::detail::LogRecord> records) {
        // Serialize the record. This isn't doing any buffering yet.
        //
        // Not clear where the buffering should happen... maybe in
        // the frontend? That would maybe be better for re-usability.
        cluster::detail::byte_buffer buf;
        if ( ! log_serializer->SerializeLogWriteInto(buf, header, records) ) {
            return false;
        }

        const std::string& fmt = log_serializer->Name();
        static std::string message_type = "log-write";

        log_push.send(zmq::const_buffer{my_node_id.data(), my_node_id.size()},
                      zmq::send_flags::sndmore | zmq::send_flags::dontwait);
        log_push.send(zmq::const_buffer{fmt.data(), fmt.size()}, zmq::send_flags::sndmore | zmq::send_flags::dontwait);
        log_push.send(zmq::const_buffer{message_type.data(), message_type.size()},
                      zmq::send_flags::sndmore | zmq::send_flags::dontwait);

        zmq::send_result_t result;
        result = log_push.send(zmq::const_buffer{buf.data(), buf.size()}, zmq::send_flags::dontwait);
        if ( ! result ) {
            // XXX: It's not exactly clear what we should do if we reach HWM.
            //      we could block and hope a logger comes along that empties
            //      our internal queue, or discard messages and log very loudly
            //      and have metrics.
            //
            //      Maybe that should be configurable?
            reporter->Error("Failed to send log write HWM reached?!");
        }
        else {
            ZEROMQ_DEBUG("log write sending done %zu", *result);
        }
        return true;
    }

    /**
     * This is the same pattern as for NATS.
     */
    void Process() override {
        ZEROMQ_DEBUG("Process()");
        std::vector<RemoteMessage> to_process;
        {
            std::scoped_lock lock(messages_mtx);
            messages_flare.Extinguish();
            to_process = std::move(messages);
            messages.clear();
        }

        ZEROMQ_DEBUG("Got %zu message", to_process.size());
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
            else if ( auto* lm = std::get_if<LogMessage>(&msg) ) {
                ZEROMQ_DEBUG("Handling LogMessage!");

                // We could also dynamically lookup the right de-serializer, but
                // for now assume we just receive what is configured.
                if ( lm->format != log_serializer->Name() ) {
                    zeek::reporter->Error("Got log message in format '%s', have de-serializer '%s'", lm->format.c_str(),
                                          log_serializer->Name().c_str());
                    continue;
                }

                auto result =
                    log_serializer->UnserializeLogWrite(reinterpret_cast<const std::byte*>(lm->payload.data()),
                                                        lm->payload.size());

                if ( ! result ) {
                    zeek::reporter->Error("Failed to unserialize log message");
                    continue;
                }

                // Send the whole batch to the logging manager.
                zeek::log_mgr->WritesFromRemote(result->header, std::move(result->records));
            }

            else {
                ZEROMQ_DEBUG("Unhandled to process %zu!", msg.index());
            }
        }
    }

    double GetNextTimeout() override { return -1; }

    const char* Tag() override { return "ZeroMQ"; }

private:
    std::unique_ptr<Serializer> serializer;
    cluster::detail::byte_buffer publish_buffer;

    std::string my_node_id;

    std::string connect_xsub_endpoint;
    std::string connect_xpub_endpoint;
    std::string listen_xsub_endpoint;
    std::string listen_xpub_endpoint;

    std::vector<std::string> connect_log_endpoints;
    std::string listen_log_endpoint;

    EventHandlerPtr event_subscription;
    EventHandlerPtr event_unsubscription;

    BrokerThreadArgs broker_thread_args;
    zmq::context_t broker_thread_ctx;
    std::thread broker_thread;

    zmq::context_t ctx;
    zmq::socket_t xsub;
    zmq::socket_t xpub;

    zmq::socket_t log_push;
    zmq::socket_t log_pull;

    std::thread self_thread;

    std::mutex messages_mtx;
    std::vector<RemoteMessage> messages;
    zeek::detail::Flare messages_flare;

    std::unique_ptr<cluster::detail::LogSerializer> log_serializer;
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

bool ZeroMQBackend::PublishLogWrites(const logging::detail::LogWriteHeader& header,
                                     zeek::Span<logging::detail::LogRecord> records) {
    return impl->PublishLogWrite(header, records);
}


} // namespace cluster::zeromq
} // namespace zeek
