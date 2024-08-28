// See the file "COPYING" in the main distribution directory for copyright.
//
// Facade wrapper functions for calling into Zeek functionality from
// OPs/ZBI.op. Main motivation is to break header dependencies from ZBody.cc
// to the rest of Zeek
#pragma once

#include <cstddef>
#include <cstdint>

namespace zeek {
class Connection;
class EnumVal;
class RecordVal;
class Val;

namespace plugin {
class Component;
}
} // namespace zeek


using zeek_uint_t = uint64_t;

namespace zeek::detail {

// log_mgr->Write()
bool log_mgr_write(EnumVal* v, RecordVal* r);

// broker_mgr->FlushLogBuffers()
size_t broker_mgr_flush_log_buffers();

// session_mgr->FindConnection()
zeek::Connection* session_mgr_find_connection(Val* cid);

// I've seen these two cause overhead, maybe we should fix
// this differently via conn removal hooks or some such.
bool packet_mgr_remove_teredo(Val* cid);
bool packet_mgr_remove_gtpv1(Val* cid);

plugin::Component* packet_mgr_lookup(EnumVal* v);

plugin::Component* analyzer_mgr_lookup(EnumVal* v);

// Conn size analyzer accessors for byte thresholds.
//
// Note: The underlying API uses a bool parameter to distinguish between
// packet and byte thresholds. For now only need bytes and seems more graspable
// to use individual functions rather (or an enum for the threshold), but not
// the true/false discriminator.
zeek_uint_t conn_size_get_bytes_threshold(Val* cid, bool is_orig);
bool conn_size_set_bytes_threshold(zeek_uint_t threshold, Val* cid, bool is_orig);

} // namespace zeek::detail
