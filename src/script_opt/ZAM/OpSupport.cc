#include "zeek/script_opt/ZAM/OpSupport.h"

#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/conn-size/ConnSize.h"
#include "zeek/broker/Manager.h"
#include "zeek/logging/Manager.h"
#include "zeek/packet_analysis/Manager.h"
#include "zeek/packet_analysis/protocol/gtpv1/GTPv1.h"
#include "zeek/packet_analysis/protocol/teredo/Teredo.h"
#include "zeek/session/Manager.h"

bool zeek::detail::log_mgr_write(zeek::EnumVal* v, zeek::RecordVal* r) { return zeek::log_mgr->Write(v, r); }

size_t zeek::detail::broker_mgr_flush_log_buffers() { return zeek::broker_mgr->FlushLogBuffers(); }

zeek::Connection* zeek::detail::session_mgr_find_connection(zeek::Val* cid) {
    return zeek::session_mgr->FindConnection(cid);
}

bool zeek::detail::packet_mgr_remove_teredo(zeek::Val* cid) {
    auto teredo = zeek::packet_mgr->GetAnalyzer("Teredo");
    if ( teredo ) {
        zeek::detail::ConnKey conn_key(cid);
        static_cast<zeek::packet_analysis::teredo::TeredoAnalyzer*>(teredo.get())->RemoveConnection(conn_key);
        return true;
    }
    return false;
}

bool zeek::detail::packet_mgr_remove_gtpv1(zeek::Val* cid) {
    auto gtpv1 = zeek::packet_mgr->GetAnalyzer("GTPv1");
    if ( gtpv1 ) {
        zeek::detail::ConnKey conn_key(cid);
        static_cast<zeek::packet_analysis::gtpv1::GTPv1_Analyzer*>(gtpv1.get())->RemoveConnection(conn_key);
        return true;
    }
    return false;
}

zeek::plugin::Component* zeek::detail::packet_mgr_lookup(zeek::EnumVal* v) { return zeek::packet_mgr->Lookup(v); }

zeek::plugin::Component* zeek::detail::analyzer_mgr_lookup(zeek::EnumVal* v) { return zeek::analyzer_mgr->Lookup(v); }

zeek_uint_t zeek::detail::conn_size_get_bytes_threshold(Val* cid, bool is_orig) {
    if ( auto* a = analyzer::conn_size::GetConnsizeAnalyzer(cid) )
        return static_cast<analyzer::conn_size::ConnSize_Analyzer*>(a)->GetByteAndPacketThreshold(true, is_orig);

    return 0;
}

bool zeek::detail::conn_size_set_bytes_threshold(zeek_uint_t threshold, Val* cid, bool is_orig) {
    if ( auto* a = analyzer::conn_size::GetConnsizeAnalyzer(cid) ) {
        static_cast<analyzer::conn_size::ConnSize_Analyzer*>(a)->SetByteAndPacketThreshold(threshold, true, is_orig);
        return true;
    }

    return false;
}
