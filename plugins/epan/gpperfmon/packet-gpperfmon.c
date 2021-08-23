#include "config.h"
#include <epan/packet.h>

#define PERFMON_PORT 8888

#define GPMON_PKTTYPE_HELLO 1
#define GPMON_PKTTYPE_METRICS 2
#define GPMON_PKTTYPE_QLOG 3
#define GPMON_PKTTYPE_QEXEC 4
#define GPMON_PKTTYPE_SEGINFO 5
#define GPMON_PKTTYPE_QUERY_HOST_METRICS 7 // query metrics update from a segment such as CPU per query
#define GPMON_PKTTYPE_FSINFO 8
#define GPMON_PKTTYPE_QUERYSEG 9

static int hf_perfmon_pdu_magic = -1;
static int hf_perfmon_pdu_version = -1;
static int hf_perfmon_pdu_pkttype = -1;
static int hf_perfmon_pdu_tmid = -1;
static int hf_perfmon_pdu_ssid = -1;
static int hf_perfmon_pdu_ccnt = -1;
static int hf_perfmon_pdu_segid = -1;
static int hf_perfmon_pdu_dbid = -1;
static int hf_perfmon_pdu_pid = -1;
static int hf_perfmon_pdu_nid = -1;
static int hf_perfmon_pdu_rowsout = -1;
static int hf_perfmon_pdu_rowsin = -1;
static int hf_perfmon_pdu_status = -1;
static int hf_perfmon_pdu_memory_used = -1;
static int hf_perfmon_pdu_memory_available = -1;

static gint ett_perfmon = -1;

static int proto_perfmon = -1;

static const value_string packettypenames[] = {
    { 1, "HELLO" },
    { 2, "METRICS" },
    { 3, "QLOG" },
    { 4, "QEXEC" },
    { 5, "SEGINFO" },
    { 7, "QUERY_HOST_METRICS" },
    { 8, "FSINFO" },
    { 9, "QUERYSEG" },
    { 0, NULL }
};

static const value_string node_statuses[] = {
    { 0, "Initialize" },
    { 1, "Executing" },
    { 2, "Finished" }
};

static int
dissect_perfmon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    gint offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GPPERFMON");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_perfmon, tvb, 0, -1, ENC_NA);
    proto_tree *perfmon_tree = proto_item_add_subtree(ti, ett_perfmon);
    proto_tree_add_item(perfmon_tree, hf_perfmon_pdu_magic, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(perfmon_tree, hf_perfmon_pdu_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_item *type_item = proto_tree_add_item(perfmon_tree, hf_perfmon_pdu_pkttype, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    gint type = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree *type_tree = proto_item_add_subtree(type_item, ett_perfmon);
    switch (type) {
        case GPMON_PKTTYPE_QLOG:
            // only from dispatcher
            proto_tree_add_item(type_tree, hf_perfmon_pdu_tmid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(type_tree, hf_perfmon_pdu_ssid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(type_tree, hf_perfmon_pdu_ccnt, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case GPMON_PKTTYPE_QEXEC:
            proto_tree_add_item(type_tree, hf_perfmon_pdu_tmid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(type_tree, hf_perfmon_pdu_ssid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(type_tree, hf_perfmon_pdu_ccnt, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(type_tree, hf_perfmon_pdu_segid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2 + 2;
            proto_tree_add_item(type_tree, hf_perfmon_pdu_pid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(type_tree, hf_perfmon_pdu_nid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2 + 2;

            //_name
            offset += 64;
            // status
            proto_tree_add_item(type_tree, hf_perfmon_pdu_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1 + 3 + 4;
            // cpu elapsed 
            offset += 8;

            // opened file descriptors
            offset += 4;
            // cpu usage
            offset += 4;
            // memory
            offset += 3 * 8;
            //rowsout
            proto_tree_add_item(type_tree, hf_perfmon_pdu_rowsout, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            //rowsin
            proto_tree_add_item(type_tree, hf_perfmon_pdu_rowsin, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            break;
        case GPMON_PKTTYPE_SEGINFO:
            //dbid
            proto_tree_add_item(type_tree, hf_perfmon_pdu_dbid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4 + 4;
            //hostname
            offset += 64;
            //memory used
            proto_tree_add_item(type_tree, hf_perfmon_pdu_memory_used, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            //memory available
            proto_tree_add_item(type_tree, hf_perfmon_pdu_memory_available, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            break;
    }

    return tvb_captured_length(tvb);
}

void
proto_register_perfmon(void)
{
    static hf_register_info hf[] = {
        { &hf_perfmon_pdu_magic,
            { "magic", "gpperfmon.magic",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_perfmon_pdu_version,
            { "version", "gpperfmon.version",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_perfmon_pdu_pkttype,
            { "packet type", "gpperfmon.pkttype",
            FT_UINT16, BASE_HEX,
            VALS(packettypenames), 0x0,
            NULL, HFILL }
        },
        { &hf_perfmon_pdu_tmid,
            { "tmid", "gpperfmon.qexec.tmid",
            FT_INT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_perfmon_pdu_ssid,
            { "ssid", "gpperfmon.qexec.ssid",
            FT_INT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_perfmon_pdu_ccnt,
            { "ccnt", "gpperfmon.qexec.ccnt",
            FT_INT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_perfmon_pdu_segid,
            { "content", "gpperfmon.qexec.segid",
            FT_INT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_perfmon_pdu_dbid,
            { "dbid", "gpperfmon.seginfo.dbid",
            FT_INT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_perfmon_pdu_pid,
            { "pid", "gpperfmon.qexec.pid",
            FT_INT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_perfmon_pdu_nid,
            { "node id", "gpperfmon.qexec.nid",
            FT_INT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_perfmon_pdu_rowsout,
            { "rows out", "gpperfmon.qexec.rowsout",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_perfmon_pdu_rowsin,
            { "rows in", "gpperfmon.qexec.rowsin",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_perfmon_pdu_status,
            { "node status", "gpperfmon.qexec.status",
            FT_UINT8, BASE_DEC,
            VALS(node_statuses), 0x0,
            NULL, HFILL }
        },
        { &hf_perfmon_pdu_memory_used,
            { "memory used", "gpperfmon.seginfo.memused",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_perfmon_pdu_memory_available,
            { "memory available", "gpperfmon.seginfo.memavailable",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_perfmon
    };

    proto_perfmon = proto_register_protocol (
        "Greenplum Perfmon Protocol", /* name        */
        "gpperfmon",          /* short name  */
        "gpperfmon"           /* filter_name */
        );

    proto_register_field_array(proto_perfmon, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_perfmon(void)
{
    static dissector_handle_t perfmon_handle;

    perfmon_handle = create_dissector_handle(dissect_perfmon, proto_perfmon);
    dissector_add_uint("udp.port", PERFMON_PORT, perfmon_handle);
}
