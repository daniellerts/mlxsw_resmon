// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "resmon.h"
#include "bits.bpf.h"

#define EMAD_ETH_HDR_LEN		0x10
#define EMAD_OP_TLV_LEN			0x10
#define EMAD_OP_TLV_METHOD_MASK		0x7F
#define EMAD_OP_TLV_STATUS_MASK		0x7F

enum {
	EMAD_OP_TLV_METHOD_QUERY = 1,
	EMAD_OP_TLV_METHOD_WRITE = 2,
	EMAD_OP_TLV_METHOD_EVENT = 5,
};

struct emad_tlv_head {
	int type;
	int length;
};

struct emad_op_tlv {
	__be16 type_len_be;
	u8 status;
	u8 resv2;
	u16 reg_id;
	u8 r_method;
	u8 resv3;
	u64 tid;
};

struct emad_reg_tlv_head {
	__be16 type_len_be;
	u16 reserved;
};

struct reg_ralue {
	u8 __protocol;
	u8 __op;
	__be16 resv1;

#define reg_ralue_protocol(reg)	((reg).__protocol & 0x0f)
#define reg_ralue_op(reg) (((reg).__op & 0x70) >> 4)

	__be16 __virtual_router;
	__be16 resv2;

#define reg_ralue_virtual_router(reg) (bpf_ntohs((reg).__virtual_router))

	__be16 resv3;
	u8 resv4;
	u8 prefix_len;

	union {
		u8 dip6[16];
		struct {
			u8 resv5[12];
			u8 dip4[4];
		};
	};
};

static struct emad_tlv_head emad_tlv_decode_header(__be16 type_len_be)
{
	u16 type_len = bpf_ntohs(type_len_be);

	return (struct emad_tlv_head){
		.type = type_len >> 11,
		.length = type_len & 0x7ff,
	};
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024 * 1024);
	__type(key, struct ralue_key);
	__type(value, struct kvd_allocation);
} ralue SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, resmon_counter_count);
	__type(key, u32);
	__type(value, s64);
} counters SEC(".maps");

static void __counter_adj(enum resmon_counter counter, u64 d)
{
	u32 index = counter;
	u64 *value = bpf_map_lookup_elem(&counters, &counter);
	if (value)
		__sync_fetch_and_add(value, d);
}

static void counter_inc(struct kvd_allocation *kvda)
{
	return __counter_adj(kvda->counter, kvda->slots);
}

static void counter_dec(struct kvd_allocation *kvda)
{
	return __counter_adj(kvda->counter, (u64)-(s64)kvda->slots);
}

static int handle_ralue(const u8 *payload)
{
	struct reg_ralue reg;
	bpf_core_read(&reg, sizeof reg, payload);

	struct ralue_key hkey = {};
	hkey.protocol = reg_ralue_protocol(reg);
	hkey.prefix_len = reg.prefix_len;
	hkey.virtual_router = reg_ralue_virtual_router(reg);

	bool ipv6 = hkey.protocol == MLXSW_REG_RALXX_PROTOCOL_IPV6;
	if (ipv6)
		__builtin_memcpy(hkey.dip, reg.dip6, sizeof(reg.dip6));
	else
		__builtin_memcpy(hkey.dip, reg.dip4, sizeof(reg.dip4));

	enum resmon_counter counter = ipv6 ? RESMON_COUNTER_LPM_IPV6
					   : RESMON_COUNTER_LPM_IPV4;
	struct kvd_allocation kvda = {
		.slots = hkey.prefix_len <= 64 ? 1 : 2,
		.counter = counter,
	};

	switch (reg_ralue_op(reg)) {
		int rc;
	default:
		rc = bpf_map_update_elem(&ralue, &hkey, &kvda, BPF_NOEXIST);
		if (!rc)
			counter_inc(&kvda);
		break;
	case MLXSW_REG_RALUE_OP_WRITE_DELETE:
		rc = bpf_map_delete_elem(&ralue, &hkey);
		if (!rc)
			counter_dec(&kvda);
		break;
	}

	return 0;
}

inline bool is_mlxsw_spectrum(struct devlink *devlink)
{
	static const char mlxsw_spectrum[] = "mlxsw_spectrum";
	char name_buf[sizeof mlxsw_spectrum];

	{
		const char *drv_name = BPF_CORE_READ(devlink, dev, driver, name);
		bpf_core_read_str(&name_buf, sizeof(name_buf), drv_name);
	}

	for (unsigned int i = 0; i < sizeof name_buf; i++)
		if (name_buf[i] != mlxsw_spectrum[i])
			return false;

	return true;
}

SEC("raw_tracepoint/devlink_hwmsg")
int BPF_PROG(handle__devlink_hwmsg,
	     struct devlink *devlink, bool incoming, unsigned long type,
	     const u8 *buf, size_t len)
{
	struct emad_op_tlv op_tlv;
	struct emad_tlv_head tlv_head;
	struct emad_reg_tlv_head reg_tlv;

	if (!is_mlxsw_spectrum(devlink))
		return 0;
	if (!incoming)
		return 0;

	buf += EMAD_ETH_HDR_LEN;

	bpf_core_read(&op_tlv, sizeof op_tlv, buf);
	tlv_head = emad_tlv_decode_header(op_tlv.type_len_be);

	/* Filter out queries and events. Later on we can assume `op'
	 * fields in a register refer to a write. */
	if ((op_tlv.r_method & EMAD_OP_TLV_METHOD_MASK)
	    != EMAD_OP_TLV_METHOD_WRITE)
		return 0;

        /* Filter out errors. */
	if (op_tlv.status & EMAD_OP_TLV_STATUS_MASK)
		return 0;

	buf += tlv_head.length * 4;
	bpf_core_read(&reg_tlv, sizeof reg_tlv, buf);
	tlv_head = emad_tlv_decode_header(reg_tlv.type_len_be);

	/* Skip over the TLV if it is in fact a STRING TLV. */
	if (tlv_head.type == MLXSW_EMAD_TLV_TYPE_STRING) {
		buf += tlv_head.length * 4;
		bpf_core_read(&reg_tlv, sizeof reg_tlv, buf);
		tlv_head = emad_tlv_decode_header(reg_tlv.type_len_be);
	}

	if (tlv_head.type != MLXSW_EMAD_TLV_TYPE_REG)
		return 0;

	/* Get to the register payload. */
	buf += sizeof reg_tlv;

	switch (bpf_ntohs(op_tlv.reg_id)) {
	case 0x8013: /* MLXSW_REG_RALUE_ID */
		return handle_ralue(buf);
	}

	return 0;

}

char LICENSE[] SEC("license") = "GPL";
