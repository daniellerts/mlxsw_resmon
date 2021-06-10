// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "resmon-bpf.h"
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

struct reg_ptar {
	u8 __op_e;
	u8 action_set_type;
	u8 resv1;
	u8 key_type;

#define reg_ptar_op(reg) ((reg).__op_e >> 4)

	__be16 resv2;
	__be16 __region_size;

	__be16 resv3;
	__be16 __region_id;

	__be16 resv4;
	u8 __dup_opt;
	u8 __packet_rate;

	u8 tcam_region_info[16];
	u8 flexible_keys[16];
};

struct reg_ptce3 {
	u8 __v_a;
	u8 __op;
	u8 resv1;
	u8 __dup;

#define reg_ptce3_v(reg) ((reg).__v_a >> 7)
#define reg_ptce3_op(reg) (((reg).__op >> 4) & 7)

	__be32 __priority;

	__be32 resv2;

	__be32 resv3;

	u8 tcam_region_info[16];

	u8 flex2_key_blocks[96];

	__be16 resv4;
	u8 resv5;
	u8 __erp_id;

#define reg_ptce3_erp_id(reg) ((reg).__erp_id & 0xf)

	__be16 resv6;
	__be16 __delta_start;

#define reg_ptce3_delta_start(reg) (bpf_ntohs((reg).__delta_start) & 0x3ff)

	u8 resv7;
	u8 delta_mask;
	u8 resv8;
	u8 delta_value;
};

struct reg_pefa {
	__be32 __pind_index;

#define reg_pefa_index(reg) (bpf_ntohl((reg).__pind_index) & 0xffffff)
};

struct reg_iedr_record {
	u8 type;
	u8 resv1;
	__be16 __size;

#define reg_iedr_record_size(rec) (bpf_ntohs((rec).__size))

	__be32 __index_start;

#define reg_iedr_record_index_start(rec) \
	(bpf_ntohl((rec).__index_start) & 0xffffff)
};

struct reg_iedr {
	u8 __bg;
	u8 resv1;
	u8 resv2;
	u8 num_rec;

	__be32 resv3;

	__be32 resv4;

	__be32 resv5;

	struct reg_iedr_record record[64];
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
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 102400/*xxx*/);
	__type(key, struct ptar_key);
	__type(value, struct kvd_allocation);
} ptar SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 102400/*xxx*/);
	__type(key, struct ptce3_key);
	__type(value, struct kvd_allocation);
} ptce3 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 102400/*xxx*/);
	__type(key, struct kvdl_key);
	__type(value, struct kvd_allocation);
} kvdl SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, resmon_counter_count);
	__type(key, u32);
	__type(value, s64);
} counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} ringbuf SEC(".maps");

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

static int handle_ptar_alloc(struct reg_ptar *reg, struct ptar_key *hkey)
{
	/* This needs to be volatile to prevent some odd interaction
	 * between the compiler and verifier. The latter rejects the
	 * program otherwise. */
	volatile unsigned int nkeys = 0;
	for (unsigned int i = 0; i < sizeof reg->flexible_keys; i++)
		if (reg->flexible_keys[i])
			nkeys++;

	struct kvd_allocation kvda = {
		.slots = nkeys >= 12 ? 4 :
			 nkeys >= 4  ? 2 : 1,
		.counter = RESMON_COUNTER_ATCAM,
	};

	bpf_map_update_elem(&ptar, hkey, &kvda, BPF_NOEXIST);
	return 0;
}

static int handle_ptar_free(struct ptar_key *hkey)
{
	bpf_map_delete_elem(&ptar, hkey);
	return 0;
}

static int handle_ptar(const u8 *payload)
{
	struct reg_ptar reg;
	bpf_core_read(&reg, sizeof reg, payload);

	switch (reg.key_type) {
	case MLXSW_REG_PTAR_KEY_TYPE_FLEX:
	case MLXSW_REG_PTAR_KEY_TYPE_FLEX2:
		break;
	default:
		return 0;
	}

	struct ptar_key hkey;
	__builtin_memcpy(hkey.tcam_region_info, reg.tcam_region_info,
			 sizeof reg.tcam_region_info);

	switch (reg_ptar_op(reg)) {
		int rc;
	case MLXSW_REG_PTAR_OP_RESIZE:
	case MLXSW_REG_PTAR_OP_TEST:
		return 0;
	case MLXSW_REG_PTAR_OP_ALLOC:
		return handle_ptar_alloc(&reg, &hkey);
	case MLXSW_REG_PTAR_OP_FREE:
		return handle_ptar_free(&hkey);
	}

	return 0;
}

static int handle_ptce3_alloc(const struct ptce3_key *hkey)
{
	struct ptar_key ptar_key;
	__builtin_memcpy(ptar_key.tcam_region_info, hkey->tcam_region_info,
			 sizeof ptar_key.tcam_region_info);

	struct kvd_allocation *kvda = bpf_map_lookup_elem(&ptar, &ptar_key);
	if (!kvda)
		return 0;

	int rc = bpf_map_update_elem(&ptce3, hkey, kvda, BPF_NOEXIST);
	if (!rc)
		counter_inc(kvda);

	return 0;
}

static int handle_ptce3_free(const struct ptce3_key *hkey)
{
	struct kvd_allocation *kvda = bpf_map_lookup_elem(&ptce3, hkey);
	if (!kvda)
		return 0;

	bpf_map_delete_elem(&ptce3, hkey);
	counter_dec(kvda);
	return 0;
}

static int handle_ptce3(const u8 *payload)
{
	struct reg_ptce3 reg;
	bpf_core_read(&reg, sizeof reg, payload);

	switch (reg_ptce3_op(reg)) {
	case MLXSW_REG_PTCE3_OP_WRITE_WRITE:
	case MLXSW_REG_PTCE3_OP_WRITE_UPDATE:
		break;
	default:
		return 0;
	}

	struct ptce3_key hkey = {
		.erp_id = reg_ptce3_erp_id(reg),
		.delta_start = reg_ptce3_delta_start(reg),
		.delta_mask = reg.delta_mask,
		.delta_value = reg.delta_value,
	};
	__builtin_memcpy(hkey.tcam_region_info, reg.tcam_region_info,
			 sizeof reg.tcam_region_info);
	__builtin_memcpy(hkey.flex2_key_blocks, reg.flex2_key_blocks,
			 sizeof reg.flex2_key_blocks);

	if (reg_ptce3_v(reg))
		return handle_ptce3_alloc(&hkey);
	else
		return handle_ptce3_free(&hkey);
}

static int handle_kvdl_alloc(struct kvdl_key *hkey, struct kvd_allocation *kvda)
{
	int rc = bpf_map_update_elem(&kvdl, hkey, kvda, BPF_NOEXIST);
	if (!rc)
		counter_inc(kvda);
	return 0;
}

static void handle_kvdl_free_1(u32 index, enum resmon_counter counter)
{
	struct kvdl_key hkey = {
		.index = index,
	};
	struct kvd_allocation *kvda = bpf_map_lookup_elem(&kvdl, &hkey);

	/* Ignore mismatched deallocations. */
	if (kvda && kvda->counter == counter) {
		bpf_map_delete_elem(&kvdl, &hkey);
		counter_dec(kvda);
	}
}

static void handle_kvdl_free_1000(u32 index, enum resmon_counter counter)
{
	/* IEDR size is encoded in a 12-bit field, so the size is at
	 * most 4095. */
	for (u32 i = 0; i < 1000; i++)
		handle_kvdl_free_1(index++, counter);
}

static void handle_kvdl_free(u32 index, enum resmon_counter counter, u32 size)
{
	/* The size could be any value 1..4095. However a loop like this:
	 *
	 *     for (u32 i = 0; i < 4095; i++) {
	 *       if (i >= size) break;
	 *       // more stuff
	 *     }
	 *
	 * ... gets rejected by the BPF verifier. Now without the extra
	 * (i >= size) condition it does pass. So we need to hard-code
	 * sizes that mlxsw is known to use, so that we do not need to
	 * actually guard the loop like this.
	 */
	if (size == 1)
		handle_kvdl_free_1(index, counter);
	else if (size == 1000)
		handle_kvdl_free_1000(index, counter);
}

static int handle_pefa(const u8 *payload)
{
	struct reg_pefa reg;
	bpf_core_read(&reg, sizeof reg, payload);

	struct kvdl_key hkey = {
		.index = reg_pefa_index(reg),
	};
	struct kvd_allocation kvda = {
		.slots = 1,
		.counter = RESMON_COUNTER_ACTSET,
	};
	return handle_kvdl_alloc(&hkey, &kvda);
}

static int handle_iedr_record(struct reg_iedr_record *rec)
{
	enum resmon_counter counter;

	switch (rec->type) {
	case 0x23:
		counter = RESMON_COUNTER_ACTSET;
		break;
	default:
		return 0;
	}

	u32 index = reg_iedr_record_index_start(*rec);
	u32 size = reg_iedr_record_size(*rec);

	handle_kvdl_free(index, counter, size);
	return 0;
}

static unsigned char reg_iedr[sizeof(struct reg_iedr)] __attribute__((aligned(4)));
static int handle_iedr(const u8 *payload)
{
	struct reg_iedr *reg = (struct reg_iedr *) reg_iedr;
	bpf_core_read(reg, sizeof *reg, payload);

	/* Nominally there are 64 records, but if we parse them all in a
	 * loop, the validator will not be able to process the large-sized
	 * ones, which involve more looping. In practice, mlxsw only ever
	 * issues single-record IEDR, so just assume that's the case here. */
	if (reg->num_rec != 1) {
		// xxx warn
		return 0;
	}

	return handle_iedr_record(&reg->record[0]);
}

static int push_to_ringbuf(const u8 *buf, size_t len)
{
	/*
#define MLXSW_REG_RALUE_LEN 0x38
#define MLXSW_REG_PTAR_LEN 0x30
#define MLXSW_REG_PTCE3_LEN 0xF0
#define MLXSW_REG_PEFA_LEN 0xB0
#define MLXSW_REG_IEDR_LEN 0x210
	*/

	if (len > 1024)
		return 0;

	u8 *space = bpf_ringbuf_reserve(&ringbuf, 1024, 0);
	if (!space)
		return 0;

	bpf_core_read(space, len, buf);
	bpf_ringbuf_submit(space, 0);

	const char fmt[] = "bublanina";
	bpf_trace_printk(fmt, sizeof fmt);

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

	switch (bpf_ntohs(op_tlv.reg_id)) {
	case 0x8013: /* MLXSW_REG_RALUE_ID */
	case 0x3006: /* MLXSW_REG_PTAR_ID */
	case 0x3027: /* MLXSW_REG_PTCE3_ID */
	case 0x300F: /* MLXSW_REG_PEFA_ID */
	case 0x3804: /* MLXSW_REG_IEDR_ID */
		return push_to_ringbuf(buf, len);
	};

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
	case 0x3006: /* MLXSW_REG_PTAR_ID */
		return handle_ptar(buf);
	case 0x3027: /* MLXSW_REG_PTCE3_ID */
		return handle_ptce3(buf);
	case 0x300F: /* MLXSW_REG_PEFA_ID */
		return handle_pefa(buf);
	case 0x3804: /* MLXSW_REG_IEDR_ID */
		return handle_iedr(buf);
	}

	return 0;

}

char LICENSE[] SEC("license") = "GPL";
