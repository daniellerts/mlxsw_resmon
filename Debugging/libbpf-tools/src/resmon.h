/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef RESMON_H
#define RESMON_H

#define RESMON_COUNTER_EXPAND_AS_ENUM(NAME, DESCRIPTION) \
	RESMON_COUNTER_ ## NAME,
#define RESMON_COUNTER_EXPAND_AS_DESC(NAME, DESCRIPTION) \
	DESCRIPTION,
#define EXPAND_AS_PLUS1(...) \
	+ 1

#define RESMON_COUNTERS(X) \
	X(LPM_IPV4, "IPv4 LPM") \
	X(LPM_IPV6, "IPv6 LPM") \
	X(ATCAM, "ATCAM") \
	X(ACTSET, "ACL Action Set")

enum resmon_counter {
	RESMON_COUNTERS(RESMON_COUNTER_EXPAND_AS_ENUM)
};
enum { resmon_counter_count = 0 RESMON_COUNTERS(EXPAND_AS_PLUS1) };

struct kvd_allocation {
	unsigned int slots;
	enum resmon_counter counter;
};

struct ralue_key {
	__u8 protocol;
	__u8 prefix_len;
	__u16 virtual_router;
	__u8 dip[16];
};

struct ptar_key {
	__u8 tcam_region_info[16];
};

struct ptce3_key {
	__u8 tcam_region_info[16];
	__u8 flex2_key_blocks[96];
	__u8 delta_mask;
	__u8 delta_value;
	__u16 delta_start;
	__u8 erp_id;
};

struct kvdl_key {
	__u32 index;
};

#endif /* RESMON_H */
