/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef RESMON_BPF_H
#define RESMON_BPF_H

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

struct kvdl_key {
	uint32_t index;
};

#endif /* RESMON_BPF_H */
