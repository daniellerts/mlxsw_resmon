#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <tuple>
#include <map>

extern "C" {
#include "resmon.h"
#include "resmon-bpf.h"
}

struct resmon_ht_ralue_key
{
	uint8_t protocol;
	uint8_t prefix_len;
	uint16_t virtual_router;
	std::array<uint8_t, 16> dip;

	bool operator<(resmon_ht_ralue_key const &that) const
	{
		return std::memcmp(this, &that, sizeof *this) < 0;
	}
};

struct resmon_ht
{
	std::map<resmon_ht_ralue_key, resmon_ht_kvd_alloc> ralue;
};

extern "C" resmon_ht *resmon_ht_create()
{
	auto ht = std::make_unique<resmon_ht>();
	return ht.release();
}

extern "C" void resmon_ht_destroy(resmon_ht *unmanaged)
{
	std::unique_ptr<resmon_ht> ht {unmanaged};
}

extern "C" void resmon_ht_ralue_update(resmon_ht *ht,
				       uint8_t protocol,
				       uint8_t prefix_len,
				       uint16_t virtual_router,
				       uint8_t _dip[16],
				       struct resmon_ht_kvd_alloc kvda)
{
	struct resmon_ht_ralue_key key = {
		protocol, prefix_len, virtual_router,
	};
	std::copy_n(_dip, 16, key.dip.begin());

	if (auto it = ht->ralue.find(key); it == ht->ralue.end()) {
		ht->ralue.insert(it, std::make_pair(key, kvda));
		// xxx counter
	}
}
