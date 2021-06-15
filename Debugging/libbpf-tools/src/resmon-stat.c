#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <json-c/linkhash.h>

#include "resmon.h"

static void resmon_stat_entry_free(struct lh_entry *e)
{
	if (!e->k_is_constant)
		free(lh_entry_k(e));
	free(lh_entry_v(e));
}

static uint64_t resmon_stat_fnv_1(const void *ptr, size_t len)
{
	const uint8_t *buf = ptr;
	uint64_t hash = 0xcbf29ce484222325ULL;
	for (size_t i = 0; i < len; i++) {
		hash = hash * 0x100000001b3ULL;
		hash = hash ^ buf[i];
	}
	return hash;
}

struct resmon_stat_key {};

static struct resmon_stat_key *
resmon_stat_key_copy(const struct resmon_stat_key *key, size_t size)
{
	struct resmon_stat_key *copy = malloc(size);
	if (copy == NULL)
		return NULL;

	memcpy(copy, key, size);
	return copy;
}

struct resmon_stat_ralue_key {
	struct resmon_stat_key super;
	uint8_t protocol;
	uint8_t prefix_len;
	uint16_t virtual_router;
	struct resmon_stat_dip dip;
};

static unsigned long resmon_stat_ralue_hash(const void *k)
{
	return resmon_stat_fnv_1(k, sizeof(struct resmon_stat_ralue_key));
}

static int resmon_stat_ralue_eq(const void *k1, const void *k2)
{
	return memcmp(k1, k2, sizeof(struct resmon_stat_ralue_key)) == 0;
}

struct resmon_stat_ptar_key {
	struct resmon_stat_key super;
	struct resmon_stat_tcam_region_info tcam_region_info;
};

static unsigned long resmon_stat_ptar_hash(const void *k)
{
	return resmon_stat_fnv_1(k, sizeof(struct resmon_stat_ptar_key));
}

static int resmon_stat_ptar_eq(const void *k1, const void *k2)
{
	return memcmp(k1, k2, sizeof(struct resmon_stat_ptar_key)) == 0;
}

struct resmon_stat_ptce3_key {
	struct resmon_stat_key super;
	struct resmon_stat_tcam_region_info tcam_region_info;
	struct resmon_stat_flex2_key_blocks flex2_key_blocks;
	uint8_t delta_mask;
	uint8_t delta_value;
	uint16_t delta_start;
	uint8_t erp_id;
};

static unsigned long resmon_stat_ptce3_hash(const void *k)
{
	return resmon_stat_fnv_1(k, sizeof(struct resmon_stat_ptce3_key));
}

static int resmon_stat_ptce3_eq(const void *k1, const void *k2)
{
	return memcmp(k1, k2, sizeof(struct resmon_stat_ptce3_key)) == 0;
}

struct resmon_stat
{
	struct resmon_stat_counters counters;
	struct lh_table *ralue;
	struct lh_table *ptar;
	struct lh_table *ptce3;
};

static struct resmon_stat_kvd_alloc *
resmon_stat_kvd_alloc_copy(struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_kvd_alloc *copy = malloc(sizeof *copy);
	if (copy == NULL)
		return NULL;

	*copy = kvd_alloc;
	return copy;
}

struct resmon_stat *resmon_stat_create(void)
{
	struct resmon_stat *stat = malloc(sizeof *stat);
	if (stat == NULL)
		return NULL;

	struct lh_table *ralue_tab = lh_table_new(1, resmon_stat_entry_free,
						  resmon_stat_ralue_hash,
						  resmon_stat_ralue_eq);
	if (ralue_tab == NULL)
		goto free_stat;

	struct lh_table *ptar_tab = lh_table_new(1, resmon_stat_entry_free,
						 resmon_stat_ptar_hash,
						 resmon_stat_ptar_eq);
	if (ptar_tab == NULL)
		goto free_ralue_tab;

	struct lh_table *ptce3_tab = lh_table_new(1, resmon_stat_entry_free,
						  resmon_stat_ptce3_hash,
						  resmon_stat_ptce3_eq);
	if (ptce3_tab == NULL)
		goto free_ptar_tab;

	*stat = (struct resmon_stat){
		.ralue = ralue_tab,
		.ptar = ptar_tab,
		.ptce3 = ptce3_tab,
	};
	return stat;

free_ptar_tab:
	lh_table_free(ptar_tab);
free_ralue_tab:
	lh_table_free(ralue_tab);
free_stat:
	free(stat);
	return NULL;
}

void resmon_stat_destroy(struct resmon_stat *stat)
{
	lh_table_free(stat->ptce3);
	lh_table_free(stat->ptar);
	lh_table_free(stat->ralue);
	free(stat);
}

struct resmon_stat_counters resmon_stat_counters(struct resmon_stat *stat)
{
	return stat->counters;
}

static void resmon_stat_counter_inc(struct resmon_stat *stat,
				    struct resmon_stat_kvd_alloc kvd_alloc)
{
	stat->counters.values[kvd_alloc.counter] += kvd_alloc.slots;
}

static void resmon_stat_counter_dec(struct resmon_stat *stat,
				    struct resmon_stat_kvd_alloc kvd_alloc)
{
	stat->counters.values[kvd_alloc.counter] -= kvd_alloc.slots;
}

static int resmon_stat_lh_get(struct lh_table *tab,
			      const struct resmon_stat_key *orig_key,
			      struct resmon_stat_kvd_alloc *ret_kvd_alloc)
{
	long hash = tab->hash_fn(orig_key);
	struct lh_entry *e = lh_table_lookup_entry_w_hash(tab, orig_key, hash);
	if (e == NULL)
		return -1;

	const struct resmon_stat_kvd_alloc *kvd_alloc = e->v;
	*ret_kvd_alloc = *kvd_alloc;
	return 0;
}

static int resmon_stat_lh_update(struct resmon_stat *stat,
				 struct lh_table *tab,
				 const struct resmon_stat_key *orig_key,
				 size_t orig_key_size,
				 struct resmon_stat_kvd_alloc orig_kvd_alloc)
{
	long hash = tab->hash_fn(orig_key);
	struct lh_entry *e = lh_table_lookup_entry_w_hash(tab, orig_key, hash);
	if (e != NULL)
		return 0;

	struct resmon_stat_key *key =
		resmon_stat_key_copy(orig_key, orig_key_size);
	if (key == NULL)
		return -ENOMEM;

	struct resmon_stat_kvd_alloc *kvd_alloc =
		resmon_stat_kvd_alloc_copy(orig_kvd_alloc);
	if (kvd_alloc == NULL)
		goto free_key;

	int rc = lh_table_insert_w_hash(tab, key, kvd_alloc, hash, 0);
	if (rc)
		goto free_kvd_alloc;

	resmon_stat_counter_inc(stat, *kvd_alloc);
	return 0;

free_kvd_alloc:
	free(kvd_alloc);
free_key:
	free(key);
	return -1;
}

static int resmon_stat_lh_delete(struct resmon_stat *stat,
				 struct lh_table *tab,
				 const struct resmon_stat_key *orig_key)
{
	long hash = tab->hash_fn(orig_key);
	struct lh_entry *e = lh_table_lookup_entry_w_hash(tab, orig_key, hash);
	if (e == NULL)
		return -1;

	const struct resmon_stat_kvd_alloc *vp = e->v;
	struct resmon_stat_kvd_alloc kvd_alloc = *vp;
	int rc = lh_table_delete_entry(tab, e);
	assert(rc == 0);

	resmon_stat_counter_dec(stat, kvd_alloc);
	return 0;
}

int resmon_stat_ralue_update(struct resmon_stat *stat,
			     uint8_t protocol,
			     uint8_t prefix_len,
			     uint16_t virtual_router,
			     struct resmon_stat_dip dip,
			     struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_ralue_key key = {
		.protocol = protocol,
		.prefix_len = prefix_len,
		.virtual_router = virtual_router,
		.dip = dip,
	};
	return resmon_stat_lh_update(stat, stat->ralue,
				     &key.super, sizeof key, kvd_alloc);
}

int resmon_stat_ralue_delete(struct resmon_stat *stat,
			     uint8_t protocol,
			     uint8_t prefix_len,
			     uint16_t virtual_router,
			     struct resmon_stat_dip dip)
{
	struct resmon_stat_ralue_key key = {
		.protocol = protocol,
		.prefix_len = prefix_len,
		.virtual_router = virtual_router,
		.dip = dip,
	};
	return resmon_stat_lh_delete(stat, stat->ralue, &key.super);
}

int resmon_stat_ptar_alloc(struct resmon_stat *stat,
			   struct resmon_stat_tcam_region_info tcam_region_info,
			   struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_ptar_key key = {
		.tcam_region_info = tcam_region_info,
	};
	return resmon_stat_lh_update(stat, stat->ptar,
				     &key.super, sizeof key, kvd_alloc);
}

int resmon_stat_ptar_free(struct resmon_stat *stat,
			  struct resmon_stat_tcam_region_info tcam_region_info)
{
	struct resmon_stat_ptar_key key = {
		.tcam_region_info = tcam_region_info,
	};
	return resmon_stat_lh_delete(stat, stat->ptar, &key.super);
}

int resmon_stat_ptar_get(struct resmon_stat *stat,
			 struct resmon_stat_tcam_region_info tcam_region_info,
			 struct resmon_stat_kvd_alloc *ret_kvd_alloc)
{
	struct resmon_stat_ptar_key key = {
		.tcam_region_info = tcam_region_info,
	};
	return resmon_stat_lh_get(stat->ptar, &key.super, ret_kvd_alloc);
}

int
resmon_stat_ptce3_alloc(struct resmon_stat *stat,
			struct resmon_stat_tcam_region_info tcam_region_info,
			const struct resmon_stat_flex2_key_blocks *key_blocks,
			uint8_t delta_mask,
			uint8_t delta_value,
			uint16_t delta_start,
			uint8_t erp_id,
			struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_ptce3_key key = {
		.tcam_region_info = tcam_region_info,
		.flex2_key_blocks = *key_blocks,
		.delta_mask = delta_mask,
		.delta_value = delta_value,
		.delta_start = delta_start,
		.erp_id = erp_id,
	};
	return resmon_stat_lh_update(stat, stat->ptce3,
				     &key.super, sizeof key, kvd_alloc);
}

int
resmon_stat_ptce3_free(struct resmon_stat *stat,
		       struct resmon_stat_tcam_region_info tcam_region_info,
		       const struct resmon_stat_flex2_key_blocks *key_blocks,
		       uint8_t delta_mask,
		       uint8_t delta_value,
		       uint16_t delta_start,
		       uint8_t erp_id)
{
	struct resmon_stat_ptce3_key key = {
		.tcam_region_info = tcam_region_info,
		.flex2_key_blocks = *key_blocks,
		.delta_mask = delta_mask,
		.delta_value = delta_value,
		.delta_start = delta_start,
		.erp_id = erp_id,
	};
	return resmon_stat_lh_delete(stat, stat->ptce3, &key.super);
}
