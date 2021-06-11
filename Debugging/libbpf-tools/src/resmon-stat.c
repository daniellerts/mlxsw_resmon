#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <json-c/linkhash.h>

#include "resmon.h"

static void resmon_stat_entry_free(struct lh_entry *e)
{
	if (!e->k_is_constant)
		free((void *) e->k);
	free((void *) e->v);
}

static uint64_t resmon_stat_fnv_1(const uint8_t *buf, size_t len)
{
	uint64_t hash = 0xcbf29ce484222325ULL;
	for (size_t i = 0; i < len; i++) {
		hash = hash * 0x100000001b3ULL;
		hash = hash ^ buf[i];
	}
	return hash;
}

struct resmon_stat_key
{
};

static struct resmon_stat_key *
resmon_stat_key_copy(const struct resmon_stat_key *key, size_t size)
{
	struct resmon_stat_key *copy = malloc(size);
	if (copy == NULL)
		return NULL;

	memcpy(copy, key, size);
	return copy;
}

struct resmon_stat_ralue_key
{
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

struct resmon_stat
{
	int64_t counters[resmon_counter_count];
	struct lh_table *ralue;
};

static struct resmon_stat_kvd_alloc *
resmon_stat_kvd_alloc_copy(struct resmon_stat_kvd_alloc kvda)
{
	struct resmon_stat_kvd_alloc *copy = malloc(sizeof *copy);
	if (copy == NULL)
		return NULL;

	*copy = kvda;
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

	*stat = (struct resmon_stat){
		.ralue = ralue_tab,
	};
	return stat;

free_stat:
	free(stat);
	return NULL;
}

void resmon_stat_destroy(struct resmon_stat *stat)
{
	lh_table_free(stat->ralue);
	free(stat);
}

static void resmon_stat_counter_inc(struct resmon_stat *stat,
				    struct resmon_stat_kvd_alloc kvda)
{
	stat->counters[kvda.counter] += kvda.slots;
}

static void resmon_stat_counter_dec(struct resmon_stat *stat,
				    struct resmon_stat_kvd_alloc kvda)
{
	stat->counters[kvda.counter] -= kvda.slots;
}

static int resmon_stat_lh_update(struct resmon_stat *stat,
				 struct lh_table *tab,
				 const struct resmon_stat_key *orig_key,
				 size_t orig_key_size,
				 struct resmon_stat_kvd_alloc orig_kvda)
{
	long hash = tab->hash_fn(orig_key);
	struct lh_entry *e = lh_table_lookup_entry_w_hash(tab, orig_key, hash);
	if (e != NULL)
		return 0;

	struct resmon_stat_key *key =
		resmon_stat_key_copy(orig_key, orig_key_size);
	if (key == NULL)
		return -ENOMEM;

	struct resmon_stat_kvd_alloc *kvda =
		resmon_stat_kvd_alloc_copy(orig_kvda);
	if (kvda == NULL)
		goto free_key;

	int rc = lh_table_insert_w_hash(tab, key, kvda, hash, 0);
	if (rc)
		goto free_kvda;

	resmon_stat_counter_inc(stat, *kvda);
	return 0;

free_kvda:
	free(kvda);
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
	struct resmon_stat_kvd_alloc kvda = *vp;
	int rc = lh_table_delete_entry(tab, e);
	assert(rc == 0);

	resmon_stat_counter_dec(stat, kvda);
	return 0;
}

int resmon_stat_ralue_update(struct resmon_stat *stat,
			     uint8_t protocol,
			     uint8_t prefix_len,
			     uint16_t virtual_router,
			     struct resmon_stat_dip dip,
			     struct resmon_stat_kvd_alloc kvda)
{
	struct resmon_stat_ralue_key key = {
		.protocol = protocol,
		.prefix_len = prefix_len,
		.virtual_router = virtual_router,
		.dip = dip,
	};

	return resmon_stat_lh_update(stat, stat->ralue,
				     &key.super, sizeof key, kvda);
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
