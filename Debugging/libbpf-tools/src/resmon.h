/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef RESMON_H
#define RESMON_H

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/un.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define RESMON_COUNTER_EXPAND_AS_ENUM(NAME, DESCRIPTION) \
	RESMON_COUNTER_ ## NAME,
#define RESMON_COUNTER_EXPAND_AS_DESC(NAME, DESCRIPTION) \
	DESCRIPTION,
#define EXPAND_AS_PLUS1(...) + 1

#define RESMON_COUNTERS(X) \
	X(LPM_IPV4, "IPv4 LPM") \
	X(LPM_IPV6, "IPv6 LPM") \
	X(ATCAM, "ATCAM") \
	X(ACTSET, "ACL Action Set")

enum resmon_counter {
	RESMON_COUNTERS(RESMON_COUNTER_EXPAND_AS_ENUM)
};

enum { resmon_counter_count = 0 RESMON_COUNTERS(EXPAND_AS_PLUS1) };

/* resmon.c */

extern struct resmon_env {
	int verbosity;
	const char *bpffs;
} env;

/* resmon-sock.c */

struct resmon_sock {
	int fd;
	struct sockaddr_un sa;
	socklen_t len;
};

int resmon_sock_open_d(struct resmon_sock *ctl);
void resmon_sock_close_d(struct resmon_sock *ctl);
int resmon_sock_open_c(struct resmon_sock *cli,
		       struct resmon_sock *peer);
void resmon_sock_close_c(struct resmon_sock *cli);

int resmon_sock_recv(struct resmon_sock *sock,
		     struct resmon_sock *peer,
		     char **bufp);

/* resmon-jrpc.c */

struct json_object *resmon_jrpc_new_object(struct json_object *id);
struct json_object *resmon_jrpc_new_request(int id, const char *method);
struct json_object *resmon_jrpc_new_error(struct json_object *id,
					  int code,
					  const char *message,
					  const char *data);

int resmon_jrpc_dissect_request(struct json_object *obj,
				struct json_object **id,
				const char **method,
				struct json_object **params,
				char **error);
int resmon_jrpc_dissect_response(struct json_object *obj,
				 struct json_object **id,
				 struct json_object **result,
				 bool *is_error,
				 char **error);
int resmon_jrpc_dissect_error(struct json_object *obj,
			      int64_t *code,
			      const char **message,
			      struct json_object **data,
			      char **error);
int resmon_jrpc_dissect_params_empty(struct json_object *obj,
				     char **error);
int resmon_jrpc_dissect_params_emad(struct json_object *obj,
				    const char **payload,
				    size_t *payload_len,
				    char **error);

int resmon_jrpc_object_take_add(struct json_object *obj,
				const char *key, struct json_object *val_obj);

int resmon_jrpc_take_send(struct resmon_sock *sock, struct json_object *obj);

/* resmon-c.c */

int resmon_c_ping(void);
int resmon_c_stop(void);

/* resmon-d.c */

int resmon_d_start(void);

/* resmon-stat.c */

struct resmon_stat;

struct resmon_stat_counters {
	int64_t values[resmon_counter_count];
};

struct resmon_stat_dip {
	uint8_t dip[16];
};

struct resmon_stat_kvd_alloc {
	unsigned int slots;
	enum resmon_counter counter;
};

struct resmon_stat *resmon_stat_create(void);
void resmon_stat_destroy(struct resmon_stat *stat);
struct resmon_stat_counters resmon_stat_counters(struct resmon_stat *stat);

int resmon_stat_ralue_update(struct resmon_stat *stat,
			     uint8_t protocol,
			     uint8_t prefix_len,
			     uint16_t virtual_router,
			     struct resmon_stat_dip dip,
			     struct resmon_stat_kvd_alloc kvda);
int resmon_stat_ralue_delete(struct resmon_stat *stat,
			     uint8_t protocol,
			     uint8_t prefix_len,
			     uint16_t virtual_router,
			     struct resmon_stat_dip dip);

/* resmon-reg.c */

enum resmon_reg_process_result {
	resmon_reg_process_ok,
	resmon_reg_process_no_register,
	resmon_reg_process_unknown_register,
	resmon_reg_process_insert_failed,
	resmon_reg_process_delete_failed,
};
enum resmon_reg_process_result resmon_reg_process_emad(struct resmon_stat *stat,
						       const uint8_t *buf,
						       size_t len);

#endif /* RESMON_H */
