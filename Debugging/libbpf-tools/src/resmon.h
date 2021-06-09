/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef RESMON_H
#define RESMON_H

#include <stdbool.h>
#include <unistd.h>
#include <sys/un.h>

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

int resmon_jrpc_object_take_add(struct json_object *obj,
				const char *key, struct json_object *val_obj);

int resmon_jrpc_take_send(struct resmon_sock *sock, struct json_object *obj);

/* resmon-c.c */

int resmon_c_ping(void);
int resmon_c_stop(void);

/* resmon-d.c */

int resmon_d_start(void);

#endif /* RESMON_H */
