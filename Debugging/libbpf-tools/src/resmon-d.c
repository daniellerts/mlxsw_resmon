// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>

#include "resmon.h"
#include "resmon.skel.h"
#include "trace_helpers.h"

static bool should_quit = false;

static void resmon_d_handle_signal(int sig)
{
	should_quit = true;
}

static int resmon_d_setup_signals(void)
{
	if (signal(SIGINT, resmon_d_handle_signal) == SIG_ERR) {
		fprintf(stderr, "Failed to set up SIGINT handling: %m\n");
		return -1;
	}
	if (signal(SIGQUIT, resmon_d_handle_signal) == SIG_ERR) {
		fprintf(stderr, "Failed to set up SIGQUIT handling: %m\n");
		return -1;
	}
	if (signal(SIGTERM, resmon_d_handle_signal) == SIG_ERR) {
		fprintf(stderr, "Failed to set up SIGTERM handling: %m\n");
		return -1;
	}
	return 0;
}

static int resmon_d_print_fn(enum libbpf_print_level level, const char *format,
			     va_list args)
{
	if ((int)level > env.verbosity)
		return 0;
	return vfprintf(stderr, format, args);
}

static void resmon_d_respond_error(struct resmon_sock *ctl,
				   struct json_object *id, int code,
				   const char *message, const char *data)
{
	resmon_jrpc_take_send(ctl,
		resmon_jrpc_new_error(id, code, message, data));
}

static void resmon_d_respond_invalid(struct resmon_sock *ctl, const char *data)
{
	resmon_jrpc_take_send(ctl,
		resmon_jrpc_new_error(NULL, -32600, "Invalid Request", data));
}

static void resmon_d_respond_method_nf(struct resmon_sock *peer,
				       struct json_object *id,
				       const char *method)
{
	resmon_jrpc_take_send(peer,
		resmon_jrpc_new_error(id, -32601, "Method not found", method));
}

static void resmon_d_respond_invalid_params(struct resmon_sock *ctl,
					    const char *data)
{
	resmon_jrpc_take_send(ctl,
		resmon_jrpc_new_error(NULL, -32602, "Invalid params", data));
}

static void resmon_d_respond_interr(struct resmon_sock *peer,
				    struct json_object *id,
				    const char *data)
{
	resmon_jrpc_take_send(peer,
		resmon_jrpc_new_error(id, -32603, "Internal error", data));
}

static void resmon_d_respond_memerr(struct resmon_sock *peer,
				    struct json_object *id)
{
	resmon_d_respond_interr(peer, id, "Memory allocation issue");
}

static void resmon_d_handle_echo(struct resmon_sock *peer,
				 struct json_object *params_obj,
				 struct json_object *id)
{
	struct json_object *obj = resmon_jrpc_new_object(id);
	if (obj == NULL)
		return;

	if (resmon_jrpc_object_take_add(obj, "result",
					json_object_get(params_obj)))
		goto put_obj;

	resmon_jrpc_take_send(peer, obj);
	return;

put_obj:
	json_object_put(obj);
	resmon_d_respond_memerr(peer, id);
}

static void resmon_d_handle_quit(struct resmon_sock *peer,
				 struct json_object *params_obj,
				 struct json_object *id)
{
	should_quit = true;

	char *error;
	int rc = resmon_jrpc_dissect_params_empty(params_obj, &error);
	if (rc) {
		resmon_d_respond_invalid_params(peer, error);
		free(error);
		return;
	}

	struct json_object *obj = resmon_jrpc_new_object(id);
	if (obj == NULL)
		return;

	if (resmon_jrpc_object_take_add(obj, "result",
					json_object_new_boolean(true)))
		goto put_obj;

	resmon_jrpc_take_send(peer, obj);
	return;

put_obj:
	json_object_put(obj);
	resmon_d_respond_memerr(peer, id);
}

static const char *resmon_d_counter_descriptions[] = {
	RESMON_COUNTERS(RESMON_COUNTER_EXPAND_AS_DESC)
};

static int resmon_d_stats_attach_counter(struct json_object *counters_obj,
					 enum resmon_counter counter,
					 int64_t value)
{
	int rc;
	struct json_object *counter_obj = json_object_new_object();
	if (counter_obj == NULL)
		return -1;

	rc = resmon_jrpc_object_take_add(counter_obj, "id",
					 json_object_new_int(counter));
	if (rc)
		goto put_counter_obj;

	const char *descr = resmon_d_counter_descriptions[counter];
	rc = resmon_jrpc_object_take_add(counter_obj, "descr",
					 json_object_new_string(descr));

	if (rc)
		goto put_counter_obj;

	rc = resmon_jrpc_object_take_add(counter_obj, "value",
					 json_object_new_int64(value));
	if (rc)
		goto put_counter_obj;

	rc = json_object_array_add(counters_obj, counter_obj);
	if (rc)
		goto put_counter_obj;

	return 0;

put_counter_obj:
	json_object_put(counter_obj);
	return -1;
}

static void resmon_d_handle_stats(struct resmon_stat *stat,
				  struct resmon_sock *peer,
				  struct json_object *params_obj,
				  struct json_object *id)
{
	/* The response is as follows:
	 *
	 * {
	 *     "id": ...,
	 *     "result": {
	 *         "counters": [
	 *             {
	 *                 "id": counter number as per enum resmon_counter,
	 *                 "description": string with human-readable descr.,
	 *                 "value": integer, value of the counter
	 *             },
	 *             ....
	 *         ]
	 *     }
	 * }
	 */

	char *error;
	int rc = resmon_jrpc_dissect_params_empty(params_obj, &error);
	if (rc) {
		resmon_d_respond_invalid_params(peer, error);
		free(error);
		return;
	}

	struct json_object *obj = resmon_jrpc_new_object(id);
	if (obj == NULL)
		return;

	struct json_object *result_obj = json_object_new_object();
	if (result_obj == NULL)
		goto put_obj;

	struct json_object *counters_obj = json_object_new_array();
	if (counters_obj == NULL)
		goto put_result_obj;

	struct resmon_stat_counters counters = resmon_stat_counters(stat);
	for (int i = 0; i < ARRAY_SIZE(counters.values); i++) {
		int rc = resmon_d_stats_attach_counter(counters_obj, i,
						       counters.values[i]);
		if (rc)
			goto put_counters_obj;
	}

	if (resmon_jrpc_object_take_add(result_obj, "counters",
					counters_obj))
		goto put_result_obj;

	if (resmon_jrpc_object_take_add(obj, "result",
					result_obj))
		goto put_obj;

	resmon_jrpc_take_send(peer, obj);
	return;

put_counters_obj:
	json_object_put(counters_obj);
put_result_obj:
	json_object_put(result_obj);
put_obj:
	json_object_put(obj);
	resmon_d_respond_memerr(peer, id);
}

static int resmon_d_emad_decode_payload(uint8_t *dec, const char *enc,
					size_t dec_len)
{
	for (size_t i = 0; i < dec_len; i++) {
		char buf[3] = {enc[2 * i], enc[2 * i + 1], '\0'};
		char *endptr = NULL;
		errno = 0;
		long int byte = strtol(buf, &endptr, 16);
		if (errno || *endptr != '\0')
			return -1;
		dec[i] = byte;
	}
	return 0;
}

static void resmon_d_handle_emad(struct resmon_stat *stat,
				 struct resmon_sock *peer,
				 struct json_object *params_obj,
				 struct json_object *id)
{
	int rc;

	const char *payload;
	size_t payload_len;
	char *error;
	rc = resmon_jrpc_dissect_params_emad(params_obj, &payload,
					     &payload_len, &error);
	if (rc != 0) {
		resmon_d_respond_invalid_params(peer, error);
		free(error);
		return;
	}

	if (payload_len % 2 != 0) {
		resmon_d_respond_invalid_params(peer,
				    "EMAD payload has an odd length");
		return;
	}

	size_t dec_payload_len = payload_len / 2;
	uint8_t *dec_payload = malloc(dec_payload_len);
	if (dec_payload == NULL)
		goto respond_memerr;

	rc = resmon_d_emad_decode_payload(dec_payload, payload,
					  dec_payload_len);
	if (rc != 0) {
		resmon_d_respond_invalid_params(peer,
				    "EMAD payload expected in hexdump format");
		goto out;
	}


	enum resmon_reg_process_result res =
		resmon_reg_process_emad(stat, dec_payload, dec_payload_len);
	switch (res) {
	case resmon_reg_process_delete_failed:
		resmon_d_respond_error(peer, id, res,
				       "EMAD processing error",
				       "Delete failed");
		goto out;
	case resmon_reg_process_insert_failed:
		resmon_d_respond_error(peer, id, res,
				       "EMAD processing error",
				       "Insert failed");
		goto out;
	case resmon_reg_process_truncated_payload:
		resmon_d_respond_error(peer, id, res,
				       "EMAD processing error",
				       "EMAD malformed: Payload truncated");
		goto out;
	case resmon_reg_process_no_register:
		resmon_d_respond_error(peer, id, res,
				       "EMAD processing error",
				       "EMAD malformed: No register");
		goto out;
	case resmon_reg_process_unknown_register:
		resmon_d_respond_error(peer, id, res,
				       "EMAD processing error",
				       "EMAD malformed: Unknown register");
		goto out;
	case resmon_reg_process_inconsistent_register:
		resmon_d_respond_error(peer, id, res,
				       "EMAD processing error",
				       "EMAD malformed: Inconsistent register");
		goto out;
	case resmon_reg_process_ok:
		break;
	default:
		assert(false);
	}

	struct json_object *obj = resmon_jrpc_new_object(id);
	if (obj == NULL)
		return;
	if (json_object_object_add(obj, "result", NULL))
		goto free_dec_payload;
	resmon_jrpc_take_send(peer, obj);

out:
	free(dec_payload);
	return;

free_dec_payload:
	free(dec_payload);
	json_object_put(obj);
respond_memerr:
	resmon_d_respond_memerr(peer, id);
}

static void resmon_d_handle_method(struct resmon_stat *stat,
				   struct resmon_sock *peer,
				   const char *method,
				   struct json_object *params_obj,
				   struct json_object *id)
{
	if (strcmp(method, "ping") == 0)
		return resmon_d_handle_echo(peer, params_obj, id);
	else if (strcmp(method, "quit") == 0)
		return resmon_d_handle_quit(peer, params_obj, id);
	else if (strcmp(method, "stats") == 0)
		return resmon_d_handle_stats(stat, peer, params_obj, id);
	else if (strcmp(method, "emad") == 0)
		return resmon_d_handle_emad(stat, peer, params_obj, id);
	else
		return resmon_d_respond_method_nf(peer, id, method);
}

static int resmon_d_ctl_activity(struct resmon_stat *stat,
				 struct resmon_sock *ctl)
{
	int err;

	struct resmon_sock peer;
	char *request = NULL;
	err = resmon_sock_recv(ctl, &peer, &request);
	if (err < 0)
		return err;

	// xxx
	fprintf(stderr, "activity: '%s'\n", request);

	struct json_object *request_obj = json_tokener_parse(request);
	if (request_obj == NULL) {
		resmon_d_respond_invalid(&peer, NULL);
		goto free_req;
	}

	struct json_object *id;
	const char *method;
	struct json_object *params;
	char *error;
	err = resmon_jrpc_dissect_request(request_obj, &id, &method, &params,
					  &error);
	if (err) {
		resmon_d_respond_invalid(&peer, error);
		free(error);
		goto put_req_obj;
	}

	resmon_d_handle_method(stat, &peer, method, params, id);

put_req_obj:
	json_object_put(request_obj);
free_req:
	free(request);
	return 0;
}

static int resmon_d_rb_activity(void *ctx, void *data, size_t len)
{
	struct resmon_stat *stat = ctx;
	fprintf(stderr, "process_sample len %zd\n", len); // xxx
	enum resmon_reg_process_result res = resmon_reg_process_emad(stat, data,
								     len);
	if (res != resmon_reg_process_ok) {
		// xxx enqueue a message? Or maybe this:
		//
		// # resmon -v start &
		// listening on such and such socket
		// # resmon -v ping
		// resmon is alive
		// # resmon -v listen
		// listening
		// ... waits for messages and prints them as they come
	}
	return 0;
}

static int resmon_d_loop(struct resmon_stat *stat, struct ring_buffer *ringbuf)
{
	int err;

	struct resmon_sock ctl;
	err = resmon_sock_open_d(&ctl);
	if (err)
		return err;

	if (env.verbosity > 0)
		fprintf(stderr, "Listening on %s\n", ctl.sa.sun_path);

	enum {
		pollfd_ctl,
		pollfd_rb,
	};

	struct pollfd pollfds[] = {
		[pollfd_ctl] = {
			.fd = ctl.fd,
			.events = POLLIN,
		},
		[pollfd_rb] = {
			.fd = ring_buffer__epoll_fd(ringbuf),
			.events = POLLIN,
		},
	};

	while (!should_quit) {
		int nfds = poll(pollfds, ARRAY_SIZE(pollfds), -1);
		if (nfds < 0 && errno != EINTR) {
			fprintf(stderr, "Failed to poll: %m\n");
			err = nfds;
			goto out;
		}
		if (nfds == 0)
			continue;
		for (size_t i = 0; i < ARRAY_SIZE(pollfds); i++) {
			struct pollfd *pollfd = &pollfds[i];

			if (pollfd->revents & (POLLERR | POLLHUP |
					       POLLNVAL)) {
				fprintf(stderr,
					"Problem on pollfd %zd: %m\n", i);
				err = -1;
				goto out;
			}
			if (pollfd->revents & POLLIN) {
				switch (i) {
				case pollfd_ctl:
					err = resmon_d_ctl_activity(stat, &ctl);
					if (err)
						goto out;
					break;
				case pollfd_rb:
					err = ring_buffer__consume(ringbuf);
					if (err < 0)
						goto out;
					break;
				}
			}
		}
	}

out:
	resmon_sock_close_d(&ctl);
	return err;
}

int resmon_d_start(void)
{
	int err;

	err = resmon_d_setup_signals();
	if (err < 0)
		return -1;

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "Failed to increase rlimit: %d\n", err);
		return -1;
	}

	struct resmon_stat *stat = resmon_stat_create();
	if (stat == NULL)
		return -1;

	libbpf_set_print(resmon_d_print_fn);

	struct resmon_bpf *obj = resmon_bpf__open();
	if (!obj) {
		fprintf(stderr, "Failed to open the resmon BPF object\n");
		goto destroy_stat;
	}

	err = resmon_bpf__load(obj);
	if (err) {
		fprintf(stderr, "Failed to load the resmon BPF object\n");
		goto destroy_bpf;
	}

	struct ring_buffer *ringbuf =
		ring_buffer__new(bpf_map__fd(obj->maps.ringbuf),
				 resmon_d_rb_activity, stat, NULL);
	if (ringbuf == NULL)
		goto destroy_bpf;

	err = resmon_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "Failed to attach BPF program\n");
		goto free_ringbuf;
	}

	err = resmon_d_loop(stat, ringbuf);

	resmon_bpf__detach(obj);
free_ringbuf:
	ring_buffer__free(ringbuf);
destroy_bpf:
	resmon_bpf__destroy(obj);
destroy_stat:
	resmon_stat_destroy(stat);
	return err;
}

