#include <assert.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>

#include "resmon.h"
#include "resmon-bpf.h"
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

static int resmon_d_start_bpf(struct resmon_bpf *obj)
{
	int err;

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "Failed to increase rlimit: %d\n", err);
		return err;
	}

	err = resmon_bpf__load(obj);
	if (err) {
		fprintf(stderr, "Failed to open & load BPF object\n");
		return err;
	}

	err = resmon_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "Failed to attach BPF program\n");
		return err;
	}

	return 0;
}

static void resmon_d_stop_bpf(struct resmon_bpf *obj)
{
	resmon_bpf__detach(obj);
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

static void resmon_d_handle_echo(struct resmon_sock *peer,
				 struct json_object *params_obj,
				 struct json_object *id)
{
	struct json_object *obj = resmon_jrpc_new_object(id);
	if (obj == NULL)
		return;

	if (resmon_jrpc_object_take_add(obj, "result",
					json_object_get(params_obj)))
		return;

	resmon_jrpc_take_send(peer, obj);
}

static void resmon_d_handle_quit(struct resmon_sock *peer,
				 struct json_object *params_obj,
				 struct json_object *id)
{
	struct json_object *obj = resmon_jrpc_new_object(id);
	if (obj == NULL)
		return;

	if (resmon_jrpc_object_take_add(obj, "result",
					json_object_new_boolean(true)))
		return;

	resmon_jrpc_take_send(peer, obj);
	should_quit = true;
}

static void resmon_d_handle_method(struct resmon_sock *peer,
				   const char *method,
				   struct json_object *params_obj,
				   struct json_object *id)
{
	if (strcmp(method, "ping") == 0)
		return resmon_d_handle_echo(peer, params_obj, id);
	else if (strcmp(method, "quit") == 0)
		return resmon_d_handle_quit(peer, params_obj, id);
	else
		return resmon_d_respond_method_nf(peer, id, method);
}

static int resmon_d_activity(struct resmon_sock *ctl)
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

	resmon_d_handle_method(&peer, method, params, id);

put_req_obj:
	json_object_put(request_obj);
free_req:
	free(request);
	return 0;
}

static int resmon_d_loop(struct resmon_bpf *obj)
{
	int err;

	struct resmon_sock ctl;
	err = resmon_sock_open_d(&ctl);
	if (err)
		return err;

	if (env.verbosity > 0)
		fprintf(stderr, "Listening on %s\n", ctl.sa.sun_path);

	struct pollfd pollfd = {
		.fd = ctl.fd,
		.events = POLLIN,
	};

	while (!should_quit) {
		int nfds = poll(&pollfd, 1, 100 /*ms*/);
		if (nfds < 0) {
			fprintf(stderr, "Failed to poll: %m\n");
			err = nfds;
			goto out;
		}
		if (nfds != 0) {
			assert(nfds == 1);
			if (pollfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
				fprintf(stderr, "Control socket error: %m\n");
				err = -1;
				goto out;
			}
			if (pollfd.revents & POLLIN) {
				assert(pollfd.fd == ctl.fd);
				err = resmon_d_activity(&ctl);
				if (err)
					goto out;
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

	struct resmon_bpf *obj = resmon_bpf__open();
	if (!obj) {
		fprintf(stderr, "Failed to open the resmon BPF object\n");
		return -1;
	}

	err = resmon_d_start_bpf(obj);
	if (err)
		return err;

	err = resmon_d_loop(obj);

	resmon_d_stop_bpf(obj);
	resmon_bpf__destroy(obj);
	return err;
}

