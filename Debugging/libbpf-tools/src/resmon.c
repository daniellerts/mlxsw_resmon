// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#define _GNU_SOURCE
#include <argp.h>
#include <assert.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <json-c/json_util.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include "resmon.h"
#include "resmon-bpf.h"
#include "resmon.skel.h"
#include "trace_helpers.h"

static bool should_quit = false;

static struct {
	int verbosity;
	const char *bpffs;
} env = {
	.verbosity = 0,
	.bpffs = "/sys/fs/bpf",
};
const char *program_version = "resmon 0.0";
const char *program_bug_address = "<mlxsw@nvidia.com>";

#define IS_ERR_VALUE(x) ((unsigned long)(void *)(x) >= (unsigned long)-1000)
static inline bool IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}

static int resmon_help(void);

static int unknown_argument(const char *arg)
{
	fprintf(stderr, "Unknown argument \"%s\"\n", arg);
	resmon_help();
	return -EINVAL;
}

int resmon_print_fn(enum libbpf_print_level level, const char *format,
		    va_list args)
{
	if ((int)level > env.verbosity)
		return 0;
	return vfprintf(stderr, format, args);
}

static const char *counter_descriptions[] = {
	RESMON_COUNTERS(RESMON_COUNTER_EXPAND_AS_DESC)
};

static void resmon_print_stats(struct bpf_map *counters)
{
	__u32 ncounters = bpf_map__max_entries(counters);
	int fd = bpf_map__fd(counters);

	if (ncounters != resmon_counter_count) {
		fprintf(stderr, "BPF tracks %d counters, but the userspace tool knows about %d.\n",
			ncounters, resmon_counter_count);
		if (resmon_counter_count < ncounters)
			ncounters = resmon_counter_count;
	}

	fprintf(stdout, "%-40s Usage\n", "Resource");
	for (int i = 0; i < ncounters; i++) {
		uint64_t value;
		if (!bpf_map_lookup_elem(fd, &i, &value))
			fprintf(stdout, "%-40s %" PRIi64 "\n",
				counter_descriptions[i], value);
		else
			fprintf(stdout, "%-40s ???\n", counter_descriptions[i]);
	}
}

static unsigned int resmon_fmt_path(char *buf, size_t size,
				    const char *bpffs, const char *name)
{
	int len = snprintf(buf, size, "%s/mlxsw_spectrum_resmon/%s",
			   bpffs, name);

	if (len < 0) {
		fprintf(stderr, "Couldn't format pin path: %s\n",
			strerror(errno));
		abort();
	}
	return len;
}

#define resmon_pin_path(BPFFS, NAME)					\
	({								\
		const char *__bpffs = (BPFFS);				\
		const char *__name = (NAME);				\
		unsigned int len = resmon_fmt_path(NULL, 0,		\
						   __bpffs, __name);	\
		char *buf = alloca(len + 1);				\
									\
		resmon_fmt_path(buf, len + 1, __bpffs, __name);		\
		(const char *) buf;					\
	})

static int resmon_bpf_start(struct resmon_bpf *obj)
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

static void resmon_bpf_stop(struct resmon_bpf *obj)
{
	resmon_bpf__detach(obj);
}

static int resmon_bpf_restore_map(struct bpf_map *map, const char *path)
{
	int fd;
	int err;

	fd = bpf_obj_get(path);
	if (fd < 0) {
		fprintf(stderr, "Failed to retrieve the map pinned at %s: %s\n",
			path, strerror(errno));
		return -errno;
	}

	err = bpf_map__reuse_fd(map, fd);
	if (err) {
		fprintf(stderr, "Failed to reuse pinned counter map descriptor: %s\n",
			strerror(-err));
		return err;
	}

	return 0;
}

static int resmon_bpf_restore(struct resmon_bpf *obj, const char *bpffs)
{
	int err;

	err = resmon_bpf_restore_map(obj->maps.counters,
				     resmon_pin_path(bpffs, "counters"));
	if (err)
		return err;

	return 0;
}

static int resmon_common_args(int argc, char **argv,
			      int (*and_then)(int argc, char **argv))
{
	while (argc) {
		if (strcmp(*argv, "help") == 0) {
			return resmon_help();
		} else {
			break;
		}
	}

	return and_then(argc, argv);
}

static int resmon_common_args_only_check(int argc, char **argv)
{
	return argc == 0 ? 0 : -1;
}

static int resmon_common_args_only(int argc, char **argv,
			      int (*and_then)(void))
{
	int err = resmon_common_args(argc, argv,
				     resmon_common_args_only_check);
	if (err)
		return err;
	return and_then();
}

static void resmon_ctl_respond_invalid(struct resmon_sock *ctl,
				       struct json_object *id, const char *data)
{
	resmon_jrpc_take_send(ctl,
		    resmon_jrpc_new_error(id, -32600, "Invalid Request", data));
}

static void resmon_ctl_respond_method_nf(struct resmon_sock *peer,
					 struct json_object *id,
					 const char *method)
{
	resmon_jrpc_take_send(peer,
		    resmon_jrpc_new_error(id, -32601, "Method not found",
					  method));
}

static void resmon_ctl_handle_echo(struct resmon_sock *peer,
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

static void resmon_ctl_handle_quit(struct resmon_sock *peer,
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

static void resmon_ctl_handle_method(struct resmon_sock *peer,
				     const char *method,
				     struct json_object *params_obj,
				     struct json_object *id)
{
	if (strcmp(method, "ping") == 0)
		return resmon_ctl_handle_echo(peer, params_obj, id);
	else if (strcmp(method, "quit") == 0)
		return resmon_ctl_handle_quit(peer, params_obj, id);
	else
		return resmon_ctl_respond_method_nf(peer, id, method);
}

static bool resmon_cli_validate_id(struct json_object *id_obj, int expect_id)
{
	int64_t id = json_object_get_int64(id_obj);
	return id == expect_id;
}

static void resmon_cli_handle_response_error(struct json_object *error_obj)
{
	int64_t code;
	const char *message;
	struct json_object *data;
	char *error;
	int err = resmon_jrpc_dissect_error(error_obj, &code, &message, &data,
					    &error);
	if (err) {
		fprintf(stderr, "Invalid error object: %s\n", error);
		free(error);
		return;
	}

	if (data != NULL)
		fprintf(stderr, "Error %" PRId64 ": %s (%s)\n", code, message,
			json_object_to_json_string(data));
	else
		fprintf(stderr, "Error %" PRId64 ": %s\n", code, message);
}

static struct json_object *
resmon_cli_handle_response(struct json_object *j,
			   int expect_id, enum json_type result_type)
{
	struct json_object *id;
	struct json_object *result;
	bool is_error;
	char *error;
	int err = resmon_jrpc_dissect_response(j, &id, &result, &is_error,
					       &error);
	if (err) {
		fprintf(stderr, "Invalid response object: %s\n", error);
		free(error);
		return NULL;
	}

	if (!resmon_cli_validate_id(id, expect_id)) {
		fprintf(stderr, "Unknown response ID: %s\n",
			json_object_to_json_string(id));
		return NULL;
	}

	if (is_error) {
		resmon_cli_handle_response_error(result);
		return NULL;
	}

	if (json_object_get_type(result) != result_type) {
		fprintf(stderr, "Unexpected result type: %s expected, got %s\n",
			json_type_to_name(json_object_get_type(result)),
			json_type_to_name(result_type));
		return NULL;
	}

	return json_object_get(result);
}

static int resmon_ctl_activity(struct resmon_sock *ctl)
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
		resmon_ctl_respond_invalid(&peer, NULL, NULL);
		goto free_req;
	}

	struct json_object *id;
	const char *method;
	struct json_object *params;
	char *error;
	err = resmon_jrpc_dissect_request(request_obj, &id, &method, &params,
					  &error);
	if (err) {
		resmon_ctl_respond_invalid(&peer, NULL, error);
		free(error);
		goto put_req_obj;
	}

	resmon_ctl_handle_method(&peer, method, params, id);

put_req_obj:
	json_object_put(request_obj);
free_req:
	free(request);
	return 0;
}

static int resmon_loop(void)
{
	int err;

	struct resmon_bpf *obj = resmon_bpf__open();
	if (!obj) {
		fprintf(stderr, "Failed to open the resmon BPF object\n");
		return -1;
	}

	err = resmon_bpf_start(obj);
	if (err)
		goto destroy_out;

	struct resmon_sock ctl;
	err = resmon_ctl_open(&ctl);
	if (err)
		goto stop_out;

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
				err = resmon_ctl_activity(&ctl);
				if (err)
					goto out;
			}
		}
	}

out:
	resmon_ctl_close(&ctl);
stop_out:
	resmon_bpf_stop(obj);
destroy_out:
	resmon_bpf__destroy(obj);
	return err;
}

static void signal_handle_quit(int sig)
{
	should_quit = true;
}

static int signals_setup(void)
{
	if (signal(SIGINT, signal_handle_quit) == SIG_ERR) {
		fprintf(stderr, "Failed to set up SIGINT handling: %m\n");
		return -1;
	}
	if (signal(SIGQUIT, signal_handle_quit) == SIG_ERR) {
		fprintf(stderr, "Failed to set up SIGQUIT handling: %m\n");
		return -1;
	}
	if (signal(SIGTERM, signal_handle_quit) == SIG_ERR) {
		fprintf(stderr, "Failed to set up SIGTERM handling: %m\n");
		return -1;
	}
	return 0;
}

static int resmon_do_start(void)
{
	int err;

	err = signals_setup();
	if (err < 0)
		return -1;

	struct resmon_bpf *obj = resmon_bpf__open();
	if (!obj) {
		fprintf(stderr, "Failed to open the resmon BPF object\n");
		return -1;
	}

	err = resmon_bpf_start(obj);
	if (err)
		return err;

	err = resmon_loop();
	if (err)
		goto destroy_bpf;

destroy_bpf:
	resmon_bpf__destroy(obj);
	return err;
}

static int resmon_start(int argc, char **argv)
{
	return resmon_common_args_only(argc, argv, resmon_do_start);
}

static struct json_object *resmon_cli_send_request(struct json_object *request)
{
	struct json_object *response_obj = NULL;
	int err = -1;

	struct resmon_sock cli;
	struct resmon_sock peer;
	err = resmon_cli_open(&cli, &peer);
	if (err < 0) {
		fprintf(stderr, "Failed to open a socket: %m\n");
		return NULL;
	}

	err = resmon_jrpc_take_send(&peer, json_object_get(request));
	if (err < 0) {
		fprintf(stderr, "Failed to send the RPC message: %m\n");
		goto close_fd;
	}

	char *response;
	err = resmon_sock_recv(&cli, &peer, &response);
	if (err < 0) {
		fprintf(stderr, "Failed to receive an RPC response\n");
		goto close_fd;
	}

	response_obj = json_tokener_parse(response);
	if (response_obj == NULL) {
		fprintf(stderr, "Failed to parse RPC response as JSON.\n");
		goto free_response;
	}

free_response:
	free(response);
close_fd:
	resmon_cli_close(&cli);
	return response_obj;
}

static int resmon_cli_do_stop(void)
{
	int err;

	const int id = 1;
	struct json_object *request = resmon_jrpc_new_request(id, "quit");
	if (request == NULL)
		return -1;

	struct json_object *response = resmon_cli_send_request(request);
	if (response == NULL) {
		err = -1;
		goto put_request;
	}

	struct json_object *result =
		resmon_cli_handle_response(response, id, json_type_boolean);
	if (result == NULL) {
		err = -1;
		goto put_response;
	}

	if (json_object_get_boolean(result)) {
		if (env.verbosity > 0)
			fprintf(stderr, "resmond will stop\n");
		err = 0;
	} else {
		if (env.verbosity > 0)
			fprintf(stderr, "resmond refuses to stop\n");
		err = -1;
	}


	json_object_put(result);
put_response:
	json_object_put(response);
put_request:
	json_object_put(request);
	return err;
}

static int resmon_cli_stop(int argc, char **argv)
{
	return resmon_common_args_only(argc, argv, resmon_cli_do_stop);
}

static int resmon_cli_do_ping(void)
{
	int err;

	const int id = 1;
	struct json_object *request = resmon_jrpc_new_request(id, "ping");
	if (request == NULL)
		return -1;

	srand(time(NULL));
	const int r = rand();
	if (resmon_jrpc_object_take_add(request, "params",
					json_object_new_int(r))) {
		fprintf(stderr, "Failed to form a request object.\n");
		err = -1;
		goto put_request;
	}

	struct json_object *response = resmon_cli_send_request(request);
	if (response == NULL) {
		err = -1;
		goto put_request;
	}

	struct json_object *result = resmon_cli_handle_response(response, id,
								json_type_int);
	if (result == NULL) {
		err = -1;
		goto put_response;
	}

	const int nr = json_object_get_int(result);
	if (nr != r) {
		fprintf(stderr, "Unexpected ping response: sent %d, got %d.\n",
			r, nr);
		err = -1;
		goto put_result;
	}

	if (env.verbosity > 0)
		fprintf(stderr, "resmond is alive\n");
	err = 0;

put_result:
	json_object_put(result);
put_response:
	json_object_put(response);
put_request:
	json_object_put(request);
	return err;
}

static int resmon_cli_ping(int argc, char **argv)
{
	return resmon_common_args_only(argc, argv, resmon_cli_do_ping);
}

static int resmon_stats_main(int argc, char **argv)
{
	int err;

	if (argc)
		return unknown_argument(*argv);

	struct resmon_bpf *obj = resmon_bpf__open();
	if (!obj) {
		fprintf(stderr, "Failed to open the resmon BPF object\n");
		return -1;
	}

	err = resmon_bpf_restore(obj, env.bpffs);
	if (err)
		return err;

	resmon_print_stats(obj->maps.counters);
	resmon_bpf__destroy(obj);
	return 0;
}

static int resmon_stats(int argc, char **argv)
{
	return resmon_common_args(argc, argv, resmon_stats_main);
}

static int resmon_cmd(int argc, char **argv)
{
	if (!argc || strcmp(*argv, "help") == 0)
		return resmon_help();
	else if (strcmp(*argv, "start") == 0)
		return resmon_start(argc - 1, argv + 1);
	else if (strcmp(*argv, "stop") == 0)
		return resmon_cli_stop(argc - 1, argv + 1);
	else if (strcmp(*argv, "ping") == 0)
		return resmon_cli_ping(argc - 1, argv + 1);
	else if (strcmp(*argv, "stats") == 0)
		return resmon_stats(argc - 1, argv + 1);

	fprintf(stderr, "Unknown command \"%s\"\n", *argv);
	return -EINVAL;
}

static int resmon_help(void)
{
	puts("Monitor resource usage in a Spectrum switch.\n"
	     "\n"
	     "Usage: resmon [OPTIONS] { COMMAND | help }\n"
	     "where  OPTIONS := [ -h | --help | -q | --quiet | -v | --verbose |\n"
             "                    -V | --version | --bpffs <PATH> ]\n"
             "       COMMAND := { start | stop | ping | stats }\n"
	     );
	return 0;
}

enum {
	resmon_opt_bpffs,
};

int main(int argc, char **argv)
{
	static const struct option long_options[] = {
		{ "help",	no_argument,	   NULL, 'h' },
		{ "quiet",	no_argument,	   NULL, 'q' },
		{ "verbose",	no_argument,	   NULL, 'v' },
		{ "Version",	no_argument,	   NULL, 'V' },
		{ "bpffs",	required_argument, NULL, resmon_opt_bpffs },
		{ NULL, 0, NULL, 0 }
	};
	int opt;

	while ((opt = getopt_long(argc, argv, "hqvV",
				  long_options, NULL)) >= 0) {
		switch (opt) {
		case 'V':
			printf("mlxsw resource monitoring tool, %s\n", program_version);
			return 0;
		case 'h':
			resmon_help();
			return 0;
		case 'v':
			env.verbosity++;
			break;
		case 'q':
			env.verbosity--;
			break;
		case resmon_opt_bpffs:
			env.bpffs = optarg;
			break;
		default:
			fprintf(stderr, "Unknown option.\n");
			resmon_help();
			return 1;
		}
	}

	argc -= optind;
	argv += optind;

	libbpf_set_print(resmon_print_fn);

	return resmon_cmd(argc, argv);
}
