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
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <json-c/json_object.h>
#include <json-c/json_object_iterator.h>
#include <json-c/json_tokener.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include "resmon.h"
#include "resmon.skel.h"
#include "trace_helpers.h"

static bool should_quit = false;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

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

static bool matches(const char *prefix, const char *string)
{
	if (!*prefix)
		return true;
	while (*string && *prefix == *string) {
		prefix++;
		string++;
	}

	return !!*prefix;
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
		if (matches(*argv, "help") == 0) {
			return resmon_help();
		} else {
			break;
		}
	}

	return and_then(argc, argv);
}

static struct sockaddr_un resmon_ctl_sockaddr(void)
{
	return (struct sockaddr_un) {
		.sun_family = AF_LOCAL,
		.sun_path = "/var/run/resmon.ctl",
	};
}

static struct sockaddr_un resmon_cli_sockaddr(void)
{
	static struct sockaddr_un sa = {};
	if (sa.sun_family == AF_UNSPEC) {
		snprintf(sa.sun_path, sizeof sa.sun_path,
			 "/var/run/resmon.cli.%d", getpid());
		sa.sun_family = AF_LOCAL;
	}
	return sa;
}

static int resmon_socket_open(struct sockaddr_un sa)
{
	int fd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "Failed to create control socket: %m\n");
		return -1;
	}

	unlink(sa.sun_path);

	int err = bind(fd, (struct sockaddr *) &sa, sizeof sa);
	if (err < 0) {
		fprintf(stderr, "Failed to bind control socket: %m\n");
		goto close_fd;
	}

	return fd;

close_fd:
	close(fd);
	return err;
}

static void resmon_socket_close(struct sockaddr_un sa, int fd)
{
	close(fd);
	unlink(sa.sun_path);
}

static int resmon_ctl_open(void)
{
	return resmon_socket_open(resmon_ctl_sockaddr());
}

static void resmon_ctl_close(int fd)
{
	return resmon_socket_close(resmon_ctl_sockaddr(), fd);
}

static int resmon_ctl_send(int fd, struct sockaddr *sa, size_t sasz,
			   struct json_object *obj)
{
	const char *str = json_object_to_json_string(obj);
	size_t len = strlen(str);
	int rc = sendto(fd, str, len, 0, sa, sasz);
	return rc == len ? 0 : -1;
}

static int resmon_ctl_object_attach(struct json_object *obj,
				    const char *key,
				    struct json_object *val_obj)
{
	if (val_obj == NULL)
		return -1;

	int rc = json_object_object_add(obj, key, val_obj);
	if (rc < 0) {
		json_object_put(val_obj);
		return -1;
	}

	return 0;
}

static struct json_object *resmon_ctl_jsonrpc_object(struct json_object *id)
{
	struct json_object *obj = json_object_new_object();
	if (obj == NULL)
		return NULL;

	if (resmon_ctl_object_attach(obj, "jsonrpc",
				     json_object_new_string("2.0")) ||
	    /* Note: ID is allowed to be NULL, so use json_object_object_add. */
	    json_object_object_add(obj, "id", id))
		goto err_put_obj;

	return obj;

err_put_obj:
	json_object_put(obj);
	return NULL;
}

static int resmon_ctl_object_attach_error(struct json_object *obj,
					  int code, const char *message)
{
	struct json_object *err_obj = json_object_new_object();
	if (err_obj == NULL)
		return -1;

	if (resmon_ctl_object_attach(err_obj, "code",
				     json_object_new_int(code)) ||
	    resmon_ctl_object_attach(err_obj, "message",
				     json_object_new_string(message)))
		goto err_put_obj;

	return resmon_ctl_object_attach(obj, "error", err_obj);

err_put_obj:
	json_object_put(obj);
	return -1;
}

static int resmon_ctl_object_attach_result(struct json_object *obj,
					   struct json_object *val_obj)
{
	int rc = json_object_object_add(obj, "result", val_obj);
	if (rc)
		json_object_put(val_obj);
	return rc;
}

static void resmon_ctl_respond_invalid(int fd, struct sockaddr *sa, size_t sasz,
				       struct json_object *id)
{
	struct json_object *obj = resmon_ctl_jsonrpc_object(id);
	if (obj == NULL)
		return;

	if (resmon_ctl_object_attach_error(obj, -32600, "Invalid Request"))
		goto err_put_obj;

	resmon_ctl_send(fd, sa, sasz, obj);

err_put_obj:
	json_object_put(obj);
}

static void resmon_ctl_respond_method_nf(int fd, struct sockaddr *sa, size_t sasz,
					 struct json_object *id)
{
	struct json_object *obj = resmon_ctl_jsonrpc_object(id);
	if (obj == NULL)
		return;

	if (resmon_ctl_object_attach_error(obj, -32601, "Method not found"))
		goto err_put_obj;

	resmon_ctl_send(fd, sa, sasz, obj);

err_put_obj:
	json_object_put(obj);
}

static void resmon_ctl_handle_echo(int fd, struct sockaddr *sa, size_t sasz,
				   struct json_object *params_obj,
				   struct json_object *id)
{
	struct json_object *obj = resmon_ctl_jsonrpc_object(id);
	if (obj == NULL)
		return;

	if (resmon_ctl_object_attach_result(obj, json_object_get(params_obj)))
		goto err_put_obj;

	resmon_ctl_send(fd, sa, sasz, obj);

err_put_obj:
	json_object_put(obj);
}

static void resmon_ctl_handle_quit(int fd, struct sockaddr *sa, size_t sasz,
				   struct json_object *params_obj,
				   struct json_object *id)
{
	struct json_object *obj = resmon_ctl_jsonrpc_object(id);
	if (obj == NULL)
		return;

	if (resmon_ctl_object_attach_result(obj, json_object_new_boolean(true)))
		goto err_put_obj;

	resmon_ctl_send(fd, sa, sasz, obj);
	should_quit = true;

err_put_obj:
	json_object_put(obj);
}

static void resmon_ctl_handle_method(int fd, struct sockaddr *sa, size_t sasz,
				     struct json_object *method_obj,
				     struct json_object *params_obj,
				     struct json_object *id)
{
	if (json_object_get_type(method_obj) != json_type_string)
		return resmon_ctl_respond_invalid(fd, sa, sasz, id);

	const char *method = json_object_get_string(method_obj);
	if (id != NULL &&
	    strcmp(method, "echo") == 0)
		return resmon_ctl_handle_echo(fd, sa, sasz, params_obj, id);
	else if (id != NULL &&
		 strcmp(method, "quit") == 0)
		return resmon_ctl_handle_quit(fd, sa, sasz, params_obj, id);
	else
		return resmon_ctl_respond_method_nf(fd, sa, sasz, id);
}

static bool resmon_ctl_validate_jsonrpc(struct json_object *ver_obj)
{
	if (json_object_get_type(ver_obj) != json_type_string)
		return false;

	const char *ver = json_object_get_string(ver_obj);
	return strcmp(ver, "2.0") == 0;
}

static int resmon_ctl_recv(int fd, struct sockaddr *sa, socklen_t *sasz,
			   char **bufp)
{
	int err;
	ssize_t msgsz = recvfrom(fd, NULL, 0, MSG_PEEK | MSG_TRUNC,
				 sa, sasz);
	if (msgsz < 0) {
		fprintf(stderr, "Failed to receive data on control socket: %m\n");
		return -1;
	}

	char *buf = calloc(1, msgsz + 1);
	if (buf == NULL) {
		fprintf(stderr, "Failed to allocate control message buffer: %m\n");
		return -1;
	}

	ssize_t n = recv(fd, buf, msgsz, 0);
	if (n < 0) {
		fprintf(stderr, "Failed to receive data on control socket: %m\n");
		err = -1;
		goto out;
	}
	buf[n] = '\0';

	*bufp = buf;
	buf = NULL;
	err = 0;

out:
	free(buf);
	return err;
}

static int resmon_ctl_activity(int fd)
{
	struct sockaddr_un sa = {};
	socklen_t sasz = sizeof sa;
	char *buf = NULL;
	int err = resmon_ctl_recv(fd, (struct sockaddr *) &sa, &sasz, &buf);
	if (err < 0)
		return err;


	fprintf(stderr, "activity: '%s'\n", buf);

	struct json_object *method = NULL;
	struct json_object *params = NULL;
	struct json_object *id = NULL;
	bool invalid = false;

	struct json_object *j = json_tokener_parse(buf);
	if (j == NULL)
		invalid = true;
	else {
		for (struct json_object_iterator it = json_object_iter_begin(j),
			     et = json_object_iter_end(j);
		     !json_object_iter_equal(&it, &et);
		     json_object_iter_next(&it)) {
			const char *key = json_object_iter_peek_name(&it);
			struct json_object *val = json_object_iter_peek_value(&it);
			if (strcmp(key, "method") == 0)
				method = val;
			else if (strcmp(key, "params") == 0)
				params = val;
			else if (strcmp(key, "id") == 0)
				id = val;
			else if (strcmp(key, "jsonrpc") == 0) {
				if (!resmon_ctl_validate_jsonrpc(val))
					invalid = true;
			} else {
				invalid = true;
				break;
			}
		}
	}

	if (invalid)
		resmon_ctl_respond_invalid(fd, (struct sockaddr *) &sa, sasz,
					   id);
	else if (method != NULL)
		resmon_ctl_handle_method(fd, (struct sockaddr *) &sa, sasz,
					 method, params, id);
	else
		/* No method => not a request. */
		resmon_ctl_respond_invalid(fd, (struct sockaddr *) &sa, sasz,
					   id);

	free(buf);
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

	int fd = resmon_ctl_open();
	if (fd < 0) {
		err = fd;
		goto stop_out;
	}

	struct pollfd pollfd = {
		.fd = fd,
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
				err = resmon_ctl_activity(pollfd.fd);
				if (err)
					goto out;
			}
		}
	}

out:
	resmon_ctl_close(fd);
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

static int resmon_start_main(int argc, char **argv)
{
	int err;

	if (argc)
		return unknown_argument(*argv);

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
		return err;

	resmon_bpf__destroy(obj);
	return err;
}

static int resmon_start(int argc, char **argv)
{
	return resmon_common_args(argc, argv, resmon_start_main);
}

static int resmon_stop(int argc, char **argv)
{
	int err = -1;
	int fd = resmon_socket_open(resmon_cli_sockaddr());
	if (fd < 0) {
		fprintf(stderr, "Failed to open a socket: %m\n");
		return -1;
	}

	struct sockaddr_un sa = resmon_ctl_sockaddr();
	err = connect(fd, &sa, sizeof sa);
	if (err) {
		fprintf(stderr, "Failed to connect to %s: %m\n",
			sa.sun_path);
		goto close_fd;
	}

	struct json_object *id = json_object_new_int(1);
	if (id == NULL) {
		fprintf(stderr, "Failed to allocate an ID object.\n");
		goto close_fd;
	}

	struct json_object *query = resmon_ctl_jsonrpc_object(id);
	if (query == NULL) {
		fprintf(stderr, "Failed to allocate a request object.\n");
		goto free_id;
	}
	id = NULL;

	if (resmon_ctl_object_attach(query, "method",
				     json_object_new_string("quit"))) {
		fprintf(stderr, "Failed to form a request object.\n");
		goto put_query;
	}

	err = resmon_ctl_send(fd, (struct sockaddr *) &sa, sizeof sa, query);
	if (err < 0) {
		fprintf(stderr, "Failed to send the RPC message: %m\n");
		goto put_query;
	}

	char *buf = NULL;
	err = resmon_ctl_recv(fd, NULL, NULL, &buf);
	if (err < 0) {
		fprintf(stderr, "Failed to receive an RPC response\n");
		goto put_query;
	}

	fprintf(stderr, "response: '%s'\n", buf);
	err = 0;

	free(buf);
put_query:
	json_object_put(query);
free_id:
	if (id != NULL)
		json_object_put(id);
close_fd:
	resmon_socket_close(resmon_cli_sockaddr(), fd);
	return err;
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
	if (!argc || matches(*argv, "help") == 0)
		return resmon_help();
	else if (matches(*argv, "__start__") == 0)
		return resmon_start(argc - 1, argv + 1);
	else if (matches(*argv, "__stop__") == 0)
		return resmon_stop(argc - 1, argv + 1);
	else if (matches(*argv, "stats") == 0)
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
             "       COMMAND := { start | stop | restart | is-running | stats }\n"
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
