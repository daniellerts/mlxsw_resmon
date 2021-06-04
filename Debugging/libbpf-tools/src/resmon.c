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

static int resmon_bpf_pin_map(struct bpf_map *map,
			      const char *bpffs, const char *name)
{
	int err;

	err = bpf_map__pin(map, resmon_pin_path(bpffs, name));
	if (err)
		fprintf(stderr, "Failed to pin %s map: %s\n", name, strerror(-err));

	return err;
}

static int resmon_bpf_pin(struct resmon_bpf *obj, const char *bpffs)
{
	int err;

	err = bpf_link__pin(obj->links.handle__devlink_hwmsg,
			    resmon_pin_path(bpffs, "link"));
	if (err) {
		fprintf(stderr, "Failed to pin BPF link: %s\n", strerror(-err));
		return err;
	}

	err = resmon_bpf_pin_map(obj->maps.counters, bpffs, "counters");
	if (err)
		goto unpin_link;

	err = resmon_bpf_pin_map(obj->maps.ralue, bpffs, "ralue");
	if (err)
		goto unpin_counters;

	err = resmon_bpf_pin_map(obj->maps.ptar, bpffs, "ptar");
	if (err)
		goto unpin_ralue;

	err = resmon_bpf_pin_map(obj->maps.ptce3, bpffs, "ptce3");
	if (err)
		goto unpin_ptar;

	err = resmon_bpf_pin_map(obj->maps.kvdl, bpffs, "kvdl");
	if (err)
		goto unpin_ptce3;

	return 0;

unpin_ptce3:
	bpf_map__unpin(obj->maps.ptce3, NULL);
unpin_ptar:
	bpf_map__unpin(obj->maps.ptar, NULL);
unpin_ralue:
	bpf_map__unpin(obj->maps.ralue, NULL);
unpin_counters:
	bpf_map__unpin(obj->maps.counters, NULL);
unpin_link:
	bpf_link__unpin(obj->links.handle__devlink_hwmsg);
	rmdir(resmon_pin_path(bpffs, ""));
	return err;
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
		.sun_path = "/run/resmon.ctl",
	};
}

static int resmon_ctl_open(void)
{
	int fd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "Failed to create control socket: %m\n");
		return -1;
	}

	struct sockaddr_un sa = resmon_ctl_sockaddr();
	unlink(sa.sun_path);

	int err = bind(fd, (struct sockaddr *) &sa, sizeof sa);
	if (err < 0) {
		fprintf(stderr, "Failed to bind control socket: %m\n");
		goto close_out;
	}

	return fd;

close_out:
	close(fd);
	return err;
}

static void resmon_ctl_close(int fd)
{
	close(fd);
	unlink(resmon_ctl_sockaddr().sun_path);
}

enum {
	RESMON_ATTR_UNDEFINED,
	RESMON_ATTR_RESPONSE,
};

static void resmon_ctl_respond(int fd, struct sockaddr *sa, size_t sasz,
			       struct json_object *obj)
{
	const char *str = json_object_to_json_string(obj);
	sendto(fd, str, strlen(str), 0, sa, sasz);
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
	    /* Note: ID is allowed to be NULL. */
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

	resmon_ctl_respond(fd, sa, sasz, obj);

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

	resmon_ctl_respond(fd, sa, sasz, obj);

err_put_obj:
	json_object_put(obj);
}

static void resmon_ctl_handle_echo(int fd, struct sockaddr *sa, size_t sasz,
				   struct json_object *params_obj,
				   struct json_object *id)
{
	if (!id)
		return;

	struct json_object *obj = resmon_ctl_jsonrpc_object(id);
	if (obj == NULL)
		return;

	if (resmon_ctl_object_attach_result(obj, json_object_get(params_obj)))
		goto err_put_obj;

	resmon_ctl_respond(fd, sa, sasz, obj);

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
	if (strcmp(method, "echo") == 0)
		return resmon_ctl_handle_echo(fd, sa, sasz, params_obj, id);
	else
		return resmon_ctl_respond_method_nf(fd, sa, sasz, id);
}

static int resmon_ctl_activity(int fd)
{
	int err;
	struct sockaddr_un sa = {};
	socklen_t sasz = sizeof sa;
	ssize_t msgsz = recvfrom(fd, NULL, 0, MSG_PEEK | MSG_TRUNC,
				 (struct sockaddr *) &sa, &sasz);
	if (msgsz < 0) {
		fprintf(stderr, "Failed to receive data on control socket: %m\n");
		return -1;
	}

	char *buf = malloc(msgsz + 1);
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
			// xxx handle jsonrpc = "2.0"
			if (strcmp(key, "method") == 0)
				method = val;
			else if (strcmp(key, "params") == 0)
				params = val;
			else if (strcmp(key, "id") == 0)
				id = val;
			else {
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

	err = 0;
out:
	free(buf);
	return err;
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

static int resmon_start_main(int argc, char **argv)
{
	int err;

	if (argc)
		return unknown_argument(*argv);

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

	err = resmon_bpf_pin(obj, env.bpffs);
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
	return -EOPNOTSUPP; // xxx
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

static int resmon_ping(int argc, char **argv)
{
	return -EOPNOTSUPP; // xxx
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
	else if (matches(*argv, "ping") == 0)
		return resmon_ping(argc - 1, argv + 1);

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
		fprintf(stderr, "cannot handle SIGQUIT\n");
		return -1;
	}
	if (signal(SIGTERM, signal_handle_quit) == SIG_ERR) {
		fprintf(stderr, "Failed to set up SIGTERM handling: %m\n");
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int err = signals_setup();
	if (err < 0)
		return 1;

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
