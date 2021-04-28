// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
#include <inttypes.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "resmon.h"
#include "resmon.skel.h"
#include "trace_helpers.h"

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

	return 0;

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

	err = resmon_bpf_restore_map(obj->maps.ralue,
				     resmon_pin_path(bpffs, "ralue"));
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

enum resmon_unlink_status {
	resmon_unlink_nil,
	resmon_unlink_ok,
	resmon_unlink_enoent,
	resmon_unlink_fail,
};

static void resmon_check_status(enum resmon_unlink_status *status,
				enum resmon_unlink_status proposed)
{
	/* The following forbids transitioning from OK to ENOENT. ENOENT
	 * serves to distinguish the case where the tool has not been
	 * running at all, and therefore should only be reported if all
	 * items fail. */
	if (*status == resmon_unlink_nil)
		*status = proposed;
	else if (proposed != resmon_unlink_ok &&
		 proposed != *status)
		*status = resmon_unlink_fail;
}

static void resmon_check_rc(int (*cb)(const char *),
			    const char *path,
			    enum resmon_unlink_status *status,
			    int *errno_p, const char **path_p)
{
	if (cb(path) == 0)
		resmon_check_status(status, resmon_unlink_ok);
	else if (errno == ENOENT)
		resmon_check_status(status, resmon_unlink_enoent);
	else
		resmon_check_status(status, resmon_unlink_fail);

	if (*status == resmon_unlink_fail && *errno_p == 0) {
		*errno_p = errno;
		*path_p = path;
	}
}

static int resmon_stop_main(int argc, char **argv)
{
	if (argc)
		return unknown_argument(*argv);

	enum resmon_unlink_status status = resmon_unlink_nil;
	int fail_errno = 0;
	const char *fail_path;

	resmon_check_rc(unlink, resmon_pin_path(env.bpffs, "link"), &status,
			&fail_errno, &fail_path);
	resmon_check_rc(unlink, resmon_pin_path(env.bpffs, "counters"), &status,
			&fail_errno, &fail_path);
	resmon_check_rc(unlink, resmon_pin_path(env.bpffs, "ralue"), &status,
			&fail_errno, &fail_path);
	resmon_check_rc(rmdir, resmon_pin_path(env.bpffs, ""), &status,
			&fail_errno, &fail_path);

	switch (status) {
	case resmon_unlink_fail:
		fprintf(stderr, "Couldn't remove `%s': %s\n",
			fail_path, strerror(fail_errno));
		return -1;
	case resmon_unlink_enoent:
		fprintf(stderr, "Resmon is not running.\n");
		return -1;
	default:
		return 0;
	}
}

static int resmon_stop(int argc, char **argv)
{
	return resmon_common_args(argc, argv, resmon_stop_main);
}

static int resmon_stat(const char *path)
{
	struct stat buf;
	return stat(path, &buf);
}

static int resmon_is_running_main(int argc, char **argv)
{
	if (argc)
		return unknown_argument(*argv);

	enum resmon_unlink_status status = resmon_unlink_nil;
	int fail_errno = 0;
	const char *fail_path;

	resmon_check_rc(resmon_stat, resmon_pin_path(env.bpffs, "link"),
			&status, &fail_errno, &fail_path);
	resmon_check_rc(resmon_stat, resmon_pin_path(env.bpffs, "counters"),
			&status, &fail_errno, &fail_path);
	resmon_check_rc(resmon_stat, resmon_pin_path(env.bpffs, "ralue"),
			&status, &fail_errno, &fail_path);
	resmon_check_rc(resmon_stat, resmon_pin_path(env.bpffs, ""),
			&status, &fail_errno, &fail_path);

	switch (status) {
	case resmon_unlink_fail:
		fprintf(stderr, "Inconsistent state at `%s': %s\n",
			fail_path, strerror(fail_errno));
		return -1;
	case resmon_unlink_enoent:
		if (env.verbosity >= LIBBPF_INFO)
			fprintf(stderr, "Resmon is not running.\n");
		return 1;
	default:
		if (env.verbosity >= LIBBPF_INFO)
			fprintf(stderr, "Resmon is running.\n");
		return 0;
	}
}

static int resmon_is_running(int argc, char **argv)
{
	return resmon_common_args(argc, argv, resmon_is_running_main);
}

static int resmon_restart_main(int argc, char **argv)
{
	int err;

	if (argc)
		return unknown_argument(*argv);

	err = resmon_stop_main(0, NULL);
	if (err)
		return err;

	err = resmon_start_main(0, NULL);
	if (err)
		fprintf(stderr, "Couldn't restart resmon after already stopping it: %s.\n",
			strerror(errno));

	return err;
}

static int resmon_restart(int argc, char **argv)
{
	return resmon_common_args(argc, argv, resmon_restart_main);
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
	else if (matches(*argv, "start") == 0)
		return resmon_start(argc - 1, argv + 1);
	else if (matches(*argv, "stop") == 0)
		return resmon_stop(argc - 1, argv + 1);
	else if (matches(*argv, "restart") == 0)
		return resmon_restart(argc - 1, argv + 1);
	else if (matches(*argv, "is-running") == 0)
		return resmon_is_running(argc - 1, argv + 1);
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
