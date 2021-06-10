// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <json-c/json_object.h>
#include <json-c/json_object_iterator.h>
#include <json-c/json_util.h>

#include "resmon.h"
#include "bpf_util.h"

int resmon_jrpc_object_take_add(struct json_object *obj,
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

static int resmon_jrpc_object_add_error(struct json_object *obj,
					int code, const char *message,
					const char *data)
{
	struct json_object *err_obj = json_object_new_object();
	if (err_obj == NULL)
		return -1;

	if (resmon_jrpc_object_take_add(err_obj, "code",
					json_object_new_int(code)) ||
	    resmon_jrpc_object_take_add(err_obj, "message",
					json_object_new_string(message)))
		goto err_put_obj;

	if (data)
		/* Allow this to fail, the error object is valid without it. */
		resmon_jrpc_object_take_add(err_obj, "data",
					    json_object_new_string(data));

	return resmon_jrpc_object_take_add(obj, "error", err_obj);

err_put_obj:
	json_object_put(obj);
	return -1;
}

struct json_object *resmon_jrpc_new_object(struct json_object *id)
{
	struct json_object *obj = json_object_new_object();
	if (obj == NULL)
		return NULL;

	if (resmon_jrpc_object_take_add(obj, "jsonrpc",
					json_object_new_string("2.0")))
		goto err_put_obj;

	/* ID member is mandatory, but is allowed to be a NULL object. */
	if (id == NULL) {
		if (json_object_object_add(obj, "id", NULL))
			goto err_put_obj;
	} else {
		if (resmon_jrpc_object_take_add(obj, "id",
						json_object_get(id)))
			goto err_put_obj;
	}

	return obj;

err_put_obj:
	json_object_put(obj);
	return NULL;
}

struct json_object *resmon_jrpc_new_request(int id, const char *method)
{
	struct json_object *id_obj = json_object_new_int(id);
	if (id_obj == NULL) {
		fprintf(stderr, "Failed to allocate an ID object.\n");
		return NULL;
	}

	struct json_object *request = resmon_jrpc_new_object(id_obj);
	if (request == NULL) {
		fprintf(stderr, "Failed to allocate a request object.\n");
		goto put_id;
	}

	if (resmon_jrpc_object_take_add(request, "method",
					json_object_new_string(method))) {
		fprintf(stderr, "Failed to form a request object.\n");
		goto put_request;
	}

	goto put_id;

put_request:
	json_object_put(request);
put_id:
	json_object_put(id_obj);
	return request;
}

struct json_object *resmon_jrpc_new_error(struct json_object *id,
					  int code,
					  const char *message,
					  const char *data)
{
	struct json_object *obj = resmon_jrpc_new_object(id);
	if (obj == NULL)
		return NULL;

	if (resmon_jrpc_object_add_error(obj, code, message, data))
		goto err_put_obj;

	return obj;

err_put_obj:
	json_object_put(obj);
	return NULL;
}

struct resmon_jrpc_policy {
	const char *key;
	enum json_type type;
	bool any_type;
	bool required;
};

static int resmon_jrpc_dissect(struct json_object *obj,
			       struct resmon_jrpc_policy policy[],
			       struct json_object *values[],
			       size_t policy_size,
			       char **error)
{
	for (struct json_object_iterator it = json_object_iter_begin(obj),
					 et = json_object_iter_end(obj);
	     !json_object_iter_equal(&it, &et);
	     json_object_iter_next(&it)) {
		const char *key = json_object_iter_peek_name(&it);
		struct json_object *val = json_object_iter_peek_value(&it);

		bool found = false;
		for (size_t i = 0; i < policy_size; i++) {
			struct resmon_jrpc_policy *pol = &policy[i];
			if (strcmp(key, pol->key) == 0) {
				enum json_type type = json_object_get_type(val);
				if (!pol->any_type && pol->type != type) {
					asprintf(error, "The member %s is expected to be a %s, but is %s",
						 key,
						 json_type_to_name(pol->type),
						 json_type_to_name(type));
					return -1;
				}

				if (values[i] != NULL) {
					asprintf(error, "Duplicate member %s",
						 key);
					return -1;
				}

				values[i] = val;
				found = true;
				break;
			}
		}

		if (!found) {
			asprintf(error, "The member %s is not expected", key);
			return -1;
		}
	}

	for (size_t i = 0; i < policy_size; i++) {
		struct resmon_jrpc_policy *pol = &policy[i];
		if (values[i] == NULL && pol->required) {
			asprintf(error, "Required member %s not present",
				 pol->key);
			return -1;
		}
	}

	return 0;
}

static bool resmon_jrpc_validate_version(struct json_object *ver_obj,
					 char **error)
{
	assert(json_object_get_type(ver_obj) == json_type_string);
	const char *ver = json_object_get_string(ver_obj);
	if (strcmp(ver, "2.0") != 0) {
		asprintf(error, "Unsupported jsonrpc version: %s", ver);
		return false;
	}

	return true;
}

int resmon_jrpc_dissect_request(struct json_object *obj,
				struct json_object **id,
				const char **method,
				struct json_object **params,
				char **error)
{
	enum {
		pol_jsonrpc,
		pol_id,
		pol_method,
		pol_params,
	};
	struct resmon_jrpc_policy policy[] = {
		[pol_jsonrpc] = { .key = "jsonrpc", .type = json_type_string,
				  .required = true },
		[pol_id] =      { .key = "id", .any_type = true,
				  .required = true },
		[pol_method] =  { .key = "method", .type = json_type_string,
				  .required = true },
		[pol_params] =  { .key = "params", .any_type = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	int err = resmon_jrpc_dissect(obj, policy, values, ARRAY_SIZE(policy),
				      error);
	if (err)
		return err;

	if (!resmon_jrpc_validate_version(values[pol_jsonrpc], error))
		return -1;

	*id = values[pol_id];
	*method = json_object_get_string(values[pol_method]);
	*params = values[pol_params];
	return 0;
}

int resmon_jrpc_dissect_response(struct json_object *obj,
				 struct json_object **id,
				 struct json_object **result,
				 bool *is_error,
				 char **error)
{
	enum {
		pol_jsonrpc,
		pol_id,
		pol_result,
		pol_error,
	};
	struct resmon_jrpc_policy policy[] = {
		[pol_jsonrpc] = { .key = "jsonrpc", .type = json_type_string,
				  .required = true },
		[pol_id] =      { .key = "id", .any_type = true,
				  .required = true },
		[pol_error] =   { .key = "error", .type = json_type_object },
		[pol_result] =  { .key = "result", .any_type = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	int err = resmon_jrpc_dissect(obj, policy, values, ARRAY_SIZE(policy),
				      error);
	if (err)
		return err;

	if (!resmon_jrpc_validate_version(values[pol_jsonrpc], error))
		return -1;

	struct json_object *e = values[pol_error];
	struct json_object *r = values[pol_result];
	if (e != NULL && r != NULL) {
		asprintf(error, "Both error and result present in jsonrpc response");
		return -1;
	} else if (e == NULL && r == NULL) {
		asprintf(error, "Neither error nor result present in jsonrpc response");
		return -1;
	}

	*id = values[pol_id];
	*result = r ?: e;
	*is_error = e;
	return 0;
}

int resmon_jrpc_dissect_error(struct json_object *obj,
			      int64_t *code,
			      const char **message,
			      struct json_object **data,
			      char **error)
{
	enum {
		pol_code,
		pol_message,
		pol_data,
	};
	struct resmon_jrpc_policy policy[] = {
		[pol_code] =    { .key = "code", .type = json_type_int,
				  .required = true },
		[pol_message] = { .key = "message", .type = json_type_string,
				  .required = true },
		[pol_data] =    { .key = "data", .any_type = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	int err = resmon_jrpc_dissect(obj, policy, values, ARRAY_SIZE(policy),
				      error);
	if (err)
		return err;

	*code = json_object_get_int64(values[pol_code]);
	*message = json_object_get_string(values[pol_message]);
	*data = values[pol_data];
	return 0;
}

int resmon_jrpc_take_send(struct resmon_sock *sock, struct json_object *obj)
{
	const char *str = json_object_to_json_string(obj);
	size_t len = strlen(str);
	int rc = sendto(sock->fd, str, len, 0,
			(struct sockaddr *) &sock->sa, sock->len);
	json_object_put(obj);
	return rc == len ? 0 : -1;
}
