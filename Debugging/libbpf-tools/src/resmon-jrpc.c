#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <json-c/json_object.h>

#include "resmon.h"

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
	id_obj = NULL;

	if (resmon_jrpc_object_take_add(request, "method",
					json_object_new_string(method))) {
		fprintf(stderr, "Failed to form a request object.\n");
		goto put_request;
	}

	return request;

put_request:
	json_object_put(request);
put_id:
	json_object_put(id_obj);
	return NULL;
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

int resmon_jrpc_take_send(struct resmon_sock *sock, struct json_object *obj)
{
	const char *str = json_object_to_json_string(obj);
	size_t len = strlen(str);
	int rc = sendto(sock->fd, str, len, 0,
			(struct sockaddr *) &sock->sa, sock->len);
	json_object_put(obj);
	return rc == len ? 0 : -1;
}
