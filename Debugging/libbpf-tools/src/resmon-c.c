// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <json-c/json_util.h>

#include "resmon.h"

static bool resmon_c_validate_id(struct json_object *id_obj, int expect_id)
{
	int64_t id = json_object_get_int64(id_obj);
	return id == expect_id;
}

static void resmon_c_handle_response_error(struct json_object *error_obj)
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

static struct json_object *resmon_c_handle_response(struct json_object *j,
						    int expect_id,
						    enum json_type result_type)
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

	if (!resmon_c_validate_id(id, expect_id)) {
		fprintf(stderr, "Unknown response ID: %s\n",
			json_object_to_json_string(id));
		return NULL;
	}

	if (is_error) {
		resmon_c_handle_response_error(result);
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

static struct json_object *resmon_c_send_request(struct json_object *request)
{
	struct json_object *response_obj = NULL;
	int err = -1;

	struct resmon_sock cli;
	struct resmon_sock peer;
	err = resmon_sock_open_c(&cli, &peer);
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
	resmon_sock_close_c(&cli);
	return response_obj;
}

int resmon_c_ping(void)
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

	struct json_object *response = resmon_c_send_request(request);
	if (response == NULL) {
		err = -1;
		goto put_request;
	}

	struct json_object *result = resmon_c_handle_response(response, id,
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

int resmon_c_stop(void)
{
	int err;

	const int id = 1;
	struct json_object *request = resmon_jrpc_new_request(id, "quit");
	if (request == NULL)
		return -1;

	struct json_object *response = resmon_c_send_request(request);
	if (response == NULL) {
		err = -1;
		goto put_request;
	}

	struct json_object *result = resmon_c_handle_response(response, id,
							    json_type_boolean);
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
