/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 *
 * Adopted from DPDK's telemetry V2 library:
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <dlfcn.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

/* we won't link against libbsd, so just always use DPDKs-specific strlcpy */
#undef RTE_USE_LIBBSD
#include <rte_common.h>
#include <rte_lcore.h>
#include <rte_os.h>
#include <rte_spinlock.h>
#include <rte_string_fns.h>

#include "../log/log.h"
#include "ipc.h"

#define LF_IPC_LOG(level, ...) LF_LOG(level, "IPC: " __VA_ARGS__)


#define MAX_CMD_LEN  56
#define MAX_HELP_LEN 1024

#define MAX_OUTPUT_LEN      (1024 * 16)
#define MAX_OUTPUT_INFO_LEN 1024
#define MAX_INPUT_LEN       1024

#define MAX_CONNECTIONS 10

typedef void *(*socket_handler)(void *sock_id);

static void *
client_handler(void *socket_id);

struct cmd_callback {
	char cmd[MAX_CMD_LEN];
	lf_ipc_cb fn;
	char help[MAX_HELP_LEN];
};

struct socket {
	int sock;
	char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
	socket_handler fn;
	uint16_t *num_clients;
};
static struct socket ipc_socket; /* socket for IPC */

static const char *socket_dir; /* runtime directory */

/* list of command callbacks, with one command registered by default */
static struct cmd_callback *callbacks;
static int num_callbacks; /* How many commands are registered */
/* Used when accessing or modifying list of command callbacks */
static rte_spinlock_t callback_sl = RTE_SPINLOCK_INITIALIZER;

static uint16_t ipc_client;

int
lf_ipc_register_cmd(const char *cmd, lf_ipc_cb fn, const char *help)
{
	struct cmd_callback *new_callbacks;
	int i = 0;

	if (strlen(cmd) >= MAX_CMD_LEN || fn == NULL || cmd[0] != '/' ||
			strlen(help) >= MAX_HELP_LEN) {
		return -EINVAL;
	}

	rte_spinlock_lock(&callback_sl);
	new_callbacks =
			realloc(callbacks, sizeof(callbacks[0]) * (num_callbacks + 1));
	if (new_callbacks == NULL) {
		rte_spinlock_unlock(&callback_sl);
		return -ENOMEM;
	}
	callbacks = new_callbacks;

	while (i < num_callbacks && strcmp(cmd, callbacks[i].cmd) > 0) {
		i++;
	}
	if (i != num_callbacks) {
		/* Move elements to keep the list alphabetical */
		memmove(callbacks + i + 1, callbacks + i,
				sizeof(struct cmd_callback) * (num_callbacks - i));
	}
	strlcpy(callbacks[i].cmd, cmd, MAX_CMD_LEN);
	callbacks[i].fn = fn;
	strlcpy(callbacks[i].help, help, MAX_HELP_LEN);
	num_callbacks++;
	rte_spinlock_unlock(&callback_sl);

	return 0;
}


static int
list_commands(const char *cmd __rte_unused, const char *params __rte_unused,
		char *out_buf, size_t buf_len)
{
	int i;
	int used = 0;

	rte_spinlock_lock(&callback_sl);
	for (i = 0; i < num_callbacks; i++) {
		used += snprintf(out_buf + used, buf_len - used, "%s\t",
				callbacks[i].cmd);

		/*
		rte_tel_data_add_array_string(d, callbacks[i].cmd);
		*/
	}
	rte_spinlock_unlock(&callback_sl);
	return used;
}

static int
command_help(const char *cmd __rte_unused, const char *params, char *out_buf,
		size_t buf_len)
{
	int i;
	int used = 0;

	if (!params) {
		return -1;
	}
	rte_spinlock_lock(&callback_sl);
	for (i = 0; i < num_callbacks; i++) {
		if (strcmp(params, callbacks[i].cmd) == 0) {
			used += snprintf(out_buf + used, buf_len - used, "%s: %s\n", params,
					callbacks[i].help);
			/*
			rte_tel_data_add_dict_string(d, params,
			        callbacks[i].help);
			*/
			break;
		}
	}
	rte_spinlock_unlock(&callback_sl);
	if (i == num_callbacks) {
		return -1;
	}
	return used;
}

static void
perform_command(lf_ipc_cb fn, const char *cmd, const char *param, int s)
{
	char out_buf[MAX_OUTPUT_LEN];
	int used = 0;

	used = fn(cmd, param, out_buf, sizeof(out_buf));
	if (used < 0) {
		/* error occured */
		used = snprintf(out_buf, sizeof(out_buf), "%.*s : Null", MAX_CMD_LEN,
				cmd ? cmd : "none");
		if (write(s, out_buf, used) < 0) {
			perror("Error writing to socket");
		}
		return;
	}

	if (write(s, out_buf, used) < 0) {
		perror("Error writing to socket");
	}
}

static int
unknown_command(const char *cmd __rte_unused, const char *params __rte_unused,
		char *out_buf, size_t buf_len)
{
	return snprintf(out_buf, buf_len, "unknown command");
}

static void *
client_handler(void *socket_id)
{
	int s = (int)(uintptr_t)socket_id;
	char buffer[MAX_INPUT_LEN];
	char info_str[MAX_OUTPUT_INFO_LEN];
	snprintf(info_str, sizeof(info_str),
			"{\"version\":\"%s\",\"pid\":%d,\"max_output_len\":%d}", "1",
			getpid(), MAX_OUTPUT_LEN);
	if (write(s, info_str, strlen(info_str)) < 0) {
		close(s);
		return NULL;
	}

	/* receive data is not null terminated */
	size_t bytes = read(s, buffer, sizeof(buffer) - 1);
	while (bytes > 0) {
		buffer[bytes] = 0;
		const char *cmd = strtok(buffer, ",");
		const char *param = strtok(NULL, "\0");
		lf_ipc_cb fn = unknown_command;
		int i;

		if (cmd && strlen(cmd) < MAX_CMD_LEN) {
			rte_spinlock_lock(&callback_sl);
			for (i = 0; i < num_callbacks; i++) {
				if (strcmp(cmd, callbacks[i].cmd) == 0) {
					fn = callbacks[i].fn;
					break;
				}
			}
			rte_spinlock_unlock(&callback_sl);
		}
		perform_command(fn, cmd, param, s);

		bytes = read(s, buffer, sizeof(buffer) - 1);
	}
	close(s);
	__atomic_sub_fetch(&ipc_client, 1, __ATOMIC_RELAXED);
	return NULL;
}

static void *
socket_listener(void *socket)
{
	int res;
	while (1) {
		pthread_t th;
		struct socket *s = (struct socket *)socket;
		int s_accepted = accept(s->sock, NULL, NULL);
		if (s_accepted < 0) {
			LF_IPC_LOG(ERR, "Error with accept, telemetry thread quitting\n");
			return NULL;
		}
		if (s->num_clients != NULL) {
			uint16_t conns = __atomic_load_n(s->num_clients, __ATOMIC_RELAXED);
			if (conns >= MAX_CONNECTIONS) {
				close(s_accepted);
				continue;
			}
			__atomic_add_fetch(s->num_clients, 1, __ATOMIC_RELAXED);
		}
		/* (fstreun) I have idea how to avoid this clang tidy performance
		 * warning. */
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		res = pthread_create(&th, NULL, s->fn, (void *)(uintptr_t)s_accepted);
		if (res != 0) {
			LF_IPC_LOG(ERR, "Error with create client thread: %s\n",
					strerror(res));
			close(s_accepted);
			if (s->num_clients != NULL) {
				__atomic_sub_fetch(s->num_clients, 1, __ATOMIC_RELAXED);
			}
			continue;
		}
		pthread_detach(th);
	}
	return NULL;
}

static inline char *
get_socket_path(const char *runtime_dir)
{
	static char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/lf-ipc",
			strlen(runtime_dir) ? runtime_dir : "/tmp");
	return path;
}

static void
unlink_sockets(void)
{
	if (ipc_socket.path[0]) {
		unlink(ipc_socket.path);
	}
}

static int
create_socket(char *path)
{
	int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (sock < 0) {
		LF_IPC_LOG(ERR, "Error with socket creation, %s\n", strerror(errno));
		return -1;
	}

	struct sockaddr_un sun = { .sun_family = AF_UNIX };
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));
	LF_IPC_LOG(DEBUG, "Attempting socket bind to path '%s'\n", path);

	if (bind(sock, (void *)&sun, sizeof(sun)) < 0) {
		struct stat st;

		LF_IPC_LOG(DEBUG, "Initial bind to socket '%s' failed.\n", path);

		/* first check if we have a runtime dir */
		if (stat(socket_dir, &st) < 0 || !S_ISDIR(st.st_mode)) {
			LF_IPC_LOG(ERR, "Cannot access DPDK runtime directory: %s\n",
					socket_dir);
			close(sock);
			return -ENOENT;
		}

		/* check if current socket is active */
		if (connect(sock, (void *)&sun, sizeof(sun)) == 0) {
			close(sock);
			return -EADDRINUSE;
		}

		/* socket is not active, delete and attempt rebind */
		LF_IPC_LOG(DEBUG, "Attempting unlink and retrying bind\n");
		unlink(sun.sun_path);
		if (bind(sock, (void *)&sun, sizeof(sun)) < 0) {
			LF_IPC_LOG(ERR, "Error binding socket: %s\n", strerror(errno));
			close(sock);
			return -errno; /* if unlink failed, this will be -EADDRINUSE as
			                  above */
		}
	}

	if (listen(sock, 1) < 0) {
		LF_IPC_LOG(ERR, "Error calling listen for socket: %s\n",
				strerror(errno));
		unlink(sun.sun_path);
		close(sock);
		return -errno;
	}
	LF_IPC_LOG(DEBUG, "Socket creation and binding ok\n");

	return sock;
}

/*
static void
set_thread_name(pthread_t id __rte_unused, const char *name __rte_unused)
{
#if defined RTE_EXEC_ENV_LINUX && defined __GLIBC__ && defined __GLIBC_PREREQ
#if __GLIBC_PREREQ(2, 12)
    pthread_setname_np(id, name);
#endif
#elif defined RTE_EXEC_ENV_FREEBSD
    pthread_set_name_np(id, name);
#endif
}
*/

static int
ipc_init(void)
{
	int res;
	char spath[sizeof(ipc_socket.path)];
	pthread_t t_new;
	short suffix = 0;

	ipc_socket.num_clients = &ipc_client;
	lf_ipc_register_cmd("/", list_commands,
			"Returns list of available commands, Takes no parameters");
	lf_ipc_register_cmd("/help", command_help,
			"Returns help text for a command. Parameters: string command");
	ipc_socket.fn = client_handler;
	if (strlcpy(spath, get_socket_path(socket_dir), sizeof(spath)) >=
			sizeof(spath)) {
		LF_IPC_LOG(ERR, "Error with socket binding, path too long\n");
		return -1;
	}
	memcpy(ipc_socket.path, spath, sizeof(ipc_socket.path));

	ipc_socket.sock = create_socket(ipc_socket.path);
	while (ipc_socket.sock < 0) {
		/* bail out on unexpected error, or suffix wrap-around */
		if (ipc_socket.sock != -EADDRINUSE || suffix < 0) {
			ipc_socket.path[0] = '\0'; /* clear socket path */
			return -1;
		}
		/* add a suffix to the path if the basic version fails */
		if (snprintf(ipc_socket.path, sizeof(ipc_socket.path), "%s:%d", spath,
					++suffix) >= (int)sizeof(ipc_socket.path)) {
			LF_IPC_LOG(ERR, "Error with socket binding, path too long\n");
			return -1;
		}
		ipc_socket.sock = create_socket(ipc_socket.path);
	}
	res = pthread_create(&t_new, NULL, socket_listener, &ipc_socket);
	if (res != 0) {
		LF_IPC_LOG(ERR, "Error with create socket thread: %s\n", strerror(res));
		close(ipc_socket.sock);
		ipc_socket.sock = -1;
		unlink(ipc_socket.path);
		ipc_socket.path[0] = '\0';
		return -1;
	}
	/*
	cpu_set_t cpuset = rte_lcore_cpuset(rte_get_main_lcore());
	(void)pthread_setaffinity_np(t_new, sizeof(cpuset), &cpuset);
	set_thread_name(t_new, "lf-ipc");
	*/
	pthread_detach(t_new);
	atexit(unlink_sockets);

	return 0;
}

int
lf_ipc_init(const char *runtime_dir)
{
	socket_dir = runtime_dir;

	if (ipc_init() != 0) {
		return -1;
	}

	return 0;
}
