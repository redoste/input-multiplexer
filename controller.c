#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <hydrogen.h>
#include <libevdev/libevdev.h>

#include "controller.config.h"

struct event_message {
	uint32_t device_id;
	uint32_t event_type;
	uint32_t event_code;
	int32_t event_value;
} __attribute__((packed));

static const size_t devices_len = sizeof(devices) / sizeof(struct device_config);
static struct libevdev* devices_libev[sizeof(devices) / sizeof(struct device_config)];
static pthread_t devices_thread[sizeof(devices) / sizeof(struct device_config)];

static const size_t clients_len = sizeof(clients) / sizeof(struct client_config);
static int clients_fd[sizeof(clients) / sizeof(struct client_config)];
static struct sockaddr* clients_addr[sizeof(clients) / sizeof(struct client_config)];

static size_t current_client = 0;
static pthread_mutex_t current_client_lock = PTHREAD_MUTEX_INITIALIZER;

static int switch_modifier_state = 0;
static int switch_key_state = 0;
static const struct event_message switch_cleanup_messages[4] = {
	{switchable_device, EV_KEY, switch_key, 0},
	{switchable_device, 0, 0, 0},
	{switchable_device, EV_KEY, switch_modifier, 0},
	{switchable_device, 0, 0, 0},
};

#ifdef ENCRYPTED_CONNECTION
static uint8_t encryption_key[hydro_secretbox_KEYBYTES];
static int read_encryption_key(void) {
	FILE* file;

	file = fopen(encryption_key_path, "r");
	if (file == NULL) {
		perror("fopen");
		return -1;
	}
	if (fread(encryption_key, 1, sizeof(encryption_key), file) != hydro_secretbox_KEYBYTES) {
		if (feof(file)) {
			fprintf(stderr, "fread: EOF: key is not %d bytes long\n", hydro_secretbox_KEYBYTES);
		} else {
			perror("fread");
		}
		fclose(file);
		return -1;
	}
	fclose(file);
	return 0;
}
#endif

struct libevdev* open_device(const struct device_config* dev) {
	struct libevdev* dev_libev;
	int err;
	int fd = open(dev->device_path, O_RDWR);
	if (fd < 0) {
		perror("open");
		return NULL;
	}

	err = libevdev_new_from_fd(fd, &dev_libev);
	if (err < 0) {
		fprintf(stderr, "libevdev_new_from_fd: %s\n", strerror(-err));
		close(fd);
		return NULL;
	}

	/* The doc says :
	 * > This is generally a bad idea. Don't do this.
	 * This might be the exact reason why I'm doing it right now.
	 */
	err = libevdev_grab(dev_libev, LIBEVDEV_GRAB);
	if (err < 0) {
		fprintf(stderr, "libevdev_grab: %s\n", strerror(-err));
		libevdev_free(dev_libev);
		close(fd);
		return NULL;
	}

	return dev_libev;
}

static int open_client(const struct client_config* cli, struct sockaddr** addr_out) {
	int fd = -1;
	if (cli->listen_mode == LISTEN_NETWORK) {
		struct sockaddr_in* socket_name;

		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd < 0) {
			perror("socket");
			return -1;
		}

		socket_name = malloc(sizeof(struct sockaddr_in));
		socket_name->sin_family = AF_INET;
		socket_name->sin_port = htons(cli->port);

		if (inet_aton(cli->address, &socket_name->sin_addr) == 0) {
			fprintf(stderr, "inet_aton: Invalid address\n");
			free(socket_name);
			return -1;
		}

		*addr_out = (struct sockaddr*)socket_name;
	} else if (cli->listen_mode == LISTEN_UNIX) {
		struct sockaddr_un* socket_name;

		fd = socket(AF_UNIX, SOCK_DGRAM, 0);
		if (fd < 0) {
			perror("socket");
			return -1;
		}

		socket_name = malloc(sizeof(struct sockaddr_un));
		socket_name->sun_family = AF_UNIX;
		strncpy(socket_name->sun_path, cli->address, sizeof(socket_name->sun_path) - 1);
		*addr_out = (struct sockaddr*)socket_name;
	} else {
		/* WHAT HAVE YOU DONE ??? */
		abort();
	}
	return fd;
}

static int send_message(size_t client_index, const struct event_message* message_to_send) {
	const struct client_config* cli = &clients[client_index];
	ssize_t sent_bytes;
	size_t addrlen;
	struct event_message message_to_send_be;

	message_to_send_be.device_id = ntohl(message_to_send->device_id);
	message_to_send_be.event_code = ntohl(message_to_send->event_code);
	message_to_send_be.event_type = ntohl(message_to_send->event_type);
	message_to_send_be.event_value = ntohl(message_to_send->event_value);

#ifdef ENCRYPTED_CONNECTION
	const size_t message_len = sizeof(struct event_message) + hydro_secretbox_HEADERBYTES;
	uint8_t encrypted_message[message_len];
	hydro_secretbox_encrypt(encrypted_message, &message_to_send_be, sizeof(struct event_message),
				time(NULL) / encryption_time_divison, encryption_context, encryption_key);
	void* final_packet = encrypted_message;
#else
	const size_t message_len = sizeof(struct event_message);
	void* final_packet = &message_to_send_be;
#endif

	if (cli->listen_mode == LISTEN_NETWORK)
		addrlen = sizeof(struct sockaddr_in);
	else if (cli->listen_mode == LISTEN_UNIX)
		addrlen = sizeof(struct sockaddr_un);
	else
		abort();

	sent_bytes =
		sendto(clients_fd[client_index], final_packet, message_len, 0, clients_addr[client_index], addrlen);
	if (sent_bytes != message_len) {
		perror("sendto");
		return -1;
	}
	return 0;
}

static void switch_client(void) {
	int ret = pthread_mutex_lock(&current_client_lock);
	if (ret != 0) {
		fprintf(stderr, "pthread_mutex_lock: %s\n", strerror(ret));
		abort();
	}

	current_client = (current_client + 1) % clients_len;
	switch_modifier_state = 0;
	switch_key_state = 0;
	for (size_t i = 0; i < clients_len; i++) {
		for (size_t j = 0; j < sizeof(switch_cleanup_messages) / sizeof(struct event_message); j++) {
			send_message(i, &switch_cleanup_messages[j]);
		}
	}

	if (clients[current_client].postswitch_command) {
		ret = system(clients[current_client].postswitch_command);
		if (ret != 0)
			fprintf(stderr, "system: returned %d\n", ret);
	}

	ret = pthread_mutex_unlock(&current_client_lock);
	if (ret != 0) {
		fprintf(stderr, "pthread_mutex_unlock: %s\n", strerror(ret));
		abort();
	}
}

static void* handle_one_device_thread(void* device_index_as_void) {
	size_t device_index = (size_t)device_index_as_void;

	for (;;) {
		struct input_event ev;
		int ret = libevdev_next_event(devices_libev[device_index], LIBEVDEV_READ_FLAG_NORMAL, &ev);
		if (ret < 0) {
			fprintf(stderr, "libevdev_next_event: %s\n", strerror(-ret));
			return NULL;
		} else {
			struct event_message message_to_send = {
				.device_id = devices[device_index].device_id,
				.event_type = ev.type,
				.event_code = ev.code,
				.event_value = ev.value,
			};
			bool did_passthrough = false;
			if (ev.type == EV_KEY) {
				for (size_t i = 0; i < sizeof(passthrough_keys) / sizeof(unsigned int); i++) {
					if (passthrough_keys[i] == ev.code) {
						struct event_message sync_message = {devices[device_index].device_id, 0,
										     0, 0};
						send_message(passthrough_client, &message_to_send);
						send_message(passthrough_client, &sync_message);
						did_passthrough = true;
					}
				}
			}
			if (!did_passthrough) {
				send_message(current_client, &message_to_send);
				if (devices[device_index].device_id == switchable_device && ev.type == EV_KEY) {
					if (ev.code == switch_modifier)
						switch_modifier_state = ev.value;
					if (ev.code == switch_key)
						switch_key_state = ev.value;

					if (switch_modifier_state && switch_key_state)
						switch_client();
				}
			}
		}
	}

	return NULL;
}

static void signal_handler(int signo) {
	switch (signo) {
		case SIGINT:
		case SIGTERM:
			for (size_t i = 0; i < devices_len; i++)
				/* Quite violent but should be fine */
				pthread_kill(devices_thread[i], SIGKILL);
			break;
		default:
			break;
	}
}

int main(void) {
	size_t i;

#ifdef ENCRYPTED_CONNECTION
	if (read_encryption_key() < 0) {
		return -1;
	}
#endif

	for (i = 0; i < clients_len; i++) {
		struct sockaddr* addr;
		clients_fd[i] = open_client(&clients[i], &addr);
		if (clients_fd[i] < 0) {
			return -1;
		}
		clients_addr[i] = addr;
	}
	for (i = 0; i < devices_len; i++) {
		devices_libev[i] = open_device(&devices[i]);
		if (devices_libev[i] == NULL) {
			return -1;
		}
	}

	for (i = 0; i < devices_len; i++)
		pthread_create(&devices_thread[i], NULL, handle_one_device_thread, (void*)i);

	struct sigaction int_handler = {.sa_handler = signal_handler};
	sigaction(SIGINT, &int_handler, NULL);
	sigaction(SIGTERM, &int_handler, NULL);

	for (i = 0; i < devices_len; i++)
		pthread_join(devices_thread[i], NULL);

	/* evdev seems to release the grab by itself, let's keep it simple */
	return 0;
}
