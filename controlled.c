#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <hydrogen.h>
#include <libevdev/libevdev-uinput.h>
#include <libevdev/libevdev.h>

#define LISTEN_NETWORK 1
#define LISTEN_UNIX 2

#include "controlled.config.h"

struct event_message {
	uint32_t device_id;
	uint32_t event_type;
	uint32_t event_code;
	int32_t event_value;
} __attribute__((packed));

static struct libevdev_uinput* uinput_devices[sizeof(devices) / sizeof(struct device_config)];
static const size_t devices_len = sizeof(devices) / sizeof(struct device_config);
static int stop_triggered;

#ifdef ENCRYPTED_CONNECTION
static uint8_t encryption_key[hydro_secretbox_KEYBYTES];
#endif

#if defined(LISTEN_MODE) && LISTEN_MODE == LISTEN_NETWORK
static int setup_socket(void) {
	int listening_socket;
	int reuseaddr_value;
	struct sockaddr_in socket_name;

	listening_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (listening_socket < 0) {
		perror("socket");
		return -1;
	}

	reuseaddr_value = 1;
	if (setsockopt(listening_socket, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_value, sizeof(int)) < 0) {
		perror("setsockopt");
		return -1;
	}

	socket_name.sin_family = AF_INET;
	socket_name.sin_port = htons(listen_port);
	if (inet_aton(listen_address, &socket_name.sin_addr) == 0) {
		fprintf(stderr, "inet_aton: Invalid listen_address\n");
		return -1;
	}

	if (bind(listening_socket, (struct sockaddr*)&socket_name, sizeof(socket_name)) < 0) {
		perror("bind");
		return -1;
	}
	return listening_socket;
}

static int close_socket(int listening_socket) {
	if (close(listening_socket) < 0) {
		perror("close");
		return -1;
	}
	return 0;
}
#elif defined(LISTEN_MODE) && LISTEN_MODE == LISTEN_UNIX
static int setup_socket(void) {
	int listening_socket;
	struct sockaddr_un socket_name;

	listening_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (listening_socket < 0) {
		perror("socket");
		return -1;
	}

	socket_name.sun_family = AF_UNIX;
	strncpy(socket_name.sun_path, listen_path, sizeof(socket_name.sun_path) - 1);

	if (bind(listening_socket, (struct sockaddr*)&socket_name, sizeof(socket_name)) < 0) {
		perror("bind");
		return -1;
	}

	if (chmod(listen_path, socket_mode) < 0) {
		perror("chmod");
		return -1;
	}
	if (chown(listen_path, socket_owner, socket_group) < 0) {
		perror("chown");
		return -1;
	}
	return listening_socket;
}

static int close_socket(int listening_socket) {
	if (close(listening_socket) < 0) {
		perror("close");
		return -1;
	}
	if (unlink(listen_path) < 0) {
		perror("unlink");
		return -1;
	}
	return 0;
}
#endif

static struct libevdev_uinput* setup_device(const struct device_config* config) {
	int err;
	size_t event_type_i, event_code_i;
	struct libevdev* device;
	struct libevdev_uinput* uidevice;

	device = libevdev_new();
	assert(device != NULL);
	libevdev_set_name(device, config->device_name);

	event_code_i = event_type_i = 0;
	for (; config->enabled_event_types[event_type_i] != (unsigned int)-1; event_type_i++) {
		unsigned int current_event_type = config->enabled_event_types[event_type_i];
		assert(libevdev_enable_event_type(device, current_event_type) == 0);
		for (; config->enabled_event_codes[event_code_i] != (unsigned int)-1; event_code_i++) {
			unsigned int current_event_code = config->enabled_event_codes[event_code_i];
			assert(libevdev_enable_event_code(device, current_event_type, current_event_code, NULL) == 0);
		}
		/* We skip the -1 */
		event_code_i++;
	}

	err = libevdev_uinput_create_from_device(device, LIBEVDEV_UINPUT_OPEN_MANAGED, &uidevice);
	if (err < 0) {
		fprintf(stderr, "libevdev_uinput_create_from_device: %s\n", strerror(-err));
		libevdev_free(device);
		return NULL;
	}
	libevdev_free(device);

	if (config->device_file_link != NULL) {
		const char* uinput_devnode = libevdev_uinput_get_devnode(uidevice);
		assert(uinput_devnode != NULL);
		if (symlink(uinput_devnode, config->device_file_link) < 0) {
			perror("symlink");
			return NULL;
		};
	}
	return uidevice;
}

static void close_devices(void) {
	size_t i;
	for (i = 0; i < devices_len; i++) {
		if (uinput_devices[i] != NULL)
			libevdev_uinput_destroy(uinput_devices[i]);
	}
}

#ifdef ENCRYPTED_CONNECTION
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

static int recv_message(int listening_socket, struct event_message* recved_message) {
#ifdef ENCRYPTED_CONNECTION
	ssize_t read_bytes;
	uint8_t encrypted_message[sizeof(struct event_message) + hydro_secretbox_HEADERBYTES];
	read_bytes = read(listening_socket, encrypted_message, sizeof(encrypted_message));
	if (read_bytes < 0) {
		perror("read");
		return -2;
	} else if (read_bytes != sizeof(encrypted_message)) {
		fprintf(stderr, "read: EOF\n");
		return -1;
	}

	uint64_t msg_id_base = time(NULL) / encryption_time_divison;
	uint64_t msg_ids[] = {
		msg_id_base + +0,
		msg_id_base + -1,
		msg_id_base + +1,
	};
	int valid_authentication_tag = 0;
	for (size_t i = 0; i < sizeof(msg_ids) / sizeof(msg_ids[0]); i++) {
		if (hydro_secretbox_decrypt(recved_message, encrypted_message, sizeof(encrypted_message), msg_ids[i],
					    encryption_context, encryption_key) == 0) {
			valid_authentication_tag = 1;
			break;
		}
	}
	if (!valid_authentication_tag) {
		fprintf(stderr, "hydro_secretbox_decrypt: Invalid authentication tag\n");
		return -1;
	}

#else
	ssize_t read_bytes;
	read_bytes = read(listening_socket, recved_message, sizeof(struct event_message));
	if (read_bytes < 0) {
		perror("read");
		return -2;
	} else if (read_bytes != sizeof(struct event_message)) {
		fprintf(stderr, "read: EOF\n");
		return -1;
	}
#endif

	recved_message->device_id = ntohl(recved_message->device_id);
	recved_message->event_code = ntohl(recved_message->event_code);
	recved_message->event_type = ntohl(recved_message->event_type);
	recved_message->event_value = ntohl(recved_message->event_value);
	return 0;
}

static void signal_handler(int signo) {
	switch (signo) {
		case SIGINT:
		case SIGTERM:
			stop_triggered = 1;
			break;
		default:
			break;
	}
}

int main(void) {
	size_t i;
	int listening_socket;
	int ret, err;

#ifdef ENCRYPTED_CONNECTION
	if (read_encryption_key() < 0) {
		return -1;
	}
#endif

	listening_socket = setup_socket();
	if (listening_socket < 0) {
		close_socket(listening_socket);
		return -1;
	}

	for (i = 0; i < devices_len; i++) {
		uinput_devices[i] = setup_device(&devices[i]);
		if (uinput_devices[i] == NULL) {
			close_socket(listening_socket);
			close_devices();
			return -1;
		}
	}

	struct sigaction int_handler = {.sa_handler = signal_handler};
	sigaction(SIGINT, &int_handler, NULL);
	sigaction(SIGTERM, &int_handler, NULL);

	stop_triggered = 0;
	ret = 0;
	while (!stop_triggered) {
		struct event_message recved_message;
		ssize_t current_message_device_index;
		err = recv_message(listening_socket, &recved_message);
		if (err == -1) {
			continue;
		} else if (err < -1) {
			stop_triggered = 1;
			ret = -1;
			break;
		}

		for (i = 0, current_message_device_index = -1; i < devices_len; i++) {
			if (devices[i].device_id == recved_message.device_id) {
				current_message_device_index = i;
				break;
			}
		}
		if (current_message_device_index != -1) {
			err = libevdev_uinput_write_event(uinput_devices[current_message_device_index],
							  recved_message.event_type, recved_message.event_code,
							  recved_message.event_value);
			if (err < 0) {
				fprintf(stderr, "libevdev_uinput_write_event: %s\n", strerror(-err));
				stop_triggered = 1;
				ret = -1;
				break;
			}
		} else {
			fprintf(stderr,
				"main: recved message with invalid device ID : "
				"%08X\n",
				recved_message.device_id);
		}
	}

	close_devices();
	close_socket(listening_socket);
	return ret;
}
