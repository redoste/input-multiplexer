#ifndef CONTROLLER_CONFIG_H
#define CONTROLLER_CONFIG_H

#define KBRD 0x4B425244
#define MOUS 0x4D4F5553

struct device_config {
	const char* device_path;
	const uint32_t device_id;
};

struct client_config {
	const char* address;
	const uint16_t port;
	const enum { LISTEN_UNIX, LISTEN_NETWORK } listen_mode;
	const char* postswitch_command;
};

static const struct client_config clients[] = {
	{"127.0.0.1", 63333, LISTEN_NETWORK, "ddcutil --bus=2 setvcp 60 0x0F"},
	{"/tmp/inmpx-controlled.socket", 0, LISTEN_UNIX, "ddcutil --bus=2 setvcp 60 0x11"},
};

/* The controller will cycle through clients when switch_modifier and switch_key are pressed on device with id
 * switchable_device */
static const uint32_t switchable_device = KBRD;
static const unsigned int switch_modifier = KEY_RIGHTCTRL;
static const unsigned int switch_key = KEY_SCROLLLOCK;

/* These keys will be sent to clients[passthrough_client] regardless of the currently selected client */
static const unsigned int passthrough_keys[] = {KEY_RIGHTMETA};
static const size_t passthrough_client = 0;

static const struct device_config devices[] = {
	{"/dev/input/by-path/platform-i8042-serio-0-event-kbd", KBRD},
	{"/dev/input/by-path/platform-i8042-serio-1-event-mouse", MOUS},
};

/* Comment / Uncomment this line to enable encrytion
 * It is heavely recommanded to enable it over UDP overwise everyone on the same network can easly read your events or
 * inject fake ones since this encryption is also used as an authentication method */
#define ENCRYPTED_CONNECTION
#ifdef ENCRYPTED_CONNECTION
/* You can generate a key using the `keygen` tool available in the repository */
static const char encryption_key_path[] = "./key";
static const char encryption_context[hydro_secretbox_CONTEXTBYTES] = "!INMPX!";

/* Current timestamp is divided by encryption_time_divison before being used as a message_id. The client will accept the
 * current message_id, the next one and the previous one, thus setting it to 1 will allow a window beetween 1 and 3
 * seconds for a message to be received. (see recv_message in controlled.c for more informations).  It's recommended to
 * keep this value as low as possible to prevent a malicious party from replaying an event.
 *
 * TL;DR : set this value to the lowest value you can, if you've some network issues producing "Invalid
 * authentication tag" errors, try increasing it but keep it under 3 to be safe.
 */
static const unsigned int encryption_time_divison = 1;
#endif

/* Comment / Uncomment this line to use read(2) instead of libevdev_next_event
 * I have encountered some issues with libevdev_next_event on some devices. Not all the events were being dispatched.
 * Prefer enabling this flag only if you notice this kind of problem beacause going through libevdev is the recommanded
 * way.
 */
// #define DONT_USE_LIBEVDEV_FOR_READING

#endif
