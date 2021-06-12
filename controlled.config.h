#ifndef CONTROLLED_CONFIG_H
#define CONTROLLED_CONFIG_H

#define KBRD 0x4B425244
#define MOUS 0x4D4F5553

struct device_config {
	/* WARNING : symlinks to devices are not deleted on cleanup */
	const char* device_file_link;
	const char* device_name;
	const uint32_t device_id;
	const unsigned int* enabled_event_types;
	const unsigned int* enabled_event_codes;
};

static const unsigned int mouse_event_types[] = {EV_KEY, EV_REL, -1};
static const unsigned int mouse_event_codes[] = {BTN_LEFT, BTN_RIGHT, BTN_MIDDLE, -1, REL_X, REL_Y, REL_WHEEL, -1};

static const unsigned int keyboard_event_types[] = {EV_KEY, EV_MSC, -1};
static const unsigned int keyboard_event_codes[] = {KEY_ESC,	    KEY_1,
						    KEY_2,	    KEY_3,
						    KEY_4,	    KEY_5,
						    KEY_6,	    KEY_7,
						    KEY_8,	    KEY_9,
						    KEY_0,	    KEY_MINUS,
						    KEY_EQUAL,	    KEY_BACKSPACE,
						    KEY_TAB,	    KEY_Q,
						    KEY_W,	    KEY_E,
						    KEY_R,	    KEY_T,
						    KEY_Y,	    KEY_U,
						    KEY_I,	    KEY_O,
						    KEY_P,	    KEY_LEFTBRACE,
						    KEY_RIGHTBRACE, KEY_ENTER,
						    KEY_LEFTCTRL,   KEY_A,
						    KEY_S,	    KEY_D,
						    KEY_F,	    KEY_G,
						    KEY_H,	    KEY_J,
						    KEY_K,	    KEY_L,
						    KEY_SEMICOLON,  KEY_APOSTROPHE,
						    KEY_GRAVE,	    KEY_LEFTSHIFT,
						    KEY_BACKSLASH,  KEY_Z,
						    KEY_X,	    KEY_C,
						    KEY_V,	    KEY_B,
						    KEY_N,	    KEY_M,
						    KEY_COMMA,	    KEY_DOT,
						    KEY_SLASH,	    KEY_RIGHTSHIFT,
						    KEY_KPASTERISK, KEY_LEFTALT,
						    KEY_SPACE,	    KEY_CAPSLOCK,
						    KEY_F1,	    KEY_F2,
						    KEY_F3,	    KEY_F4,
						    KEY_F5,	    KEY_F6,
						    KEY_F7,	    KEY_F8,
						    KEY_F9,	    KEY_F10,
						    KEY_NUMLOCK,    KEY_SCROLLLOCK,
						    KEY_KP7,	    KEY_KP8,
						    KEY_KP9,	    KEY_KPMINUS,
						    KEY_KP4,	    KEY_KP5,
						    KEY_KP6,	    KEY_KPPLUS,
						    KEY_KP1,	    KEY_KP2,
						    KEY_KP3,	    KEY_KP0,
						    KEY_KPDOT,	    KEY_102ND,
						    KEY_F11,	    KEY_F12,
						    KEY_KPENTER,    KEY_RIGHTCTRL,
						    KEY_KPSLASH,    KEY_SYSRQ,
						    KEY_RIGHTALT,   KEY_HOME,
						    KEY_UP,	    KEY_PAGEUP,
						    KEY_LEFT,	    KEY_RIGHT,
						    KEY_END,	    KEY_DOWN,
						    KEY_PAGEDOWN,   KEY_INSERT,
						    KEY_DELETE,	    KEY_PAUSE,
						    KEY_LEFTMETA,   KEY_RIGHTMETA,
						    KEY_COMPOSE,    -1,
						    MSC_SCAN,	    -1};

static const struct device_config devices[] = {
	{"/dev/input/inmpx-kbrd", "inmpx keyboard", KBRD, &keyboard_event_types[0], &keyboard_event_codes[0]},
	{"/dev/input/inmpx-mous", "inmpx mouse", MOUS, &mouse_event_types[0], &mouse_event_codes[0]},
};

/* Avaliable LISTEN_MODEs :
 * - LISTEN_NETWORK (UDP over IP)
 * - LISTEN_UNIX (Datagram UNIX domain socket)
 */
#define LISTEN_MODE LISTEN_NETWORK
#if defined(LISTEN_MODE) && LISTEN_MODE == LISTEN_NETWORK
static const char listen_address[] = "0.0.0.0";
static const uint16_t listen_port = 63333;
#elif defined(LISTEN_MODE) && LISTEN_MODE == LISTEN_UNIX
static const char listen_path[] = "/tmp/inmpx-controlled.socket";
static const mode_t socket_mode = 0600;
static const uid_t socket_owner = 0;
static const gid_t socket_group = 0;
#else
#error Invalid LISTEN_MODE
#endif

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

#endif
