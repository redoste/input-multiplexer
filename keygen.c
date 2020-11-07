#include <assert.h>
#include <stdio.h>

#include <hydrogen.h>

int main(void) {
	uint8_t key[hydro_secretbox_KEYBYTES];
	assert(hydro_init() == 0);
	hydro_secretbox_keygen(key);
	fwrite(key, sizeof(key), 1, stdout);
	return 0;
}
