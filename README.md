# input-multiplexer

Simple daemons providing KVM switch features on Linux using evdev.

* `controller` : Grab one or more devices and send events to one or more `controlled`
* `controlled` : Listen on a UNIX or a UDP socket and replay received events through a fake device

## Usage :
Edit `controlled.config.h` and  `controller.config.h` to suit your setup. All the constants should be easy enough to understand and documentation is provided through comments.

Use `make` to build the project. You'll need `libevdev` and `pthreads`.
