# LibInject

Proof-of-concept ELF binary injection into a running process.

### Demo

[![asciicast](https://asciinema.org/a/373789.svg)](https://asciinema.org/a/373789)

### Building

Make sure you have `gcc`, `make` and `cmake` installed. Then run `make`.

### Usage

```sh
sudo /<path-to-build>/inject <pid> <path-to-binary>
```

- **pid**: Process ID of the process to inject into.
- **path-to-binary**: Binary to inject into the process.

### Limitations

The binary to be injected must relocatable. You can figure this out by running:

```sh
readelf -h /bin/vim | grep "Type:"
```

If the type is `DYN` then it is relocatable. Pretty much all binaries are relocatable now due to ASLR, so this shouldn't be an issue.

### Warnings

The process that is being injected into will no longer execute the code it was originally running. If this is a critical process, your system will suffer the consequences.
