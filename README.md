# surs
> sudo alternative written in Rust
## how does surs work?
- `setuid` syscall
- the binary needs to be a. set by root and b. have the setuid bit set
- basically:
```bash
chown root:root /path/to/binary
chmod 4755
```
- the Makefile sorts this for you (but ironically uses `sudo` to do so)
## usage
- should basically just be like sudo for simple usage
- for more complex usage, try `--help`
- also note that a dev build will use `.` as the config file directory
## why would you use this
