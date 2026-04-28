# Remote Debug Example: Windows gdb-mcp -> VM gdbserver

## Architecture

Windows Codex
-> Windows gdb-mcp
-> Windows GDB
-> VM gdbserver
-> VM target process

## VM side

```bash
sudo apt update
sudo apt install -y gdbserver gcc
cd /home/kali/ctf
gcc -g -fno-stack-protector -no-pie -o pwn pwn.c
gdbserver 0.0.0.0:1234 ./pwn
```

## Windows side

```powershell
ping 192.168.56.101
Test-NetConnection 192.168.56.101 -Port 1234
```

## Codex instruction

```text
Use gdb-mcp to start GDB, load local binary E:/ctf/pwn/pwn, connect to gdbserver at 192.168.56.101:1234 using target remote, set a breakpoint at main, continue execution, then show registers, stack, disassembly near RIP, and backtrace.
```

## Equivalent GDB commands

```gdb
file "E:/ctf/pwn/pwn"
target remote 192.168.56.101:1234
b main
c
info registers
x/20gx $rsp
x/20i $rip
bt
```

## Extended remote mode

VM:

```bash
gdbserver --multi 0.0.0.0:1234
```

GDB:

```gdb
file "E:/ctf/pwn/pwn"
set remote exec-file /home/kali/ctf/pwn
target extended-remote 192.168.56.101:1234
b main
run
info registers
x/20gx $rsp
x/20i $rip
bt
```
