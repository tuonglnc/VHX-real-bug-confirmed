### Summary

Three `memset()` calls in `sha1.c` intended to clear sensitive cryptographic data are silently removed by the compiler under `-O1` and above. Since the target buffers are never read after the calls, the compiler's Dead Store Elimination removes them under the **as-if rule**. Raw SHA1 input blocks, intermediate hash state, and counter data persist on the stack after the functions return, exposing sensitive data to memory disclosure attacks.

Introduced by commit `e8313084` (2022-09-12). Confirmed on current master `a994a52d`.

### Details

Affected lines in `sha1.c`:

```c
// SHA1Transform() — line 202
// block holds the raw 64-byte SHA1 input copied from the caller
memset(block, '\0', sizeof(block));

// SHA1Final() — lines 287, 288
// context holds the full SHA1_CTX state (intermediate hash values)
// finalcount holds the bit-length counter
memset(context, '\0', sizeof(*context));
memset(&finalcount, '\0', sizeof(finalcount));
```

Since none of these buffers are read after the `memset()` calls, the compiler treats them as dead stores and removes them entirely. The vulnerable path is reachable via the public API `SHA1Update()`, which calls `SHA1Transform()` internally without any input validation:

```
caller → SHA1Update() → SHA1Transform() → memset() [REMOVED] → stack remnant
```

### PoC

Place `exploit.c` in the same directory as `sha1.c`:

```c
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "sha1.c"

__attribute__((noinline))
void trigger_via_SHA1Update(const unsigned char *sensitive, uint32_t len) {
    SHA1_CTX ctx;
    SHA1Init(&ctx);
    SHA1Update(&ctx, sensitive, len);
    /* memset(block) removed by -O2 → raw input remains on stack */
}

int main(void) {
    unsigned char sensitive[64];
    memset(sensitive, 0, sizeof(sensitive));
    memcpy(sensitive, "secret_password_block", 21);

    void (*volatile do_hash)(const unsigned char *, uint32_t) =
        trigger_via_SHA1Update;
    do_hash(sensitive, 64);

    uint8_t *sp;
    asm volatile("mov %%rsp, %0" : "=r"(sp));
    for (int offset = -512; offset < 0; offset++) {
        if (memcmp(sp + offset, "secret_password_block", 21) == 0) {
            printf("[!] Stack remnant found at rsp%d\n", offset);
            printf("    [str] : ");
            for (int i = 0; i < 32; i++) {
                uint8_t c = *(sp + offset + i);
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
            printf("\n");
            return 0;
        }
    }
    return 0;
}
```

Compile & run:

```bash
gcc -O2 -DBYTE_ORDER=1234 -DLITTLE_ENDIAN=1234 exploit.c -o exploit_vuln

# Step 1: verify memset removed from binary
objdump -d exploit_vuln | grep "memset"
# → (no output) — ALL memset calls removed at -O2

# Step 2: confirm stack remnant
./exploit_vuln
# → [!] Stack remnant found at rsp-352
#       [str] : secret_password_block...........
```

### Impact

An attacker with a memory read primitive (out-of-bounds read, core dump, `/proc/<pid>/mem`, swap file) can recover sensitive data — including password blocks, HMAC keys, and intermediate hash state — from the stack. Risk is elevated in long-lived server processes using libevent (e.g. nginx, memcached, Tor).

### Credit
- VulnHunterX — static analysis framework (CodeQL + LLM verification)