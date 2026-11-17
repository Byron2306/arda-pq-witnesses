#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/random.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <unistd.h>

#define SEED_PATH "/gate3/boot.seed"

static int fail(const char *reason)
{
    fprintf(stderr, "GATE_3_VM_INIT=FAIL %s\n", reason);
    return 1;
}

int main(void)
{
    struct {
        int entropy_count;
        int buf_size;
        unsigned char bytes[32];
    } seed = { 256, 32, { 0 } };  /* struct rand_pool_info with a 256-bit payload */
    unsigned char probe;
    int seed_fd, random_fd, seeded;
    ssize_t seed_size;
    char *const python_args[] = { "/usr/bin/python3", "-I", "-B", "/gate3/init.py", NULL };

    if (getpid() != 1)
        return fail("guest PID 1 required");

    seed_fd = open(SEED_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (seed_fd < 0)
        return fail("boot seed unavailable");
    seed_size = read(seed_fd, seed.bytes, sizeof(seed.bytes));
    close(seed_fd);
    if (unlink(SEED_PATH) != 0 || seed_size != (ssize_t)sizeof(seed.bytes)) {
        explicit_bzero(&seed, sizeof(seed));
        return fail("boot seed invalid or could not be removed");
    }

    /* Only credit the fresh seed from the host's initialized system RNG. */
    random_fd = open("/dev/random", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    seeded = random_fd >= 0 && ioctl(random_fd, RNDADDENTROPY, &seed) == 0;
    explicit_bzero(&seed, sizeof(seed));
    if (random_fd >= 0)
        close(random_fd);
    if (!seeded || getrandom(&probe, sizeof(probe), GRND_NONBLOCK) != sizeof(probe))
        return fail("kernel RNG did not become ready");

    fputs("GATE_3_VM_ENTROPY=READY\n", stdout);
    fflush(stdout);
    execv(python_args[0], python_args);
    return fail("could not exec Python supervisor");
}
