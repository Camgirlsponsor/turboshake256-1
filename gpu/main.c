#define _POSIX_C_SOURCE 200809L
#define CL_TARGET_OPENCL_VERSION 120

#include <CL/cl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dfpow_gpu.cl"

static const char *ACCENT[8] = {"XOR", "ADD", "ROT", "MUL", "SBOX", "XORROT", "ADDROT", "MIX"};

static int nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static void print_hex(const u8 *p, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        printf("%02x", p[i]);
    }
}

static int hex_eq(const u8 *got, size_t n, const char *hex) {
    size_t i;
    for (i = 0; i < n; i++) {
        int hi = nibble(hex[i * 2]);
        int lo = nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0 || got[i] != (u8)((hi << 4) | lo)) {
            return 0;
        }
    }
    return 1;
}

static int expect_hex(const char *name, const u8 *got, size_t n, const char *want) {
    if (hex_eq(got, n, want)) {
        printf("  %-22s ok\n", name);
        return 0;
    }
    printf("  %-22s FAIL\n    got  ", name);
    print_hex(got, n);
    printf("\n    want %s\n", want);
    return 1;
}

static double seconds_since(const struct timespec *start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)(now.tv_sec - start->tv_sec) + (double)(now.tv_nsec - start->tv_nsec) / 1e9;
}

static void test_header(u8 chain[16], u8 epoch[32], u8 prefix[76], u32 difficulty) {
    u8 prev[32];
    u8 merkle[32];
    int i;
    memset(chain, 0, 16);
    memcpy(chain, "dfpow-test-v0.1", 15);
    for (i = 0; i < 32; i++) {
        epoch[i] = (u8)i;
        prev[i] = 0;
        merkle[i] = 0x11;
    }
    dfpow_make_prefix(prefix, 1u, prev, merkle, 1700000000u, difficulty);
}

static int build_dataset(const u8 chain[16], const u8 epoch[32], u32 *dataset) {
    u8 pre[76];
    u8 *raw = (u8 *)malloc(DFPOW_DATASET_BYTES);
    if (raw == NULL) {
        return -1;
    }
    dfpow_dataset_preimage(chain, epoch, pre);
    dfpow_blake3_xof(pre, 76u, raw, DFPOW_DATASET_BYTES);
    dfpow_expand_dataset(dataset, raw, epoch);
    free(raw);
    return 0;
}

static int host_checks(const u32 *dataset) {
    u8 chain[16], epoch[32], prefix[76], digest[32], seed[32], opening[8];
    u32 addr = 0;
    int fails = 0;
    u8 tmp[128];
    u8 pre[76];
    u8 *raw;
    static const u8 open1000[8] = {0, 5, 6, 3, 2, 1, 7, 4};
    struct timespec start;
    int i;
    const int bench_n = 64;

    memset(tmp, 0, sizeof tmp);
    dfpow_blake3_xof(tmp, 0, digest, 32);
    fails += expect_hex("blake3 empty", digest, 32,
                        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
    tmp[0] = 'a';
    tmp[1] = 'b';
    tmp[2] = 'c';
    dfpow_blake3_xof(tmp, 3, digest, 32);
    fails += expect_hex("blake3 abc", digest, 32,
                        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");
    dfpow_blake3_xof(tmp, 3, tmp, 100);
    fails += expect_hex(
        "blake3 abc xof100", tmp, 100,
        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        "1fb250ae7393f5d02813b65d521a0d492d9ba09cf7ce7f4cffd900f23374bf0b"
        "c08a1fb0b38ed276181ccbd9f7b7edbddf9f86404ad7929605f6ffa3fb1ac879"
        "83105f01");

    memset(tmp, 'a', 128);
    dfpow_blake3_xof(tmp, 64, digest, 32);
    fails += expect_hex("blake3 a*64", digest, 32,
                        "472c51290d607f100d2036fdcedd7590bba245e9adeb21364a063b7bb4ca81c7");
    dfpow_blake3_xof(tmp, 65, digest, 32);
    fails += expect_hex("blake3 a*65", digest, 32,
                        "f345679d9055e53939e92c04ff4f6c9d824b849810d4b598f54baa23336cde99");
    dfpow_blake3_xof(tmp, 128, digest, 32);
    fails += expect_hex("blake3 a*128", digest, 32,
                        "0753df896d00f20c247f7e8c8977bb84d42f57532a5cc30d8f2ea035c9ce5757");

    {
        u8 *chunk = (u8 *)malloc(1024);
        if (chunk == NULL) {
            return 1;
        }
        memset(chunk, 'a', 1024);
        dfpow_blake3_xof(chunk, 1024, digest, 32);
        fails += expect_hex("blake3 a*1024", digest, 32,
                            "5a1c9e5d85d9898297037e8e24f69bb0e604a84c91c3b3ef4784a374812900d9");
        free(chunk);
    }

    test_header(chain, epoch, prefix, 20u);
    dfpow_dataset_preimage(chain, epoch, pre);
    {
        u8 first64[64];
        dfpow_blake3_xof(pre, 76, first64, 64);
        fails += expect_hex(
            "dataset xof first64", first64, 64,
            "516a378312e5d82022e8369b73152d388ca09bd01c5f47bdb23f36d828e6c470"
            "ade9abc386610a662a7aec9ead7893e0452fe949b8f5961c34977fdf0632acdb");
    }
    raw = (u8 *)malloc(DFPOW_DATASET_BYTES);
    if (raw == NULL) {
        return 1;
    }
    dfpow_blake3_xof(pre, 76, raw, DFPOW_DATASET_BYTES);
    fails += expect_hex("dataset xof last16", raw + DFPOW_DATASET_BYTES - 16, 16,
                        "967f08d18215284c63385da5d4d0b14e");
    free(raw);

    dfpow_eval(dataset, chain, epoch, prefix, 1000ull, digest, seed, &addr, opening);
    fails += expect_hex("nonce 1000 seed", seed, 32,
                        "2c2c49235865dacb38705af9f0aac7153f981861580369b144db23ec785ae7cb");
    fails += expect_hex("nonce 1000 digest", digest, 32,
                        "747c88f9f23c23a9636cfdc88e452c99e804905acd587a2b7e9bfcb3e7850640");
    if (addr != 1106646132u) {
        printf("  nonce 1000 addr        FAIL got %u\n", addr);
        fails++;
    } else {
        printf("  %-22s ok\n", "nonce 1000 addr");
    }
    printf("  nonce 1000 schedule   ");
    for (i = 0; i < 8; i++) {
        printf(" %s", ACCENT[opening[i] & 7u]);
    }
    if (memcmp(opening, open1000, 8) != 0) {
        printf("  FAIL\n");
        fails++;
    } else {
        printf("  ok\n");
    }

    dfpow_eval(dataset, chain, epoch, prefix, 1001ull, digest, seed, &addr, opening);
    fails += expect_hex("nonce 1001 digest", digest, 32,
                        "6408cb97b29fd2ca8ac52af08b806253af719d453fd866c2b5efb4b0b07c28cc");
    dfpow_eval(dataset, chain, epoch, prefix, 1002ull, digest, seed, &addr, opening);
    fails += expect_hex("nonce 1002 digest", digest, 32,
                        "d4865810f4e3f2ca79fac49ce4357efd97c146167b13154a893defc27387607b");
    dfpow_eval(dataset, chain, epoch, prefix, 1003ull, digest, seed, &addr, opening);
    fails += expect_hex("nonce 1003 digest", digest, 32,
                        "d3eb33b96d1e81ef15cabb4e3424173fc3e54799f93c85427d2f106988e5a38a");

    test_header(chain, epoch, prefix, 8u);
    dfpow_eval(dataset, chain, epoch, prefix, 37ull, digest, seed, &addr, opening);
    fails += expect_hex("difficulty 8 nonce 37", digest, 32,
                        "00a02a44532a21a5adc26d4a7041a0b7d28de0c222b55910f0c051fc34e3e978");

    test_header(chain, epoch, prefix, 20u);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (i = 0; i < bench_n; i++) {
        dfpow_eval(dataset, chain, epoch, prefix, 1000ull + (u64)i, digest, seed, &addr, opening);
    }
    {
        double dt = seconds_since(&start);
        printf("  host %-17s %d hashes in %.2f ms, %.0f H/s\n", "throughput", bench_n, dt * 1e3,
               dt > 0 ? (double)bench_n / dt : 0);
    }
    return fails;
}

static int check_cl(cl_int err, const char *what) {
    if (err == CL_SUCCESS) {
        return 0;
    }
    fprintf(stderr, "opencl: %s failed (%d)\n", what, err);
    return 1;
}

static char *kernel_source(size_t *out_len) {
    char exe[4096];
    char path[4200];
    ssize_t n;
    FILE *f;
    long sz;
    char *buf;
    char *slash;

    n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n < 0) {
        fprintf(stderr, "opencl: cannot locate the kernel source\n");
        return NULL;
    }
    exe[n] = 0;
    slash = strrchr(exe, '/');
    if (slash == NULL) {
        fprintf(stderr, "opencl: cannot locate the kernel source\n");
        return NULL;
    }
    slash[1] = 0;
    snprintf(path, sizeof path, "%sdfpow_gpu.cl", exe);
    f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "opencl: cannot read %s\n", path);
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    buf = (char *)malloc((size_t)sz + 1);
    if (buf == NULL || fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    buf[sz] = 0;
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

static int pick_device(cl_platform_id *platform, cl_device_id *device, int *is_gpu) {
    cl_uint nplat = 0;
    cl_platform_id *plats;
    cl_uint i;
    int pass;
    if (clGetPlatformIDs(0, NULL, &nplat) != CL_SUCCESS || nplat == 0) {
        fprintf(stderr, "opencl: no platform\n");
        return -1;
    }
    plats = (cl_platform_id *)calloc(nplat, sizeof *plats);
    if (plats == NULL || clGetPlatformIDs(nplat, plats, NULL) != CL_SUCCESS) {
        free(plats);
        return -1;
    }
    for (pass = 0; pass < 2; pass++) {
        cl_device_type want = pass == 0 ? CL_DEVICE_TYPE_GPU : CL_DEVICE_TYPE_CPU;
        for (i = 0; i < nplat; i++) {
            cl_uint nd = 0;
            if (clGetDeviceIDs(plats[i], want, 1, device, &nd) == CL_SUCCESS && nd > 0) {
                *platform = plats[i];
                *is_gpu = pass == 0;
                free(plats);
                return 0;
            }
        }
    }
    free(plats);
    fprintf(stderr, "opencl: no device\n");
    return -1;
}

static int run_batch(cl_command_queue queue, cl_kernel kernel, cl_mem prefix_buf, cl_mem digest_buf,
                     const u8 *prefix, u64 start, size_t count, u8 *digests, double *device_s) {
    cl_int err;
    cl_event event;
    cl_ulong t0 = 0, t1 = 0;
    err = clEnqueueWriteBuffer(queue, prefix_buf, CL_TRUE, 0, 76, prefix, 0, NULL, NULL);
    if (check_cl(err, "write prefix")) {
        return -1;
    }
    err = clSetKernelArg(kernel, 3, sizeof(cl_mem), &prefix_buf);
    err |= clSetKernelArg(kernel, 4, sizeof(cl_ulong), &start);
    err |= clSetKernelArg(kernel, 5, sizeof(cl_mem), &digest_buf);
    if (check_cl(err, "set args")) {
        return -1;
    }
    err = clEnqueueNDRangeKernel(queue, kernel, 1, NULL, &count, NULL, 0, NULL, &event);
    if (check_cl(err, "enqueue")) {
        return -1;
    }
    err = clWaitForEvents(1, &event);
    if (check_cl(err, "wait")) {
        clReleaseEvent(event);
        return -1;
    }
    clGetEventProfilingInfo(event, CL_PROFILING_COMMAND_START, sizeof t0, &t0, NULL);
    clGetEventProfilingInfo(event, CL_PROFILING_COMMAND_END, sizeof t1, &t1, NULL);
    clReleaseEvent(event);
    if (device_s != NULL && t1 > t0) {
        *device_s = (double)(t1 - t0) / 1e9;
    }
    err = clEnqueueReadBuffer(queue, digest_buf, CL_TRUE, 0, count * 32u, digests, 0, NULL, NULL);
    if (check_cl(err, "read digests")) {
        return -1;
    }
    return 0;
}

static int opencl_checks(const u32 *dataset, const u8 chain[16], const u8 epoch[32], int bench_n) {
    cl_platform_id platform;
    cl_device_id device;
    cl_context ctx;
    cl_command_queue queue;
    cl_program program;
    cl_kernel kernel;
    cl_mem dataset_buf, chain_buf, epoch_buf, prefix_buf, digest_buf;
    cl_int err = 0;
    int is_gpu = 0;
    int fails = 0;
    char name[256];
    char pname[256];
    char *source;
    size_t source_len = 0;
    u8 prefix[76];
    u8 chain_local[16], epoch_local[32];
    u8 *digests;
    size_t max_count;
    cl_uint units = 0;
    const char *build_opts = "-cl-std=CL1.2";
    double device_s = 0;

    if (pick_device(&platform, &device, &is_gpu) != 0) {
        return 1;
    }
    clGetPlatformInfo(platform, CL_PLATFORM_NAME, sizeof pname, pname, NULL);
    clGetDeviceInfo(device, CL_DEVICE_NAME, sizeof name, name, NULL);
    clGetDeviceInfo(device, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof units, &units, NULL);
    printf("  device                 %s / %s (%s, %u compute units)\n", pname, name,
           is_gpu ? "GPU" : "CPU", units);

    source = kernel_source(&source_len);
    if (source == NULL) {
        return 1;
    }
    ctx = clCreateContext(NULL, 1, &device, NULL, NULL, &err);
    if (check_cl(err, "context")) {
        free(source);
        return 1;
    }
    queue = clCreateCommandQueue(ctx, device, CL_QUEUE_PROFILING_ENABLE, &err);
    if (check_cl(err, "queue")) {
        clReleaseContext(ctx);
        free(source);
        return 1;
    }
    program = clCreateProgramWithSource(ctx, 1, (const char **)&source, &source_len, &err);
    free(source);
    if (check_cl(err, "program")) {
        clReleaseCommandQueue(queue);
        clReleaseContext(ctx);
        return 1;
    }
    err = clBuildProgram(program, 1, &device, build_opts, NULL, NULL);
    if (err != CL_SUCCESS) {
        size_t log_size = 0;
        char *log;
        clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_size);
        log = (char *)malloc(log_size + 1);
        if (log != NULL && log_size > 0) {
            clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, log_size, log, NULL);
            log[log_size] = 0;
            fprintf(stderr, "%s\n", log);
        }
        free(log);
        check_cl(err, "build");
        clReleaseProgram(program);
        clReleaseCommandQueue(queue);
        clReleaseContext(ctx);
        return 1;
    }
    kernel = clCreateKernel(program, "dfpow_batch", &err);
    if (check_cl(err, "kernel")) {
        clReleaseProgram(program);
        clReleaseCommandQueue(queue);
        clReleaseContext(ctx);
        return 1;
    }

    max_count = (size_t)bench_n;
    if (max_count < 4) {
        max_count = 4;
    }
    digests = (u8 *)malloc(max_count * 32u);
    if (digests == NULL) {
        clReleaseKernel(kernel);
        clReleaseProgram(program);
        clReleaseCommandQueue(queue);
        clReleaseContext(ctx);
        return 1;
    }
    dataset_buf = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                 DFPOW_DATASET_WORDS * sizeof(u32), (void *)dataset, &err);
    chain_buf = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 16, (void *)chain, &err);
    epoch_buf = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 32, (void *)epoch, &err);
    prefix_buf = clCreateBuffer(ctx, CL_MEM_READ_ONLY, 76, NULL, &err);
    digest_buf = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, max_count * 32u, NULL, &err);
    if (check_cl(err, "buffers")) {
        free(digests);
        return 1;
    }
    err = clSetKernelArg(kernel, 0, sizeof(cl_mem), &dataset_buf);
    err |= clSetKernelArg(kernel, 1, sizeof(cl_mem), &chain_buf);
    err |= clSetKernelArg(kernel, 2, sizeof(cl_mem), &epoch_buf);
    if (check_cl(err, "fixed args")) {
        free(digests);
        return 1;
    }

    test_header(chain_local, epoch_local, prefix, 20u);
    if (run_batch(queue, kernel, prefix_buf, digest_buf, prefix, 1000ull, 4, digests, NULL) != 0) {
        fails++;
    } else {
        fails += expect_hex("opencl nonce 1000", digests, 32,
                            "747c88f9f23c23a9636cfdc88e452c99e804905acd587a2b7e9bfcb3e7850640");
        fails += expect_hex("opencl nonce 1001", digests + 32, 32,
                            "6408cb97b29fd2ca8ac52af08b806253af719d453fd866c2b5efb4b0b07c28cc");
        fails += expect_hex("opencl nonce 1002", digests + 64, 32,
                            "d4865810f4e3f2ca79fac49ce4357efd97c146167b13154a893defc27387607b");
        fails += expect_hex("opencl nonce 1003", digests + 96, 32,
                            "d3eb33b96d1e81ef15cabb4e3424173fc3e54799f93c85427d2f106988e5a38a");
    }

    test_header(chain_local, epoch_local, prefix, 8u);
    if (run_batch(queue, kernel, prefix_buf, digest_buf, prefix, 37ull, 1, digests, NULL) != 0) {
        fails++;
    } else {
        fails += expect_hex("opencl nonce 37", digests, 32,
                            "00a02a44532a21a5adc26d4a7041a0b7d28de0c222b55910f0c051fc34e3e978");
    }

    test_header(chain_local, epoch_local, prefix, 20u);
    if (run_batch(queue, kernel, prefix_buf, digest_buf, prefix, 1000ull, (size_t)bench_n, digests,
                  &device_s) != 0) {
        fails++;
    } else {
        fails += expect_hex("bench nonce 1000", digests, 32,
                            "747c88f9f23c23a9636cfdc88e452c99e804905acd587a2b7e9bfcb3e7850640");
        if ((size_t)bench_n > 3) {
            fails += expect_hex("bench nonce 1003", digests + 96, 32,
                                "d3eb33b96d1e81ef15cabb4e3424173fc3e54799f93c85427d2f106988e5a38a");
        }
        printf("  opencl %-15s %d hashes in %.2f ms, %.0f H/s\n", "throughput", bench_n, device_s * 1e3,
               device_s > 0 ? (double)bench_n / device_s : 0);
    }

    clReleaseMemObject(dataset_buf);
    clReleaseMemObject(chain_buf);
    clReleaseMemObject(epoch_buf);
    clReleaseMemObject(prefix_buf);
    clReleaseMemObject(digest_buf);
    free(digests);
    clReleaseKernel(kernel);
    clReleaseProgram(program);
    clReleaseCommandQueue(queue);
    clReleaseContext(ctx);
    return fails;
}

static void usage(void) {
    fprintf(stderr,
            "usage: dfpow-gpu [all|selftest|bench N]\n"
            "  all       host vectors, then the OpenCL kernel (default)\n"
            "  selftest  host C only\n"
            "  bench N   hash N consecutive nonces on the OpenCL device\n");
}

int main(int argc, char **argv) {
    const char *cmd = (argc > 1) ? argv[1] : "all";
    int bench_n = 256;
    int do_host = 1;
    int do_cl = 1;
    u32 *dataset;
    u8 chain[16], epoch[32], prefix[76];
    int fails;

    if (strcmp(cmd, "selftest") == 0) {
        do_cl = 0;
    } else if (strcmp(cmd, "bench") == 0) {
        do_host = 0;
        if (argc > 2) {
            bench_n = atoi(argv[2]);
        }
    } else if (strcmp(cmd, "all") == 0) {
        if (argc > 2) {
            bench_n = atoi(argv[2]);
        }
    } else if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        usage();
        return 0;
    } else {
        usage();
        return 2;
    }
    if (bench_n < 4) {
        bench_n = 4;
    }
    if (bench_n > (1 << 20)) {
        bench_n = 1 << 20;
    }

    dataset = (u32 *)malloc(DFPOW_DATASET_WORDS * sizeof(u32));
    if (dataset == NULL) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    test_header(chain, epoch, prefix, 20u);
    printf("building epoch dataset\n");
    if (build_dataset(chain, epoch, dataset) != 0) {
        fprintf(stderr, "dataset build failed\n");
        free(dataset);
        return 1;
    }
    fails = 0;
    if (do_host) {
        printf("host\n");
        fails += host_checks(dataset);
    }
    if (fails == 0 && do_cl) {
        printf("opencl\n");
        fails += opencl_checks(dataset, chain, epoch, bench_n);
    }
    free(dataset);
    if (fails != 0) {
        printf("%d check(s) failed\n", fails);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
