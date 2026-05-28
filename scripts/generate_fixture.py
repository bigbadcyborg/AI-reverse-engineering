"""
Generate a synthetic JSONL fixture of 110 decompiled function records
for use in batch analysis testing.

Usage:
    python scripts/generate_fixture.py
    python scripts/generate_fixture.py --count 200 --out data/input/batch_200.jsonl

Each generated function uses a realistic decompiled C pseudocode pattern
drawn from common reverse engineering scenarios: file I/O, string operations,
cryptographic primitives, memory management, network, math, and control flow.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

# (category, template) pairs.
# {name} is replaced with the generated function name.
# {addr} is replaced with the hex address string.
PATTERNS: list[tuple[str, str, list[str], list[str]]] = [
    # (category, decompiled_template, callers_pool, callees_pool)
    (
        "file_io",
        'int {name}(char *path) {{\n  FILE *f = fopen(path, "rb");\n  if (f == 0) return -1;\n  fclose(f);\n  return 0;\n}}',
        [], ["fopen", "fclose"],
    ),
    (
        "file_io",
        'int {name}(char *path, char *buf, int len) {{\n  FILE *f = fopen(path, "r");\n  if (!f) return -1;\n  int n = (int)fread(buf, 1, len, f);\n  fclose(f);\n  return n;\n}}',
        [], ["fopen", "fread", "fclose"],
    ),
    (
        "file_io",
        'int {name}(char *path, const char *data, int len) {{\n  FILE *f = fopen(path, "wb");\n  if (!f) return -1;\n  fwrite(data, 1, len, f);\n  fclose(f);\n  return 0;\n}}',
        [], ["fopen", "fwrite", "fclose"],
    ),
    (
        "file_io",
        'long {name}(char *path) {{\n  FILE *f = fopen(path, "rb");\n  if (!f) return -1;\n  fseek(f, 0, SEEK_END);\n  long sz = ftell(f);\n  fclose(f);\n  return sz;\n}}',
        [], ["fopen", "fseek", "ftell", "fclose"],
    ),
    (
        "string_ops",
        'int {name}(const char *s) {{\n  int i = 0;\n  while (s[i] != \'\\0\') i++;\n  return i;\n}}',
        [], [],
    ),
    (
        "string_ops",
        'void {name}(char *dst, const char *src, int maxLen) {{\n  int i = 0;\n  while (i < maxLen - 1 && src[i] != \'\\0\') {{\n    dst[i] = src[i];\n    i++;\n  }}\n  dst[i] = \'\\0\';\n}}',
        [], [],
    ),
    (
        "string_ops",
        'int {name}(const char *a, const char *b) {{\n  while (*a && (*a == *b)) {{\n    a++; b++;\n  }}\n  return (unsigned char)*a - (unsigned char)*b;\n}}',
        [], [],
    ),
    (
        "string_ops",
        'char *{name}(const char *haystack, const char *needle) {{\n  int nl = 0;\n  while (needle[nl]) nl++;\n  for (int i = 0; haystack[i]; i++) {{\n    if (memcmp(haystack + i, needle, nl) == 0)\n      return (char *)(haystack + i);\n  }}\n  return 0;\n}}',
        [], ["memcmp"],
    ),
    (
        "string_ops",
        'void {name}(char *s) {{\n  int i = 0, j = 0;\n  while (s[i]) {{\n    if (s[i] != \' \') s[j++] = s[i];\n    i++;\n  }}\n  s[j] = \'\\0\';\n}}',
        [], [],
    ),
    (
        "string_ops",
        'int {name}(const char *s, char c) {{\n  int count = 0;\n  while (*s) {{\n    if (*s == c) count++;\n    s++;\n  }}\n  return count;\n}}',
        [], [],
    ),
    (
        "crypto",
        'void {name}(unsigned char *buf, int len, unsigned char key) {{\n  for (int i = 0; i < len; i++)\n    buf[i] ^= key;\n}}',
        [], [],
    ),
    (
        "crypto",
        'void {name}(unsigned char *buf, int len) {{\n  for (int i = 0; i < len; i++)\n    buf[i] = (unsigned char)((buf[i] << 4) | (buf[i] >> 4));\n}}',
        [], [],
    ),
    (
        "crypto",
        'unsigned int {name}(const unsigned char *data, int len) {{\n  unsigned int h = 0x811c9dc5;\n  for (int i = 0; i < len; i++) {{\n    h ^= data[i];\n    h *= 0x01000193;\n  }}\n  return h;\n}}',
        [], [],
    ),
    (
        "crypto",
        'void {name}(unsigned char *key, unsigned char *s) {{\n  int i, j = 0;\n  unsigned char tmp;\n  for (i = 0; i < 256; i++) s[i] = (unsigned char)i;\n  for (i = 0; i < 256; i++) {{\n    j = (j + s[i] + key[i % 16]) % 256;\n    tmp = s[i]; s[i] = s[j]; s[j] = tmp;\n  }}\n}}',
        [], [],
    ),
    (
        "crypto",
        'void {name}(unsigned char *data, int len, unsigned char *s) {{\n  int i = 0, j = 0, k;\n  unsigned char tmp;\n  for (k = 0; k < len; k++) {{\n    i = (i + 1) % 256;\n    j = (j + s[i]) % 256;\n    tmp = s[i]; s[i] = s[j]; s[j] = tmp;\n    data[k] ^= s[(s[i] + s[j]) % 256];\n  }}\n}}',
        [], [],
    ),
    (
        "memory",
        'void *{name}(int size) {{\n  void *p = malloc(size);\n  if (!p) return 0;\n  memset(p, 0, size);\n  return p;\n}}',
        [], ["malloc", "memset"],
    ),
    (
        "memory",
        'void {name}(void **ptr) {{\n  if (ptr && *ptr) {{\n    free(*ptr);\n    *ptr = 0;\n  }}\n}}',
        [], ["free"],
    ),
    (
        "memory",
        'void *{name}(const void *src, int len) {{\n  void *dst = malloc(len);\n  if (dst) memcpy(dst, src, len);\n  return dst;\n}}',
        [], ["malloc", "memcpy"],
    ),
    (
        "memory",
        'int {name}(void *ptr, int old_size, int new_size) {{\n  void *tmp = realloc(ptr, new_size);\n  if (!tmp) return -1;\n  if (new_size > old_size)\n    memset((char *)tmp + old_size, 0, new_size - old_size);\n  return 0;\n}}',
        [], ["realloc", "memset"],
    ),
    (
        "math",
        'int {name}(int a, int b) {{\n  return a > b ? a : b;\n}}',
        [], [],
    ),
    (
        "math",
        'int {name}(int a, int b) {{\n  return a < b ? a : b;\n}}',
        [], [],
    ),
    (
        "math",
        'int {name}(int n) {{\n  int result = 1;\n  for (int i = 2; i <= n; i++)\n    result *= i;\n  return result;\n}}',
        [], [],
    ),
    (
        "math",
        'unsigned int {name}(unsigned int n) {{\n  unsigned int count = 0;\n  while (n) {{\n    count += n & 1;\n    n >>= 1;\n  }}\n  return count;\n}}',
        [], [],
    ),
    (
        "math",
        'int {name}(int a, int b) {{\n  while (b != 0) {{\n    int t = b;\n    b = a % b;\n    a = t;\n  }}\n  return a;\n}}',
        [], [],
    ),
    (
        "network",
        'int {name}(int sock, const char *buf, int len) {{\n  return send(sock, buf, len, 0);\n}}',
        [], ["send"],
    ),
    (
        "network",
        'int {name}(int sock, char *buf, int len) {{\n  return recv(sock, buf, len, 0);\n}}',
        [], ["recv"],
    ),
    (
        "network",
        'int {name}(const char *host, int port) {{\n  int s = socket(AF_INET, SOCK_STREAM, 0);\n  struct sockaddr_in addr;\n  addr.sin_family = AF_INET;\n  addr.sin_port = htons(port);\n  inet_pton(AF_INET, host, &addr.sin_addr);\n  if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {{\n    close(s);\n    return -1;\n  }}\n  return s;\n}}',
        [], ["socket", "connect", "htons", "inet_pton", "close"],
    ),
    (
        "network",
        'int {name}(int port) {{\n  int s = socket(AF_INET, SOCK_STREAM, 0);\n  struct sockaddr_in addr;\n  addr.sin_family = AF_INET;\n  addr.sin_addr.s_addr = INADDR_ANY;\n  addr.sin_port = htons(port);\n  bind(s, (struct sockaddr *)&addr, sizeof(addr));\n  listen(s, 5);\n  return s;\n}}',
        [], ["socket", "bind", "listen", "htons"],
    ),
    (
        "input_validation",
        'int {name}(const char *s, int maxLen) {{\n  if (!s) return 0;\n  int n = 0;\n  while (s[n]) {{\n    if (!isprint((unsigned char)s[n])) return 0;\n    n++;\n  }}\n  return n > 0 && n <= maxLen;\n}}',
        [], ["isprint"],
    ),
    (
        "input_validation",
        'int {name}(int val, int min, int max) {{\n  return val >= min && val <= max;\n}}',
        [], [],
    ),
    (
        "input_validation",
        'int {name}(const char *s) {{\n  if (!s || !*s) return 0;\n  while (*s) {{\n    if (*s < \'0\' || *s > \'9\') return 0;\n    s++;\n  }}\n  return 1;\n}}',
        [], [],
    ),
    (
        "control_flow",
        'int {name}(const int *arr, int len, int target) {{\n  for (int i = 0; i < len; i++)\n    if (arr[i] == target) return i;\n  return -1;\n}}',
        [], [],
    ),
    (
        "control_flow",
        'void {name}(int *arr, int len) {{\n  for (int i = 0; i < len - 1; i++)\n    for (int j = 0; j < len - i - 1; j++)\n      if (arr[j] > arr[j + 1]) {{\n        int tmp = arr[j];\n        arr[j] = arr[j + 1];\n        arr[j + 1] = tmp;\n      }}\n}}',
        [], [],
    ),
    (
        "control_flow",
        'int {name}(const int *arr, int lo, int hi, int target) {{\n  while (lo <= hi) {{\n    int mid = lo + (hi - lo) / 2;\n    if (arr[mid] == target) return mid;\n    if (arr[mid] < target) lo = mid + 1;\n    else hi = mid - 1;\n  }}\n  return -1;\n}}',
        [], [],
    ),
    (
        "error_handling",
        'void {name}(int code, const char *msg) {{\n  fprintf(stderr, "Error %d: %s\\n", code, msg);\n  exit(code);\n}}',
        [], ["fprintf", "exit"],
    ),
    (
        "error_handling",
        'const char *{name}(int code) {{\n  switch (code) {{\n    case 0: return "OK";\n    case 1: return "Invalid argument";\n    case 2: return "Out of memory";\n    case 3: return "File not found";\n    default: return "Unknown error";\n  }}\n}}',
        [], [],
    ),
    (
        "process",
        'int {name}(const char *cmd) {{\n  return system(cmd);\n}}',
        [], ["system"],
    ),
    (
        "process",
        'int {name}(const char *path, char *const argv[]) {{\n  pid_t pid = fork();\n  if (pid == 0) {{\n    execv(path, argv);\n    exit(1);\n  }}\n  int status;\n  waitpid(pid, &status, 0);\n  return WEXITSTATUS(status);\n}}',
        [], ["fork", "execv", "exit", "waitpid"],
    ),
]


def generate(count: int, seed: int = 42) -> list[dict]:
    rng = random.Random(seed)
    records = []
    base_addr = 0x00101000

    for i in range(count):
        addr = base_addr + i * 0x60
        fn_name = f"FUN_{addr:08x}"
        addr_str = f"0x{addr:08x}"

        category, template, callers_pool, callees_pool = PATTERNS[i % len(PATTERNS)]
        decompiled = template.format(name=fn_name, addr=addr_str)

        record: dict = {
            "functionName": fn_name,
            "entryPoint": addr_str,
            "decompiledCode": decompiled,
        }

        # Sprinkle optional metadata on ~60% of records
        if rng.random() < 0.6:
            if callees_pool:
                record["callees"] = rng.sample(callees_pool, k=min(len(callees_pool), rng.randint(1, 3)))
            # Build callers from previously generated function names
            if i > 0 and rng.random() < 0.5:
                caller_idx = rng.randint(max(0, i - 5), i - 1)
                record["callers"] = [f"FUN_{(base_addr + caller_idx * 0x60):08x}"]

        records.append(record)

    return records


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a JSONL fixture of synthetic decompiled functions")
    parser.add_argument("--count", type=int, default=110, help="Number of functions to generate (default: 110)")
    parser.add_argument("--out", default="data/input/batch_100.jsonl", help="Output JSONL path")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    args = parser.parse_args()

    records = generate(args.count, args.seed)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"Generated {len(records)} function records -> {out}")


if __name__ == "__main__":
    main()
