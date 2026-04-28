#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

gcc -g -fno-stack-protector -z execstack -no-pie -o hello_noprotection hello.c
gcc -g -o hello_protected hello.c

echo "built examples/hello_noprotection and examples/hello_protected"

