#!/usr/bin/env python3
"""Drive a prompt/response command through a PTY without echoing responses."""

import json
import os
import pty
import select
import sys


response_path, *command = sys.argv[1:]
with open(response_path, encoding="utf-8") as response_file:
    exchanges = json.load(response_file)

pid, descriptor = pty.fork()
if pid == 0:
    os.execvp(command[0], command)

output = bytearray()
try:
    for exchange in exchanges:
        prompt = exchange["prompt"].encode()
        while prompt not in output:
            readable, _, _ = select.select([descriptor], [], [], 10)
            if not readable:
                raise TimeoutError(f"prompt not seen: {exchange['prompt']}")
            chunk = os.read(descriptor, 4096)
            if not chunk:
                raise RuntimeError(f"child exited before prompt: {exchange['prompt']}")
            output.extend(chunk)
            os.write(sys.stdout.fileno(), chunk)
        os.write(descriptor, exchange["response"].encode() + b"\n")

    while True:
        readable, _, _ = select.select([descriptor], [], [], 10)
        if not readable:
            raise TimeoutError("child did not exit")
        try:
            chunk = os.read(descriptor, 4096)
        except OSError:
            break
        if not chunk:
            break
        os.write(sys.stdout.fileno(), chunk)
finally:
    os.close(descriptor)

_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
