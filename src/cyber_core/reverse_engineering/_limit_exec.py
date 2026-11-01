"""Trusted Linux launch helper: inherited group, finite CPU and file limits."""
import math
import os
import resource
import sys

seconds = max(1, math.ceil(float(sys.argv[1])))
# RLIMIT_CPU counts CPU time summed across every thread of the process, not
# wall-clock time. A caller that intentionally runs the target multithreaded
# (e.g. OMP_NUM_THREADS=2 for a CPU OpenCL backend) would otherwise exhaust
# this limit in roughly seconds/threads of real time, killing the process
# well before its actual wall-clock budget. Scale by the same thread count
# the caller already set in this process's own environment, so no caller
# needs to pass it separately.
try:
    threads = max(1, min(64, int(os.environ.get('OMP_NUM_THREADS', '1'))))
except ValueError:
    threads = 1
cpu_seconds = seconds * threads
resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.execvpe(sys.argv[2], sys.argv[2:], os.environ)
