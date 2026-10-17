"""Trusted Linux launch helper: inherited group, finite CPU and file limits."""
import math
import os
import resource
import sys

seconds = max(1, math.ceil(float(sys.argv[1])))
resource.setrlimit(resource.RLIMIT_CPU, (seconds, seconds + 1))
resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.execvpe(sys.argv[2], sys.argv[2:], os.environ)
