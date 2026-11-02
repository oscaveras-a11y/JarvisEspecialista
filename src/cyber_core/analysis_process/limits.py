"""Sanity ceiling shared by trusted analysis-process boundaries."""
# Matches the long-task configuration contract; each call keeps its own budget.
MAX_TIMEOUT_SECONDS = 365 * 24 * 3600

# Input ceiling; defaults and per-task limits may be smaller. Raised from 1 GiB
# to 8 GiB at the owner's explicit request to support real firmware/program
# evidence over 5 GiB (confirmed blocking a real OpenWrt image during section-6
# testing); matches the RLIMIT_AS/run_bounded max_memory_bytes ceiling already
# used elsewhere for external-tool backends, so acquiring evidence at this size
# and then analyzing it never asks for more memory than was already sanctioned.
MAX_INPUT_BYTES = 8 * 1024 * 1024 * 1024
