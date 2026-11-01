"""Sanity ceiling shared by trusted analysis-process boundaries."""
# Matches the long-task configuration contract; each call keeps its own budget.
MAX_TIMEOUT_SECONDS = 365 * 24 * 3600

# Input ceiling; defaults and per-task limits may be smaller.
MAX_INPUT_BYTES = 1024 * 1024 * 1024
