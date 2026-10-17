"""Sanity ceiling shared by trusted analysis-process boundaries."""
# Matches the long-task configuration contract; each call keeps its own budget.
MAX_TIMEOUT_SECONDS = 365 * 24 * 3600
