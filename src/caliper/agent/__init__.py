"""GitHub Copilot Agent for dependency review and code review.
# tested-by: tests/unit/test_agent_main.py

Reactive PR flow: triggers on lockfile/manifest changes, evaluates packages via
the review pipeline, runs Semgrep on changed files, and posts per-package
review comments with task-fit reasoning.
"""
