"""Webhook receiver for GitHub PR events.
# tested-by: tests/unit/test_webhook.py

Thin HTTP server that validates HMAC-SHA256 signatures, accepts pull_request
events, and triggers caliper reviews as a side effect.
"""
