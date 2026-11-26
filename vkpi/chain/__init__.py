"""The measuring chain of venslabs/vens#310 step 4: it reads what vens published, per attempt, in both arms.

The before is vens `main`, which rates a CVE with four aggregates copied into its OWASP vector; the after is
`310-step3`, which publishes 16 levels, L x max(T, B) and OWASP's severity matrix, and writes `answers.json`.
"""
