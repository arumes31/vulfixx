## 2024-06-21 - Enforce SameSite=Strict on session and CSRF cookies
**Vulnerability:** Session and CSRF cookies were configured with SameSite=Lax.
**Learning:** While SameSite=Lax provides some protection against CSRF, setting it to SameSite=Strict offers a more robust defense-in-depth approach by ensuring these cookies are only sent in a first-party context.
**Prevention:** Always configure critical security cookies (like session identifiers and CSRF tokens) with SameSite=Strict unless there is a specific, documented business requirement for cross-site cookie transmission.
