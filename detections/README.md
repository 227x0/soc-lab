# Custom Detections

This folder holds custom Wazuh rules developed for the home lab.

## Rule 100001 — Juice Shop admin API enumeration

- **File:** `local_rules.xml`
- **What it detects:** `GET /api/Users` in nginx `access.log`
- **Why:** the original case (SOC-2026-002) had a visibility gap: the attacker used a stolen admin JWT to dump the user database, and no built-in rule fired.
- **Test log:** `test-api-users.log`
- **Screenshot:** `screenshots/rule-100001-fire.png` (to be added after live testing)

### How to test

1. Copy `local_rules.xml` to `/var/ossec/etc/rules/local_rules.xml` on the manager.
2. Run `wazuh-control restart` (or restart the manager container).
3. Test the decoder/rule:
   ```bash
   /var/ossec/bin/wazuh-logtest < test-api-users.log
   ```
4. Trigger the request from Kali with a valid admin JWT and verify the alert appears in the dashboard.
