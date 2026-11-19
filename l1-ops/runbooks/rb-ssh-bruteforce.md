# Runbook: SSH brute-force

## Trigger

Wazuh rule **40112** (L12) "Multiple authentication failures followed by a success",
or **5763** (L10) "sshd: brute force trying to get access".

## Triage (10 min)

1. **Confirm the pattern** in Security Events: N x failed (5760/5557/5503) -> 1 success (5501).
   Machine burst (seconds), not human typos.
2. **Source IP**: internal or external? Known scanner (CMDB/allowlist)? Lab: 192.168.100.20 = Kali.
3. **Target account**: standard or privileged? Weak password plausible?
4. **History**: any alerts on this host in the last 24h?

## Verdict

- Failures only -> recon/noise, log and watch.
- Failures -> success -> **true positive, P2**. Compromise confirmed.

## Escalate to L2 with

- rule id, timestamps, src/dst, account
- evidence: alert IDs, auth.log fragment
- requested: block src IP, force password reset, post-auth review
  (`last`, `/home/<user>/.bash_history`, new users/crons/keys)

## Contain (lab)

```bash
sudo iptables -A INPUT -p tcp -s <SRC> --dport 22 -j DROP
```

## Document

Add a line to `incident-register.csv`.
