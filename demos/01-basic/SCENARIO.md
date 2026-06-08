# Demo 01 — Basic triage and diff

This demo shows PORTFAN turning raw nmap XML into a prioritized triage list and
diffing two scans to surface attack-surface changes — a common authorized
pentest / blue-team workflow.

> PORTFAN never scans anything. It only analyzes nmap XML you produced yourself
> against systems you are authorized to test. No network access.

## Inputs

- `baseline.xml` — an `nmap -oX` scan of an authorized lab host. The host
  exposes SSH, an old Apache, and a cleartext Telnet service.
- `followup.xml` — a later scan of the same host: Telnet was remediated
  (closed), but Redis (unauthenticated by default) and SMB appeared.

Produce these the real way with, e.g.:

```
nmap -sV -oX baseline.xml 10.10.10.5
```

## Run it

Triage the baseline (sorted by risk score, highest first):

```
python -m portfan triage demos/01-basic/baseline.xml
python -m portfan --format json triage demos/01-basic/baseline.xml
```

Diff baseline against the follow-up scan:

```
python -m portfan diff demos/01-basic/baseline.xml demos/01-basic/followup.xml
```

## What to expect

- `triage` flags Telnet as **critical** (cleartext login) at the top, the
  end-of-life Apache 2.2 as elevated, and SSH lower down.
- `diff` reports Telnet **closed** (good) but Redis and SMB **newly open**
  (attack-surface increase) — and exits non-zero so it can gate CI/alerting.

Exit codes: `0` clean, `2` findings/new surface, `1` error.
