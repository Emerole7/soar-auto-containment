#!/usr/bin/env python3
"""
SOAR containment relay.

Polls the 3B containment queue for approved "Block IP" decisions and adds each
IP to the FortiGate address group SOAR-Blocklist through the REST API. Reports
the result back to 3B, which updates Slack and records time to contain.

Runs on the analyst Mac inside the lab network, so nothing in the lab has to
accept inbound connections from the internet.

Config (never committed, kept in private/):
  private/fortigate.env  FGT_URL, FGT_TOKEN
  private/relay.env      QUEUE_URL   (3B /containment-queue URL incl. external_id)

Usage:
  python3 scripts/soar_relay.py            # poll every 10 s
  python3 scripts/soar_relay.py --once     # one poll, then exit
  python3 scripts/soar_relay.py --dry-run  # show what would be blocked, change nothing
"""
import argparse
import ipaddress
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GROUP = "SOAR-Blocklist"
POLL_SECONDS = 10

# Never block these, whatever the queue says. A compromised or buggy queue must
# not be able to cut off the analyst, the firewall or the server being protected.
PROTECTED = {
    ipaddress.ip_address("10.10.10.1"),    # analyst Mac / relay host
    ipaddress.ip_address("10.10.10.254"),  # FortiGate LAN gateway
    ipaddress.ip_address("10.10.20.10"),   # DMZ web server
}


def load_env(path):
    if not path.exists():
        sys.exit(f"missing {path}")
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def log(msg):
    print(f"{now()}  {msg}", flush=True)


def http(method, url, body=None, headers=None, insecure=False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            raw = r.read().decode() or "{}"
            return r.status, json.loads(raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode() or "{}"
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"raw": raw[:200]}


class FortiGate:
    def __init__(self, url, token):
        self.url = url.rstrip("/")
        self.h = {"Authorization": f"Bearer {token}"}

    def _call(self, method, path, body=None):
        # Lab FortiGate uses its factory self-signed certificate. In production,
        # install a trusted cert and drop insecure=True.
        return http(method, f"{self.url}/api/v2/cmdb/{path}", body, self.h, insecure=True)

    def members(self):
        code, j = self._call("GET", f"firewall/addrgrp/{GROUP}")
        if code != 200:
            raise RuntimeError(f"read {GROUP}: HTTP {code} {j.get('error', '')}")
        return {m["name"] for m in j["results"][0]["member"]}

    def block(self, ip):
        name = f"SOAR-{ip}"
        code, j = self._call("POST", "firewall/address", {
            "name": name,
            "subnet": f"{ip} 255.255.255.255",
            "comment": f"Added by SOAR relay {now()}",
        })
        # -5 = entry already exists, which is fine (idempotent re-run)
        if code != 200 and j.get("error") != -5:
            raise RuntimeError(f"create address: HTTP {code} {j.get('error', '')}")
        if name not in self.members():
            code, j = self._call("POST", f"firewall/addrgrp/{GROUP}/member", {"name": name})
            if code != 200 and j.get("error") != -5:
                raise RuntimeError(f"add to group: HTTP {code} {j.get('error', '')}")
        if name not in self.members():
            raise RuntimeError("verification failed: address not in group after update")
        return name


def validate(ip_text):
    ip = ipaddress.ip_address(ip_text)  # raises ValueError on junk
    if ip.version != 4:
        raise ValueError("IPv4 only")
    if ip in PROTECTED:
        raise ValueError("protected address, refusing to block")
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        raise ValueError("non-routable address")
    return str(ip)


def poll(queue_url, fgt, dry_run):
    code, j = http("GET", queue_url)
    if code != 200:
        log(f"queue read failed: HTTP {code}")
        return
    jobs = j.get("jobs", [])
    if not jobs:
        return
    for job in jobs:
        job_id = job.get("job_id")
        try:
            ip = validate(job.get("ip", ""))
        except ValueError as e:
            log(f"job {job_id}: rejected {job.get('ip')!r}: {e}")
            if not dry_run:
                http("POST", queue_url, {"job_id": job_id, "status": "failed",
                                         "detail": f"relay rejected: {e}", "at": now()})
            continue
        if dry_run:
            log(f"job {job_id}: DRY RUN would block {ip} (approved by {job.get('approved_by')})")
            continue
        try:
            obj = fgt.block(ip)
            log(f"job {job_id}: BLOCKED {ip} as {obj} in {GROUP}")
            result = {"job_id": job_id, "status": "blocked",
                      "detail": f"{obj} added to {GROUP}", "at": now()}
        except Exception as e:  # report every failure back so Slack shows it
            log(f"job {job_id}: FAILED {ip}: {e}")
            result = {"job_id": job_id, "status": "failed", "detail": str(e)[:200], "at": now()}
        code, _ = http("POST", queue_url, result)
        if code != 200:
            log(f"job {job_id}: result post failed HTTP {code}, will be retried by 3B")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    load_env(REPO / "private" / "fortigate.env")
    load_env(REPO / "private" / "relay.env")
    fgt = FortiGate(os.environ["FGT_URL"], os.environ["FGT_TOKEN"])
    queue_url = os.environ["QUEUE_URL"]

    members = fgt.members()  # fail fast if the token or group is wrong
    log(f"relay up. {GROUP} has {len(members)} member(s). polling every {POLL_SECONDS}s"
        + (" [DRY RUN]" if args.dry_run else ""))
    while True:
        try:
            poll(queue_url, fgt, args.dry_run)
        except Exception as e:
            log(f"poll error: {e}")
        if args.once:
            break
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("relay stopped")
