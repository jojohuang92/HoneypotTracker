# Honeypot sensor agent

Ships Cowrie events from a remote honeypot to the Honeypot Tracker hub.

The hub owns the database, the dashboard, and every API key. A sensor only
tails its local Cowrie log and pushes events outbound, so it needs no inbound
ports, no database, and no third-party credentials. Geolocation, intent
classification, and abuse reporting all happen on the hub — nothing a sensor
claims about geography or intent is trusted.

```
  Acer (Taiwan)                          Raspberry Pi (hub)
  ┌────────────────────┐   HTTPS push    ┌──────────────────────────┐
  │ Cowrie (SSH+Telnet)│ ──────────────► │ /api/ingest              │
  │ agent.py           │  batches + hb   │ normalize · GeoIP        │
  │ spool + cursor     │ ◄────────────── │ classify · store · alert │
  └────────────────────┘   accepted/seq  └──────────────────────────┘
```

## 1. Provision the sensor on the hub

On the hub, with your admin key. Pick coordinates at the precision you are
willing to publish — for a home connection use `country` with the country
centroid, never your city:

```bash
curl -sX POST https://honeypottracker.live/api/admin/sensors \
  -H "X-Admin-Key: $ADMIN_API_KEY" -H 'Content-Type: application/json' \
  -d '{"sensor_id":"acer-taiwan","label":"Acer (Taiwan)","country_code":"TW",
       "country_name":"Taiwan","latitude":23.9739,"longitude":120.982,
       "location_precision":"country","timezone":"Asia/Taipei",
       "protocols":"ssh,telnet"}'
```

The response contains the ingest token **once** — it is stored only as a
SHA-256 hash and cannot be recovered, only rotated:

```json
{"sensor_id":"acer-taiwan","label":"Acer (Taiwan)","token":"…"}
```

## 2. Install the agent on the sensor

Copy this directory to the sensor machine and run:

```bash
sudo ./install.sh \
  --hub https://honeypottracker.live \
  --token <TOKEN_FROM_STEP_1> \
  --log /home/cowrie/cowrie/var/log/cowrie/cowrie.json
```

That creates an unprivileged `honeypot-sensor` user, installs the agent to
`/opt/honeypot-sensor`, writes the token to `/etc/honeypot-sensor.env` (mode
0640), and starts a hardened systemd unit. Check it with:

```bash
journalctl -u honeypot-sensor -f
```

The sensor appears in the dashboard's Fleet view within a minute, since the
agent heartbeats even when no attacks are arriving.

## Behaviour worth knowing

- **Starts at the end of the log.** A fresh agent sends only new activity;
  pass `--from-start` to replay the whole existing log instead.
- **Survives outages.** Events spool to `/var/lib/honeypot-sensor/state.json`
  and the read cursor only advances after the hub acknowledges them. When the
  link returns, the backlog drains oldest-first.
- **Retries cannot double-count.** Each event carries a sequence number inside
  an epoch; the hub keeps the high-water mark and skips anything it has seen.
- **Bounded disk use.** Beyond `--spool-limit` events (default 50,000) the
  oldest are dropped, preferring recent intelligence over a complete backlog.
- **Follows log rotation** by inode, so rotating Cowrie's log loses nothing.

## Rotating or revoking a token

```bash
# new token, old one stops working immediately
curl -sX POST https://honeypottracker.live/api/admin/sensors/acer-taiwan/rotate \
  -H "X-Admin-Key: $ADMIN_API_KEY"

# revoke access, keeping the events already reported
curl -sX DELETE https://honeypottracker.live/api/admin/sensors/acer-taiwan \
  -H "X-Admin-Key: $ADMIN_API_KEY"
```

After rotating, update `SENSOR_TOKEN` in `/etc/honeypot-sensor.env` and
`systemctl restart honeypot-sensor`.

## Hardening the sensor host

A honeypot host is attacked on purpose. Cowrie emulates a shell rather than
granting one, but treat the machine as untrusted anyway:

- Put it in a DMZ or its own VLAN with no route to the rest of your LAN.
- Forward the router's port 22 to Cowrie's high port (2222); never run Cowrie
  as root on 22 directly.
- Cap Cowrie's `var/lib/cowrie/downloads` directory and rotate its logs — the
  hub alerts on low disk, but old hardware fills up fast.
- The token in `/etc/honeypot-sensor.env` is the only secret present. Its blast
  radius is event submission for this one sensor, and it can be rotated from
  the hub at any time.
