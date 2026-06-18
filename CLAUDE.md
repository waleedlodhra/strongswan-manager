# StrongSwan Manager — CLAUDE.md

## Project Overview
StrongSwan Manager is a complete web-based management GUI for the strongSwan VPN daemon. It provides full two-way synchronization between the GUI and strongSwan, importing all existing configurations automatically on first run.

Forked from StrongMan (https://github.com/strongswan/strongman), heavily extended and refactored.

## Project Structure
```
strongswan-manager/
  strongswan_manager/           ← Django project root (renamed from strongMan)
    apps/
      connections/              ← client-side VPN connections (initiator)
      server_connections/       ← server-side VPN (responder + S2S) — to be merged into connections in Phase 1
      certificates/             ← X.509 certificate + private key management
      eap_secrets/              ← EAP username/password secrets — to be extended to secrets/ in Phase 1
      pools/                    ← IP address pools
      monitoring/               ← (Phase 5) live SA dashboard
      sync/                     ← (Phase 3-4) config import/export + file watcher
      api/                      ← (Phase 6) DRF REST API
    helper_apps/
      vici/wrapper/             ← VICI socket wrapper
      encryption/               ← AES-encrypted model fields
    services/                   ← (Phase 2+) ViciService, ConfigParser, SyncEngine
    workers/                    ← (Phase 5) background SA monitor
    settings/
      base.py                   ← shared settings
      local.py                  ← dev/test settings
      production.py             ← production settings
    templates/                  ← Bootstrap 5 templates (upgraded from Bootstrap 3)
  requirements.txt
  requirements-tests.txt
  install.sh                    ← (Phase 7) one-command installer
  manage.py
  pytest.ini
```

## Technology Stack
- **Backend**: Django 4.2, Python 3.9+
- **Database**: SQLite (default), PostgreSQL (optional)
- **StrongSwan API**: VICI protocol via `vici` Python library, socket at `/var/run/charon.vici`
- **Frontend**: Bootstrap 5 + Bootstrap Icons + jQuery (progressive)
- **REST API**: Django REST Framework
- **WebSocket**: Django Channels + Daphne
- **File watching**: watchdog (inotify-based)
- **Background tasks**: APScheduler (in-process)
- **Testing**: pytest + pytest-django + factory_boy

## Implementation Phases
| Phase | Status | Description |
|-------|--------|-------------|
| 0 | ✅ DONE | Project bootstrap, rename, Bootstrap 5, requirements |
| 1 | ✅ DONE | Unified data model (all swanctl fields, IKEv1/PSK/XAUTH, Authority model, 232 tests) |
| 2 | ✅ DONE | Enhanced VICI service — ViciService singleton + SaMonitor, all 38 commands, 313 tests |
| 3 | ✅ DONE | Config import engine — ipsec.conf/secrets/swanctl parsers + import management cmd, 392 tests |
| 4 | 🔲 NEXT | Two-way synchronization (GUI→StrongSwan signals, file watcher→GUI) |
| 5 | 🔲 TODO | Real-time monitoring dashboard (WebSocket SA table) |
| 6 | 🔲 TODO | Complete GUI feature coverage (IKEv1, PSK, transport mode, etc.) |
| 7 | 🔲 TODO | install.sh one-command installer |
| 8 | 🔲 TODO | Full test suite |

## Running the Project (Development)
```bash
cd strongswan-manager
python -m venv env
source env/bin/activate
pip install -r requirements-tests.txt
python manage.py migrate --settings=strongswan_manager.settings.local
python manage.py loaddata fixtures/default_user.json --settings=strongswan_manager.settings.local
python manage.py runserver --settings=strongswan_manager.settings.local
```

## Key Design Decisions
1. **File-as-source-of-truth**: on conflict between file and DB, file wins
2. **Unified Connection model**: replaces the split connections/server_connections apps
3. **VICI singleton**: one persistent socket, reconnect on failure
4. **APScheduler** over Celery (no broker dependency for single-server deployment)
5. **Bootstrap 5** (upgraded from Bootstrap 3)

## StrongSwan Environment
- Version: 6.0.4
- VICI socket: `/var/run/charon.vici`
- Config: `/etc/ipsec.conf`, `/etc/ipsec.secrets`, `/etc/swanctl/`
- Current live config: IKEv1 PSK tunnels (hq-host1, hq-host2) — good import test case

## Default Login (Development)
- Username: John
- Password: Lennon@1940
