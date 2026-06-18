"""
Management command: import_strongswan_config

Scans /etc/ipsec.conf, /etc/ipsec.secrets, and /etc/swanctl/swanctl.conf
(plus any conf.d/*.conf files) and imports all found connections, secrets,
pools, and CA configurations into the database.

Existing profiles are skipped (not overwritten) so the command is safe to
re-run at any time.

Usage:
    python manage.py import_strongswan_config
    python manage.py import_strongswan_config --ipsec-conf /etc/ipsec.conf
    python manage.py import_strongswan_config --swanctl-conf /etc/swanctl/swanctl.conf
    python manage.py import_strongswan_config --dry-run
"""
from django.core.management.base import BaseCommand

from strongswan_manager.services.importers import ConfigImportEngine


class Command(BaseCommand):
    help = "Import existing StrongSwan configuration into the database"

    def add_arguments(self, parser):
        parser.add_argument(
            "--ipsec-conf",
            default="/etc/ipsec.conf",
            help="Path to ipsec.conf (default: /etc/ipsec.conf)",
        )
        parser.add_argument(
            "--ipsec-secrets",
            default="/etc/ipsec.secrets",
            help="Path to ipsec.secrets (default: /etc/ipsec.secrets)",
        )
        parser.add_argument(
            "--swanctl-conf",
            default="/etc/swanctl/swanctl.conf",
            help="Path to swanctl.conf (default: /etc/swanctl/swanctl.conf)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Parse configs and report what would be imported without writing to DB",
        )

    def handle(self, *args, **options):
        ipsec_conf = options["ipsec_conf"]
        ipsec_secrets = options["ipsec_secrets"]
        swanctl_conf = options["swanctl_conf"]
        dry_run = options["dry_run"]

        if dry_run:
            self._dry_run(ipsec_conf, ipsec_secrets, swanctl_conf)
            return

        self.stdout.write("Importing StrongSwan configuration...")
        engine = ConfigImportEngine(
            ipsec_conf=ipsec_conf,
            ipsec_secrets=ipsec_secrets,
            swanctl_conf=swanctl_conf,
        )
        result = engine.import_all()

        self.stdout.write(self.style.SUCCESS("\nImport complete:"))
        self.stdout.write(str(result))

        if result.errors:
            self.stderr.write(
                self.style.WARNING(f"\n{len(result.errors)} error(s) during import — "
                                   "see above for details.")
            )
        else:
            self.stdout.write(self.style.SUCCESS("\nNo errors."))

    def _dry_run(self, ipsec_conf, ipsec_secrets, swanctl_conf):
        import os
        from strongswan_manager.services.importers.ipsec_conf_parser import IpsecConfParser
        from strongswan_manager.services.importers.ipsec_secrets_parser import IpsecSecretsParser
        from strongswan_manager.services.importers.swanctl_conf_parser import SwanctlConfParser

        self.stdout.write("=== DRY RUN — no changes will be made ===\n")

        if os.path.exists(ipsec_conf):
            specs = IpsecConfParser.parse_file(ipsec_conf)
            self.stdout.write(f"ipsec.conf: {len(specs)} connection(s) found")
            for s in specs:
                self.stdout.write(f"  {s.name}  keyexchange={s.keyexchange}  authby={s.authby}  auto={s.auto}")
        else:
            self.stdout.write(f"ipsec.conf not found: {ipsec_conf}")

        if os.path.exists(ipsec_secrets):
            secrets = IpsecSecretsParser.parse_file(ipsec_secrets)
            self.stdout.write(f"\nipsec.secrets: {len(secrets)} secret(s) found")
            for s in secrets:
                self.stdout.write(f"  type={s.type}  left={s.left_id}  right={s.right_id}  user={s.username}")
        else:
            self.stdout.write(f"\nipsec.secrets not found: {ipsec_secrets}")

        if os.path.exists(swanctl_conf):
            tree = SwanctlConfParser.parse_file(swanctl_conf)
            n_conns = len(tree.get("connections", {}))
            n_secrets = len(tree.get("secrets", {}))
            n_pools = len(tree.get("pools", {}))
            n_auth = len(tree.get("authorities", {}))
            self.stdout.write(f"\nswanctl.conf:")
            self.stdout.write(f"  connections: {n_conns}")
            self.stdout.write(f"  secrets:     {n_secrets}")
            self.stdout.write(f"  pools:       {n_pools}")
            self.stdout.write(f"  authorities: {n_auth}")
            for name in tree.get("connections", {}):
                self.stdout.write(f"  conn: {name}")
        else:
            self.stdout.write(f"\nswanctl.conf not found: {swanctl_conf}")
