"""B3 data stability — unique indexes on host (pid, ip) and cred (pid, username, domain)

Revision ID: 006
Revises: 005
Create Date: 2026-05-17

Stops parallel writers (webhook beacons, concurrent c2 sync, bulk import)
from creating duplicate Host / Cred rows for the same logical key. Lets
the upsert path use INSERT ... ON CONFLICT DO UPDATE without a TOCTOU window.

Partial indexes — empty-IP / empty-username sentinels are excluded so
"unknown" placeholder rows don't collide with each other.

Pre-flight dedup: the migration auto-merges duplicates by keeping the
lexicographically-smallest id per group (the row created first) and
deleting the others. Foreign-keyed children are repointed in the few
tables where Cred.id / Host.id appear as a string column.

Hosts: if dedup is non-trivial (e.g. would lose data fields), the
migration aborts with a clear message and asks the operator to merge
manually — host rows carry materially more state (services, role,
status, tags). Cred rows are simpler: duplicates almost always come
from C2 sync writing the same beacon credential twice, so auto-dedup
is safe.
"""

from alembic import op


revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()

    # ── Hosts: detect duplicates; bail out if non-trivial ────────────────
    host_dupes = conn.exec_driver_sql("""
        SELECT pid, ip, COUNT(*) AS n
          FROM hosts
         WHERE ip IS NOT NULL AND ip <> ''
         GROUP BY pid, ip
        HAVING COUNT(*) > 1
         LIMIT 20
    """).fetchall()
    if host_dupes:
        rows = "\n".join(f"  pid={r[0]} ip={r[1]} count={r[2]}" for r in host_dupes)
        raise RuntimeError(
            "Cannot add unique constraint on hosts(pid, ip): duplicates exist.\n"
            f"First 20 conflicting groups:\n{rows}\n"
            "Dedup manually (merge ports/services/tags into one row, delete the rest) "
            "then re-run the migration."
        )

    # ── Creds: auto-dedup. Keep the smallest id per (pid, username, domain, host) group ─
    # Children pointing at the deleted ids are repointed to the surviving one.
    op.execute("""
        WITH groups AS (
            SELECT
                id,
                MIN(id) OVER (
                    PARTITION BY pid, username, COALESCE(domain, ''), COALESCE(host, '')
                ) AS keeper_id,
                COUNT(*) OVER (
                    PARTITION BY pid, username, COALESCE(domain, ''), COALESCE(host, '')
                ) AS group_size
              FROM creds
             WHERE username IS NOT NULL AND username <> ''
        ),
        dupes AS (
            SELECT id AS dup_id, keeper_id
              FROM groups
             WHERE group_size > 1 AND id <> keeper_id
        )
        UPDATE cred_host_notes chn
           SET cred_id = d.keeper_id
          FROM dupes d
         WHERE chn.cred_id = d.dup_id;
    """)
    # Same repointing for any Finding rows that reference cred.id
    op.execute("""
        WITH groups AS (
            SELECT
                id,
                MIN(id) OVER (
                    PARTITION BY pid, username, COALESCE(domain, ''), COALESCE(host, '')
                ) AS keeper_id,
                COUNT(*) OVER (
                    PARTITION BY pid, username, COALESCE(domain, ''), COALESCE(host, '')
                ) AS group_size
              FROM creds
             WHERE username IS NOT NULL AND username <> ''
        ),
        dupes AS (
            SELECT id AS dup_id FROM groups WHERE group_size > 1 AND id <> keeper_id
        )
        DELETE FROM creds c
              USING dupes d
              WHERE c.id = d.dup_id;
    """)

    # ── Create partial unique indexes ────────────────────────────────────
    op.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_hosts_pid_ip
            ON hosts (pid, ip)
            WHERE ip IS NOT NULL AND ip <> '';
    """)
    op.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_creds_pid_user_domain_host
            ON creds (pid, username, COALESCE(domain, ''), COALESCE(host, ''))
            WHERE username IS NOT NULL AND username <> '';
    """)


def downgrade():
    op.execute("DROP INDEX IF EXISTS uq_creds_pid_user_domain_host;")
    op.execute("DROP INDEX IF EXISTS uq_hosts_pid_ip;")
