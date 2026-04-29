"""add issued_tokens table and users.removed_at

Revision ID: 2d35c00d0e7f
Revises: 5a01a50ef701
Create Date: 2026-04-29 00:16:16.666206

Adds the JWT blocklist infrastructure (issued_tokens) and the
soft-remove timestamp on users (removed_at).

Manual migration body. Autogenerate-then-amend was used because
env.py side-effects (db.create_all) silently created issued_tokens
in the live DB before autogen could detect it -- so autogen only
caught the users.removed_at delta. The CREATE TABLE block below
was added by hand and round-trip-tested per the PLB-1 procedure.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2d35c00d0e7f'
down_revision: Union[str, Sequence[str], None] = '5a01a50ef701'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # 1) issued_tokens -- JWT blocklist row written on every login
    op.create_table(
        'issued_tokens',
        sa.Column('id',            sa.String(length=36), primary_key=True),
        sa.Column('jti',           sa.String(length=36), nullable=False),
        sa.Column('user_id',       sa.Integer(),         nullable=False),
        sa.Column('issued_at',     sa.DateTime(),        nullable=False),
        sa.Column('expires_at',    sa.DateTime(),        nullable=False),
        sa.Column('revoked',       sa.Boolean(),         nullable=False),
        sa.Column('revoked_at',    sa.DateTime(),        nullable=True),
        sa.Column('revoked_by',    sa.Integer(),         nullable=True),
        sa.Column('revoke_reason', sa.String(length=50), nullable=True),
        sa.ForeignKeyConstraint(['user_id'],    ['users.id']),
        sa.ForeignKeyConstraint(['revoked_by'], ['users.id']),
    )
    op.create_index(
        'ix_issued_tokens_jti', 'issued_tokens',
        ['jti'], unique=True,
    )
    op.create_index(
        'ix_issued_tokens_user_id', 'issued_tokens',
        ['user_id'], unique=False,
    )

    # PLB-1 two-role convention: this migration runs as
    # aipet_admin (CREATEDB), so the new table is owned by
    # aipet_admin. The runtime app uses the lower-privileged
    # aipet_user; without an explicit GRANT, app inserts and
    # selects fail with "permission denied". Grant DML privileges
    # here so a fresh deploy doesn't surface this failure mode at
    # runtime. Caught live during the session-infra ship: Sentry
    # fired three production errors (login.INSERT and
    # iam.list_members.SELECT) within seconds of deploy; the live
    # aipet_db needed a manual GRANT before this addition.
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON issued_tokens TO aipet_user"
    )

    # 2) users.removed_at -- soft-remove timestamp
    op.add_column(
        'users',
        sa.Column('removed_at', sa.DateTime(), nullable=True),
    )
    op.create_index(
        op.f('ix_users_removed_at'), 'users',
        ['removed_at'], unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_users_removed_at'), table_name='users')
    op.drop_column('users', 'removed_at')

    op.drop_index('ix_issued_tokens_user_id', table_name='issued_tokens')
    op.drop_index('ix_issued_tokens_jti',     table_name='issued_tokens')
    op.drop_table('issued_tokens')
