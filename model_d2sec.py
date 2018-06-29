import os
from playhouse.postgres_ext import ArrayField
import peewee

from datetime import datetime

from settings import SETTINGS

POSTGRES = SETTINGS.get("postgres", {})

pg_default_database = POSTGRES.get("database", "updater_db")
pg_default_user = POSTGRES.get("user", "admin")
pg_default_password = POSTGRES.get("password", "123")
pg_default_host = POSTGRES.get("host", "localhost")
pg_default_port = POSTGRES.get("port", "5432")

pg_drop_before = bool(POSTGRES.get("drop_pg_before", True))

pg_database = os.environ.get("PG_DATABASE", pg_default_database)
pg_user = os.environ.get("PG_USER", pg_default_user)
pg_password = os.environ.get("PG_PASS", pg_default_password)
pg_host = os.environ.get("PG_HOST", pg_default_host)
pg_port = os.environ.get("PG_PORT", pg_default_port)

database = peewee.PostgresqlDatabase(
    database=pg_database,
    user=pg_user,
    password=pg_password,
    host=pg_host,
    port=pg_port
)


class D2SEC(peewee.Model):
    class Meta:
        database = database
        ordering = ("cve_id", )
        table_name = "vulnerabilities_d2sec"

    id = peewee.PrimaryKeyField(null=False)
    type = peewee.TextField(default="", verbose_name="Vulnerability type")
    cve_id = peewee.TextField(default="", verbose_name="CVE ID")
    name = peewee.TextField(default="", verbose_name="D2SEC name")
    url = peewee.TextField(default="https://www.d2sec.com/")
    refs = ArrayField(peewee.TextField, default=[],  verbose_name="References", index=False)
    source = peewee.TextField(default="d2sec", verbose_name="Vulnerability source")
    bid = peewee.TextField(default="")
    nid = peewee.TextField(default="")
    osvdb = peewee.TextField(default="")
    published = peewee.DateTimeField(default=datetime.now)

    def __unicode__(self):
        return "d2sec"

    def __str__(self):
        return str(self.cve_id)

    @property
    def to_json(self):
        return dict(
            id=self.id,
            type=self.type,
            refs=self.refs,
            cve_id=self.cve_id,
            name=self.name,
            url=self.url,
            source=self.source,
            bid=self.bid,
            nid=self.nid,
            osvdb=self.osvdb,
            published=self.published
        )