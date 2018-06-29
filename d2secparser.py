import os
import sys
import bz2
import gzip
import json
import peewee
import zipfile
import logging
import urllib.request as req
from io import BytesIO
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from datetime import datetime

source_file = "https://www.d2sec.com/exploits/elliot.xml"

from settings import SETTINGS


from model_d2sec import D2SEC

logging.basicConfig(format='%(name)s >> [%(asctime)s] :: %(message)s', level=logging.DEBUG)
logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)

debug = bool(SETTINGS.get("debug", True))

json_filename = SETTINGS.get("json_filename", "snyk.json")

enable_extra_logging = SETTINGS.get("enable_extra_logging", False)
enable_results_logging = SETTINGS.get("enable_results_logging", False)
enable_exception_logging = SETTINGS.get("enable_exception_logging", True)

drop_d2sec_table_before = SETTINGS.get("drop_d2sec_table_before", False)

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

def LOGINFO_IF_ENABLED(message="\n"):
    if enable_extra_logging:
        logger.info(message)

def LOGWARN_IF_ENABLED(message="\n"):
    if enable_extra_logging:
        logger.warning(message)

def LOGERR_IF_ENABLED(message="\n"):
     if enable_exception_logging:
        logger.error(message)

def LOGVAR_IF_ENABLED(message="\n"):
    if enable_results_logging:
        logger.info(message)

def set_default(obj):
    if isinstance(obj, set):
        return list(obj)
    raise TypeError

def connect_database():
    try:
        peewee.logger.disabled = True
        if database.is_closed():
            database.connect()
        else:
            pass
        LOGVAR_IF_ENABLED("[+] Connect Postgress database")
        return True
    except peewee.OperationalError as peewee_operational_error:
        LOGERR_IF_ENABLED("[e] Connect Postgres database error: {}".format(peewee_operational_error))
    return False


def disconnect_database():
    try:
        if database.is_closed():
            pass
        else:
            database.close()
        LOGVAR_IF_ENABLED("[+] Disconnect Postgress database")
        peewee.logger.disabled = False
        return True
    except peewee.OperationalError as peewee_operational_error:
        LOGERR_IF_ENABLED("[-] Disconnect Postgres database error: {}".format(peewee_operational_error))
    peewee.logger.disabled = False
    return False

def drop_d2sec_table():
    connect_database()
    if D2SEC.table_exists():
        D2SEC.drop_table()
    disconnect_database()

def create_d2sec_table():
    connect_database()
    if not D2SEC.table_exists():
        D2SEC.create_table()
    disconnect_database()

def count_d2sec_table():
    connect_database()
    count = D2SEC.select().count()
    if count:
        disconnect_database()
        return count
    return 0


class D2secHandler(ContentHandler):
    def __init__(self):
        self.exploits = []
        self.d2sec    = None
        self.tag      = None

    def startElement(self, name, attrs):
        self.tag = name
        if   name == 'exploit': self.d2sec={'refs':[]}
        elif name == 'ref':
            self.d2sec['refs'].append({'type': attrs.get('type').lower()})

    def characters(self, ch):
        if self.d2sec and self.tag:
            if   self.tag == 'ref':     self.d2sec['refs'][-1]['key'] = ch
            elif self.tag != "exploit": self.d2sec[self.tag] = ch

    def endElement(self, name):
        self.tag = None
        if   name == 'exploit' and self.d2sec:
            self.exploits.append(self.d2sec)
            self.saint = None


def get_feed_data(getfile, unpack=True):
    try:
        response = req.urlopen(getfile)
    except:
        msg = "[!] Could not fetch file %s"%getfile
        sys.exit(msg)
    data = None
    data = response.read()
    if unpack:
        if 'gzip' in response.info().get('Content-Type'):
            data = gzip.GzipFile(fileobj = BytesIO(data))
        elif 'bzip2' in response.info().get('Content-Type'):
            data = BytesIO(bz2.decompress(data))
        elif 'zip' in response.info().get('Content-Type'):
            fzip = zipfile.ZipFile(BytesIO(data), 'r')
            if len(fzip.namelist())>0:
                data=BytesIO(fzip.read(fzip.namelist()[0]))
        elif 'application/octet-stream' in response.info().get('Content-Type'):
            if data[:4] == b'PK\x03\x04': # Zip
                fzip = zipfile.ZipFile(BytesIO(data), 'r')
                if len(fzip.namelist())>0:
                    data=BytesIO(fzip.read(fzip.namelist()[0]))
    return (data, response)


def download_d2sec():
    parser = make_parser()
    handler = D2secHandler()
    _file, r = get_feed_data(source_file)
    parser.setContentHandler(handler)
    parser.parse(BytesIO(_file))
    vulners = []
    for exploit in handler.exploits:
        refs = exploit.get('refs', [])
        name = exploit.get('name', "undefined")
        url = exploit.get('url', "undefined")
        rfex = [
            {"type": "cve", "key": "CVE-2009-3249"},
            {"type": "nid", "key": "NID-52656"},
            {"type": "osvdb", "key": "OSVDB-57239"},
            {"type": "bid", "key": "BID-36062"}
        ]
        cve_id = "undefined"
        nid = "undefined"
        osvdb = "undefined"
        bid = "undefined"
        references = []
        for r in refs:
            if isinstance(r, dict):
                type = r.get("type", None)
                if type is not None:
                    key = r.get("key", None)
                    if key is not None:
                        if type == "cve":
                            cve_id = key
                        elif type == "nid":
                            nid = key
                        elif type == "osvdb":
                            osvdb = key
                        elif type == "bid":
                            bid = key
                references.append(json.dumps(
                    dict(
                        type=type,
                        key=key
                    )
                ))
        vulners.append(dict(
            type="d2sec",
            refs=references,
            name=name,
            source="d2sec",
            url=url,
            cve_id=cve_id,
            nid=nid,
            osvdb=osvdb,
            bid=bid,
            published="undefined"
        ))
    return vulners


def create_d2sec_item_in_postgres(item_in_json):
    connect_database()

    item_in_json["published"] = datetime.utcnow() if item_in_json["published"] == "undefined" else item_in_json["published"]

    d2sec = D2SEC(
        type=item_in_json["type"],
        refs=item_in_json["refs"],
        cve_id=item_in_json["cve_id"],
        name=item_in_json["name"],
        url=item_in_json["url"],
        source=item_in_json["source"],
        bid=item_in_json["bid"],
        nid=item_in_json["nid"],
        osvdb=item_in_json["osvdb"],
        published=item_in_json["published"]
    )
    d2sec.save()

    disconnect_database()
    return d2sec.id

def update_d2sec_item_in_postgres(item_in_json, sid):
    connect_database()
    modified = False

    d2sec = D2SEC.get_by_id(sid)

    if d2sec.refs != item_in_json["refs"] or \
        d2sec.cve_id != item_in_json["cve_id"] or \
        d2sec.name != item_in_json["name"] or \
        d2sec.url != item_in_json["url"] or \
        d2sec.bid != item_in_json["bid"] or \
        d2sec.nid != item_in_json["nid"] or \
        d2sec.osvdb != item_in_json["osvdb"]:
        modified = True

    if modified:
        item_in_json["published"] = datetime.utcnow() if item_in_json["published"] == "undefined" else item_in_json["published"]
        d2sec.refs = item_in_json["refs"]
        d2sec.cve_id = item_in_json["cve_id"]
        d2sec.name = item_in_json["name"]
        d2sec.url = item_in_json["url"]
        d2sec.bid = item_in_json["bid"]
        d2sec.nid = item_in_json["nid"]
        d2sec.osvdb = item_in_json["osvdb"]
        d2sec.save()
        disconnect_database()
        return True
    else:
        disconnect_database()
        return False

def check_if_d2sec_item_exists_in_postgres(item_in_json):
    connect_database()
    sid = -1
    if "url" in item_in_json:
        url = item_in_json["url"]
        d2secs = list(
            D2SEC.select().where(
                (D2SEC.url == url)
            )
        )
        if len(d2secs) == 0:
            disconnect_database()
            return False, sid
        else:
            sid = d2secs[0].to_json["id"]
            disconnect_database()
            return True, sid

def create_or_update_d2sec_vulnerability_in_postgres(item_in_json):
    exists, sid = check_if_d2sec_item_exists_in_postgres(item_in_json)
    if not exists and sid == -1:
        sid = create_d2sec_item_in_postgres(item_in_json)
        return "created"
    else:
        modified = update_d2sec_item_in_postgres(item_in_json, sid)
        if modified:
            return "modified"
        else:
            return "skipped"


def run():
    print("run")
    vulners = download_d2sec()

    if drop_d2sec_table_before:
        drop_d2sec_table()
        create_d2sec_table()

    with open('v.txt', 'w') as vp:
        for v in vulners:
            vp.write(json.dumps(v) + '\n')

    created = []
    modified = []
    skipped = []

    for v in vulners:
        result = create_or_update_d2sec_vulnerability_in_postgres(v)
        if result == "created":
            created.append(v)
        elif result == "modified":
            modified.append(v)
        elif result == "skipped":
            skipped.append(v)

    LOGINFO_IF_ENABLED("Create {} vulnerabilities".format(len(created)))
    LOGINFO_IF_ENABLED("Modify {} vulnerabilities".format(len(modified)))
    LOGINFO_IF_ENABLED("Skip {} vulnerabilities".format(len(skipped)))

    print('complete')

def main():
    run()


if __name__ == "__main__":
    main()
