"""Build the MySQL init script that loads the ExCyTIn incident logs.

ExCyTIn-Bench (Wu et al., ICML 2026, MIT licence) ships each of its 8 incidents
as a folder of CSV files (fields separated by U+2756 "❖") plus a .meta JSON file
mapping column -> Kusto type. Upstream starts one MySQL container per incident;
we load all 8 into ONE container as databases ``incident_<N>`` so the whole
benchmark fits in Docker Desktop's default memory.

Table layout and the "alert" layer (every table except AzureDiagnostics and
LAQueryLogs) match upstream's ``setup_database.py`` so question difficulty is
unchanged. Every column is TEXT, as upstream.

    python -m triage.excytin.setup_db --data ~/excytin-data/data_anonymized/incidents
    docker compose -f docker-compose.excytin.yml up -d
"""

import argparse
import json
import os
from pathlib import Path

INCIDENTS = (5, 34, 38, 39, 55, 134, 166, 322)
SKIP_TABLES = {"AzureDiagnostics", "LAQueryLogs"}  # upstream's "alert" layer
SEPARATOR = "❖"
DEFAULT_DATA = Path(os.getenv("EXCYTIN_DATA", "~/excytin-data/data_anonymized/incidents")).expanduser()
DEFAULT_OUT = Path(__file__).resolve().parents[2] / "build" / "excytin_init"


def _q(name: str) -> str:
    return "`" + name.replace("`", "") + "`"


def _create_table(table: str, type_map: dict) -> str:
    cols = ",\n  ".join(f"{_q(c)} LONGTEXT" for c in type_map)
    return f"CREATE TABLE {_q(table)} (\n  {cols}\n) CHARACTER SET utf8mb4;"


def _load(rel_path: str, table: str) -> str:
    return (
        f"LOAD DATA INFILE '/var/lib/mysql-files/{rel_path}'\n"
        f"INTO TABLE {_q(table)} CHARACTER SET utf8mb4\n"
        f"FIELDS TERMINATED BY '{SEPARATOR}' ENCLOSED BY '\"'\n"
        "LINES TERMINATED BY '\\n'\nIGNORE 1 ROWS;"
    )


def tables_for_incident(folder: Path):
    """Yield (table, type_map, [csv paths relative to the incidents root])."""
    root = folder.parent
    for entry in sorted(folder.iterdir()):
        if entry.name.startswith((".", "._")):
            continue
        if entry.is_file() and entry.suffix == ".csv":
            table = entry.stem
            meta = entry.with_suffix(".meta")
            if table in SKIP_TABLES or not meta.exists():
                continue
            yield table, json.loads(meta.read_text()), [str(entry.relative_to(root))]
        elif entry.is_dir() and entry.name not in SKIP_TABLES:
            csvs = sorted(p for p in entry.glob(f"{entry.name}_*.csv") if not p.name.startswith("._"))
            meta = entry / f"{entry.name}_0.meta"
            if csvs and meta.exists():
                yield entry.name, json.loads(meta.read_text()), [str(p.relative_to(root)) for p in csvs]


def build_sql(data_dir: Path, incidents=INCIDENTS) -> str:
    out = [
        "SET GLOBAL local_infile = 0;",
        "CREATE USER IF NOT EXISTS 'reader'@'%' IDENTIFIED BY 'reader';",
    ]
    for n in incidents:
        folder = data_dir / f"incident_{n}"
        if not folder.is_dir():
            raise FileNotFoundError(f"missing {folder}; download data_anonymized.tar.gz first (see docs/EXCYTIN.md)")
        db = f"incident_{n}"
        out += [f"CREATE DATABASE IF NOT EXISTS {db};", f"USE {db};"]
        for table, type_map, paths in tables_for_incident(folder):
            out.append(_create_table(table, type_map))
            out += [_load(p, table) for p in paths]
        # The agent connects as a read-only user: a hostile or confused query cannot modify evidence.
        out.append(f"GRANT SELECT, SHOW VIEW ON {db}.* TO 'reader'@'%';")
    out.append("FLUSH PRIVILEGES;")
    return "\n\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data", type=Path, default=DEFAULT_DATA)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--incidents", default=",".join(map(str, INCIDENTS)))
    args = ap.parse_args()
    incidents = [int(x) for x in args.incidents.split(",")]
    args.out.mkdir(parents=True, exist_ok=True)
    sql = build_sql(args.data.expanduser(), incidents)
    path = args.out / "01_excytin.sql"
    path.write_text(sql)
    print(f"wrote {path} ({sql.count('LOAD DATA')} loads, {len(incidents)} incidents)")
    print(f"EXCYTIN_DATA={args.data.expanduser()}  # mount this at /var/lib/mysql-files")


if __name__ == "__main__":
    main()
