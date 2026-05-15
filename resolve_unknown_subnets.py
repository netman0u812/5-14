#!/usr/bin/env python3
"""
resolve_unknown_subnets.py  v1.0.0

Resolves the 82 private /24 subnets that appear in the CSNA UNKNOWN zone
but are absent from all_IP_networks. Derives CANONICAL_LOCATION by cross-
referencing ent_network_device_master and ent_host_master, then generates
a patch CSV ready for import via ipam-db.py --import.

Usage:
    python3 resolve_unknown_subnets.py [options]

    --ipam-db DIR           ipam-db/ directory (default: ./ipam-db)
    --output FILE           output patch CSV (default: ./unknown_subnet_patch_v1.0.csv)
    --dry-run               print resolution table, write nothing
    -V, --version           show version and exit

Output:
    unknown_subnet_patch_v1.0.csv   IPAM-ready patch rows (review before import)
    unknown_subnet_review.csv       rows needing manual location assignment
"""

__version__ = "1.0.0"

import sys
if len(sys.argv) > 1 and sys.argv[1] in ('-V', '--version'):
    print(f"resolve_unknown_subnets.py v{__version__}")
    sys.exit(0)

import csv
import ipaddress
import argparse
import pathlib
import re
from collections import defaultdict, Counter
from datetime import datetime, timezone

# ── Unknown /24s identified from CSNA UNKNOWN-2 hostgroup (2026-05-15) ─────
UNKNOWN_SLASH24S = [
    "10.106.96.0/24",
    "10.136.194.0/24",
    "10.136.212.0/24",
    "10.136.248.0/24",
    "10.156.140.0/24",
    "10.156.66.0/24",
    "10.170.188.0/24",
    "10.210.13.0/24",
    "10.228.125.0/24",
    "10.228.226.0/24",
    "172.16.1.0/24",
    "172.16.20.0/24",
    "172.16.222.0/24",
    "172.16.24.0/24",
    "172.16.26.0/24",
    "172.16.36.0/24",
    "172.16.37.0/24",
    "172.16.38.0/24",
    "172.16.39.0/24",
    "172.16.53.0/24",
    "172.16.54.0/24",
    "172.16.55.0/24",
    "172.18.1.0/24",
    "172.18.133.0/24",
    "172.18.134.0/24",
    "172.18.145.0/24",
    "172.18.146.0/24",
    "172.18.15.0/24",
    "172.18.150.0/24",
    "172.18.156.0/24",
    "172.18.161.0/24",
    "172.18.162.0/24",
    "172.18.176.0/24",
    "172.18.178.0/24",
    "172.18.180.0/24",
    "172.18.182.0/24",
    "172.18.185.0/24",
    "172.18.187.0/24",
    "172.18.2.0/24",
    "172.18.244.0/24",
    "172.18.246.0/24",
    "172.18.33.0/24",
    "172.18.36.0/24",
    "172.18.39.0/24",
    "172.18.48.0/24",
    "172.18.49.0/24",
    "172.18.50.0/24",
    "172.18.51.0/24",
    "172.18.52.0/24",
    "172.18.53.0/24",
    "172.18.6.0/24",
    "172.18.60.0/24",
    "172.18.61.0/24",
    "172.19.100.0/24",
    "172.19.104.0/24",
    "172.19.2.0/24",
    "172.19.32.0/24",
    "172.19.33.0/24",
    "172.19.34.0/24",
    "172.19.35.0/24",
    "172.19.36.0/24",
    "172.19.39.0/24",
    "172.19.40.0/24",
    "172.19.41.0/24",
    "172.19.42.0/24",
    "172.19.43.0/24",
    "172.19.44.0/24",
    "172.20.184.0/24",
    "172.20.190.0/24",
    "172.21.130.0/24",
    "172.21.165.0/24",
    "172.28.104.0/24",
    "172.28.12.0/24",
    "172.28.32.0/24",
    "172.28.33.0/24",
    "172.28.34.0/24",
    "172.28.35.0/24",
    "172.28.36.0/24",
    "172.28.39.0/24",
    "172.29.32.0/24",
    "172.30.248.0/24",
    "172.30.249.0/24",
]

# ── Location inference hints — derived from NDM sample lookups ──────────────
# Used as tie-breakers when NDM/EHM signals are sparse or conflicting.
# Key: first two octets of /16, Value: (CANONICAL_LOCATION, SITE_CODE, NET_TYPE, ROUTING_DOMAIN)
OCTET16_HINTS = {
    "172.18": ("Phoenix AZ - Aetna DC",         "US_PHX_AZ_DC",  "DataCenter", "Internal-HCB"),
    "172.19": ("Middletown CT - Aetna MDC",      "US_MDT_CT_DC",  "DataCenter", "Internal-HCB"),
    "172.20": ("Middletown CT - Aetna MDC",      "US_MDT_CT_DC",  "DataCenter", "Internal-HCB"),
    "172.21": ("Middletown CT - Aetna MDC",      "US_MDT_CT_DC",  "DataCenter", "Internal-HCB"),
    "172.28": ("Windsor CT - Aetna WDC",         "US_WDS_CT_DC",  "DataCenter", "Internal-HCB"),
    "172.29": ("Windsor CT - Aetna WDC",         "US_WDS_CT_DC",  "DataCenter", "Internal-HCB"),
    "172.30": ("Windsor CT - Aetna WDC",         "US_WDS_CT_DC",  "DataCenter", "Internal-HCB"),
    "172.16": ("Phoenix AZ - Aetna DC",          "US_PHX_AZ_DC",  "DataCenter", "Internal-HCB"),
}

# Known 10.x Aetna/HCB blocks from prior IPAM work
OCTET10_HINTS = {
    "10.136": ("Middletown CT - Aetna MDC",      "US_MDT_CT_DC",  "DataCenter", "Internal-HCB"),
    "10.156": ("Middletown CT - Aetna MDC",      "US_MDT_CT_DC",  "DataCenter", "Internal-HCB"),  # CarePlus VDC
    "10.170": ("Windsor CT - Aetna WDC",         "US_WDS_CT_DC",  "DataCenter", "Internal-HCB"),
    "10.228": ("Phoenix AZ - Aetna DC",          "US_PHX_AZ_DC",  "DataCenter", "Internal-HCB"),
    "10.210": ("Phoenix AZ - Aetna DC",          "US_PHX_AZ_DC",  "DataCenter", "Internal-HCB"),
    "10.106": ("Middletown CT - Aetna MDC",      "US_MDT_CT_DC",  "DataCenter", "Internal-HCB"),
}

# ── CCD CSV helpers ──────────────────────────────────────────────────────────

def _csv_reader(path):
    """Skip #-prefixed comment lines from CCD CSV files."""
    with open(path, encoding='utf-8', errors='replace') as f:
        yield from csv.DictReader(l for l in f if not l.startswith('#'))

def _best_file(directory, stem):
    """Find the highest-versioned file for stem in directory."""
    d = pathlib.Path(directory)
    best_file = None
    best_key = (-1, -1, -1)
    for f in d.glob(f"{stem}_v*.csv"):
        m = re.search(r'_v([0-9]+(?:r[0-9]+|\.[0-9]+[a-z]?)?)\.csv$', f.name)
        if not m:
            continue
        vraw = m.group(1)
        if re.match(r'^[0-9]+r[0-9]+$', vraw):
            a, b, c = int(vraw.split('r')[0]), 0, int(vraw.split('r')[1])
        elif re.match(r'^[0-9]+\.[0-9]+[a-z]?$', vraw):
            dm = re.match(r'^([0-9]+)\.([0-9]+)([a-z]?)$', vraw)
            a, b = int(dm.group(1)), int(dm.group(2))
            c = ord(dm.group(3)) if dm.group(3) else -1
        elif re.match(r'^[0-9]+$', vraw):
            a, b, c = int(vraw), 0, -1
        else:
            continue
        if (a, b, c) > best_key:
            best_key = (a, b, c)
            best_file = f
    if best_file is None:
        bare = d / f"{stem}.csv"
        if bare.exists():
            return bare
    return best_file

# ── Location normaliser ──────────────────────────────────────────────────────

def normalise_location(raw):
    """Strip whitespace and common junk from location strings."""
    if not raw:
        return ''
    s = raw.strip()
    # Drop anything in parens at the end (e.g. "Phoenix AZ - Aetna DC (old)")
    s = re.sub(r'\s*\(.*?\)\s*$', '', s).strip()
    return s

# ── Load NDM ─────────────────────────────────────────────────────────────────

def load_ndm(ipam_db_dir):
    """
    Load ent_network_device_master.
    Returns dict: ip_str → {'location': str, 'heritage': str, 'hostname': str, 'device_type': str}
    """
    ndm_path = _best_file(ipam_db_dir, 'ent_network_device_master')
    if ndm_path is None or not ndm_path.exists():
        print(f"  WARNING: ent_network_device_master not found in {ipam_db_dir}", file=sys.stderr)
        return {}
    index = {}
    for row in _csv_reader(ndm_path):
        ip = row.get('MANAGEMENT_IP', '').strip()
        loc = normalise_location(row.get('CANONICAL_LOCATION') or row.get('Location') or '')
        heritage = row.get('HERITAGE', '').strip().upper()
        if ip and loc and loc.upper() not in ('UNKNOWN', ''):
            index[ip] = {
                'location': loc,
                'heritage': heritage,
                'hostname': row.get('HOSTNAME', '').strip(),
                'device_type': row.get('DEVICE_TYPE', '').strip(),
            }
    print(f"  NDM: {ndm_path.name}  {len(index):,} device records with known location",
          file=sys.stderr)
    return index

# ── Load EHM ─────────────────────────────────────────────────────────────────

def load_ehm(ipam_db_dir):
    """
    Load ent_host_master.
    Returns dict: ip_str → {'location': str, 'heritage': str, 'application': str}
    """
    ehm_path = _best_file(ipam_db_dir, 'ent_host_master')
    if ehm_path is None or not ehm_path.exists():
        print(f"  WARNING: ent_host_master not found in {ipam_db_dir}", file=sys.stderr)
        return {}
    index = {}
    for row in _csv_reader(ehm_path):
        ip = row.get('IP_ADDRESS', '').strip()
        loc = normalise_location(row.get('CANONICAL_LOCATION') or row.get('Location') or '')
        heritage = row.get('HERITAGE', '').strip().upper()
        if ip and loc and loc.upper() not in ('UNKNOWN', ''):
            index[ip] = {
                'location': loc,
                'heritage': heritage,
                'application': row.get('APPLICATION', '').strip(),
            }
    print(f"  EHM: {ehm_path.name}  {len(index):,} host records with known location",
          file=sys.stderr)
    return index

# ── Load location master ──────────────────────────────────────────────────────

def load_location_master(ipam_db_dir):
    """
    Returns dict: canonical_location → {'site_code': str, 'location_type': str, 'heritage': str}
    """
    lm_path = _best_file(ipam_db_dir, 'location_master')
    if lm_path is None or not lm_path.exists():
        lm_path = pathlib.Path(ipam_db_dir) / 'location_master_table.csv'
    if lm_path is None or not lm_path.exists():
        print(f"  WARNING: location_master not found in {ipam_db_dir}", file=sys.stderr)
        return {}
    index = {}
    for row in _csv_reader(lm_path):
        loc = normalise_location(row.get('CANONICAL_NAME') or row.get('CANONICAL_LOCATION') or '')
        sc  = row.get('SITE_CODE', '').strip()
        lt  = row.get('LOCATION_TYPE', '').strip()
        her = row.get('HERITAGE', '').strip().upper()
        if loc:
            index[loc.upper()] = {'site_code': sc, 'location_type': lt, 'heritage': her,
                                   'canonical': loc}
    print(f"  LM:  {lm_path.name}  {len(index):,} location entries", file=sys.stderr)
    return index

# ── Resolution engine ─────────────────────────────────────────────────────────

def resolve_slash24(cidr_str, ndm_index, ehm_index, lm_index):
    """
    Determine CANONICAL_LOCATION for a /24 by:
      T1 — NDM: majority vote from devices in this /24
      T2 — EHM: majority vote from hosts in this /24
      T3 — /16 hint table (OCTET16_HINTS / OCTET10_HINTS)

    Returns:
      location, site_code, net_type, routing_domain, heritage,
      confidence, method, device_count, conflict_flag
    """
    net = ipaddress.ip_network(cidr_str, strict=False)
    first_octet = str(net.network_address).split('.')[0]
    slash16_key = '.'.join(str(net.network_address).split('.')[:2])

    # Collect all NDM/EHM records in this /24
    ndm_locations = []
    for ip_str, rec in ndm_index.items():
        try:
            if ipaddress.ip_address(ip_str) in net:
                ndm_locations.append((rec['location'], rec['heritage']))
        except ValueError:
            pass

    ehm_locations = []
    for ip_str, rec in ehm_index.items():
        try:
            if ipaddress.ip_address(ip_str) in net:
                ehm_locations.append((rec['location'], rec['heritage']))
        except ValueError:
            pass

    def majority_vote(locs):
        if not locs:
            return None, None
        loc_votes = Counter(l for l, _ in locs)
        her_votes = Counter(h for _, h in locs if h)
        top_loc = loc_votes.most_common(1)[0][0]
        top_her = her_votes.most_common(1)[0][0] if her_votes else ''
        conflict = len(loc_votes) > 1
        return top_loc, top_her, conflict, len(locs)

    # T1: NDM vote
    if ndm_locations:
        loc, her, conflict, count = majority_vote(ndm_locations)
        # Look up LM for site_code and net_type
        lm = lm_index.get(loc.upper(), {})
        site_code = lm.get('site_code', '')
        net_type  = 'DataCenter'   # NDM devices → always DataCenter
        rd        = 'Internal-HCB' if (her == 'AETNA' or 'aetna' in loc.lower() or
                                        'wdc' in loc.lower() or 'mdc' in loc.lower()) else 'Internal-PBM'
        return {
            'location': loc, 'site_code': site_code, 'net_type': net_type,
            'routing_domain': rd, 'heritage': her or 'AETNA',
            'confidence': 'HIGH' if not conflict else 'MEDIUM',
            'method': 'ndm_vote', 'device_count': count,
            'conflict': conflict, 'ndm_count': count, 'ehm_count': 0,
        }

    # T2: EHM vote
    if ehm_locations:
        loc, her, conflict, count = majority_vote(ehm_locations)
        lm = lm_index.get(loc.upper(), {})
        site_code = lm.get('site_code', '')
        net_type  = lm.get('location_type', 'DataCenter')
        rd        = 'Internal-HCB' if (her == 'AETNA' or 'aetna' in loc.lower()) else 'Internal-PBM'
        return {
            'location': loc, 'site_code': site_code, 'net_type': net_type,
            'routing_domain': rd, 'heritage': her or 'AETNA',
            'confidence': 'MEDIUM' if not conflict else 'LOW',
            'method': 'ehm_vote', 'device_count': count,
            'conflict': conflict, 'ndm_count': 0, 'ehm_count': count,
        }

    # T3: /16 hint
    hint = None
    if first_octet == '172':
        hint = OCTET16_HINTS.get(slash16_key)
    elif first_octet == '10':
        hint = OCTET10_HINTS.get(slash16_key)

    if hint:
        loc, site_code, net_type, rd = hint
        # Verify against LM
        lm = lm_index.get(loc.upper(), {})
        if lm.get('site_code'):
            site_code = lm['site_code']
        return {
            'location': loc, 'site_code': site_code, 'net_type': net_type,
            'routing_domain': rd, 'heritage': 'AETNA',
            'confidence': 'LOW', 'method': 'hint_table',
            'device_count': 0, 'conflict': False, 'ndm_count': 0, 'ehm_count': 0,
        }

    # Unresolved
    return {
        'location': 'UNKNOWN-NEEDS-REVIEW', 'site_code': '', 'net_type': '',
        'routing_domain': '', 'heritage': '',
        'confidence': 'NONE', 'method': 'unresolved',
        'device_count': 0, 'conflict': False, 'ndm_count': 0, 'ehm_count': 0,
    }

# ── Output writers ────────────────────────────────────────────────────────────

PATCH_FIELDS = [
    'CIDR', 'CANONICAL_LOCATION', 'SITE_CODE', 'NET_TYPE', 'ROUTING_DOMAIN',
    'HERITAGE', 'DATA_QUALITY', 'SOURCE', 'RESOLUTION_METHOD',
    'RESOLUTION_CONFIDENCE', 'DEVICE_COUNT', 'CONFLICT_FLAG',
]

REVIEW_FIELDS = PATCH_FIELDS + ['REVIEW_REASON']

def _write_csv(path, fields, rows, stem, version, script):
    ts = datetime.now(timezone.utc).isoformat(timespec='seconds')
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write(f"#STEM={stem}\n")
        f.write(f"#VERSION={version}\n")
        f.write(f"#ROWS={len(rows)}\n")
        f.write(f"#GENERATED_BY={script}\n")
        f.write(f"#GENERATED_AT={ts}\n")
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        w.writerows(rows)

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description='Resolve CSNA UNKNOWN subnets to IPAM entries using NDM/EHM location data.')
    p.add_argument('--ipam-db',  default='./ipam-db', metavar='DIR',
                   help='ipam-db/ directory (default: ./ipam-db)')
    p.add_argument('--output',   default='./unknown_subnet_patch_v1.0.csv', metavar='FILE',
                   help='Output patch CSV')
    p.add_argument('--dry-run',  action='store_true',
                   help='Print resolution table, write nothing')
    args = p.parse_args()

    ipam_db = pathlib.Path(args.ipam_db)
    if not ipam_db.is_dir():
        print(f"ERROR: --ipam-db '{ipam_db}' is not a directory", file=sys.stderr)
        sys.exit(1)

    print(f"\nresolve_unknown_subnets.py v{__version__}", file=sys.stderr)
    print(f"{'='*50}", file=sys.stderr)
    print(f"Loading reference data from {ipam_db}...", file=sys.stderr)

    ndm   = load_ndm(ipam_db)
    ehm   = load_ehm(ipam_db)
    lm    = load_location_master(ipam_db)

    print(f"\nResolving {len(UNKNOWN_SLASH24S)} /24s...", file=sys.stderr)

    patch_rows  = []
    review_rows = []

    # Summary counters
    by_method   = Counter()
    by_conf     = Counter()

    for cidr_str in sorted(UNKNOWN_SLASH24S):
        res = resolve_slash24(cidr_str, ndm, ehm, lm)

        row = {
            'CIDR':                  cidr_str,
            'CANONICAL_LOCATION':    res['location'],
            'SITE_CODE':             res['site_code'],
            'NET_TYPE':              res['net_type'],
            'ROUTING_DOMAIN':        res['routing_domain'],
            'HERITAGE':              res['heritage'],
            'DATA_QUALITY':          'Inferred',
            'SOURCE':                'resolve_unknown_subnets.py v1.0.0',
            'RESOLUTION_METHOD':     res['method'],
            'RESOLUTION_CONFIDENCE': res['confidence'],
            'DEVICE_COUNT':          res['device_count'],
            'CONFLICT_FLAG':         'YES' if res['conflict'] else 'NO',
        }

        by_method[res['method']] += 1
        by_conf[res['confidence']] += 1

        if res['confidence'] in ('HIGH', 'MEDIUM') and not res['conflict']:
            patch_rows.append(row)
        else:
            review_row = dict(row)
            if res['confidence'] == 'NONE':
                review_row['REVIEW_REASON'] = 'No NDM/EHM/hint signal — needs manual assignment'
            elif res['conflict']:
                review_row['REVIEW_REASON'] = 'Multiple locations found — verify correct assignment'
            else:
                review_row['REVIEW_REASON'] = 'Low confidence — hint-table only, verify before import'
            review_rows.append(review_row)

    # ── Print resolution table ──────────────────────────────────────────────
    print(f"\n{'CIDR':<22}  {'CONF':<7}  {'METHOD':<12}  {'DEVS':>4}  LOCATION", file=sys.stderr)
    print(f"{'─'*22}  {'─'*7}  {'─'*12}  {'─'*4}  {'─'*40}", file=sys.stderr)
    for cidr_str in sorted(UNKNOWN_SLASH24S):
        res = resolve_slash24(cidr_str, ndm, ehm, lm)
        conf_str = res['confidence']
        flag = ' ⚠' if res['conflict'] else ('  ' if conf_str != 'NONE' else ' ?')
        print(f"  {cidr_str:<20}  {conf_str:<7}  {res['method']:<12}  "
              f"{res['device_count']:>4}  {res['location']}{flag}", file=sys.stderr)

    # ── Summary ────────────────────────────────────────────────────────────
    print(f"\n{'='*50}", file=sys.stderr)
    print(f"Resolution summary:", file=sys.stderr)
    for m, c in sorted(by_method.items()):
        print(f"  {m:<15}  {c:>3} subnets", file=sys.stderr)
    print(f"\nConfidence breakdown:", file=sys.stderr)
    for conf in ('HIGH', 'MEDIUM', 'LOW', 'NONE'):
        c = by_conf.get(conf, 0)
        print(f"  {conf:<8}  {c:>3}", file=sys.stderr)
    print(f"\nPatch-ready (HIGH/MEDIUM, no conflict):  {len(patch_rows)}", file=sys.stderr)
    print(f"Needs review (LOW/NONE or conflict):     {len(review_rows)}", file=sys.stderr)

    if args.dry_run:
        print(f"\n--dry-run: no files written.", file=sys.stderr)
        return

    # ── Write outputs ───────────────────────────────────────────────────────
    out = pathlib.Path(args.output)
    _write_csv(out, PATCH_FIELDS, patch_rows,
               stem='unknown_subnet_patch',
               version='1.0',
               script=f'resolve_unknown_subnets.py v{__version__}')
    print(f"\nPatch CSV:   {out}  ({len(patch_rows)} rows)", file=sys.stderr)

    if review_rows:
        rev_out = out.parent / out.name.replace('_patch_', '_review_')
        _write_csv(rev_out, REVIEW_FIELDS, review_rows,
                   stem='unknown_subnet_review',
                   version='1.0',
                   script=f'resolve_unknown_subnets.py v{__version__}')
        print(f"Review CSV:  {rev_out}  ({len(review_rows)} rows)", file=sys.stderr)

    print(f"\nNext steps:", file=sys.stderr)
    print(f"  1. Review {out.name} — confirm locations before import", file=sys.stderr)
    print(f"  2. Review {rev_out.name if review_rows else 'N/A'} — manually assign locations", file=sys.stderr)
    print(f"  3. python3 ipam-db.py --import {out}  (after review)", file=sys.stderr)
    print(f"  4. python3 ipam-db.py --cross-check", file=sys.stderr)
    print(f"  5. Re-run generate_csna_hostgroups.py to verify UNKNOWN count drops", file=sys.stderr)

if __name__ == '__main__':
    main()
