"""DF-017 synthetic investigation. Implement only the two TODO functions."""
import argparse
from datetime import timedelta
from pathlib import Path
from evidence_tools import load_case, write_json

BASE = Path(__file__).resolve().parent

def find_login_sequences(rows, min_failures=3, window_minutes=5):
    """Find successes preceded by repeated failures; return a list of dicts.

    Input: validated auth dictionaries in arbitrary order. timestamp is an
    aware UTC datetime. Group on (username, source_ip, host), all case-sensitive.
    For EACH SUCCESS at time T, select FAIL rows from that same group where
    T - timedelta(minutes=window_minutes) <= failure time < T.
    If there are at least min_failures, emit exactly one dict with these keys:
      username, source_ip, host, session_id (copied from the success),
      success_id (success event_id), success_time (success timestamp),
      failure_ids (list ordered by timestamp then event_id).
    Sort the output by (success_time, success_id). Emit nothing below threshold.
    Do not reset at earlier successes: this rule evaluates each success window
    independently. A failure may support more than one window.
    Empty input returns []. Do not mutate input. No hardcoded IDs or outcomes.
    Parameters are positive numbers. Use loops, dictionaries, lists, sorted,
    and the imported timedelta. No additional packages are needed.
    """
    # TODO 1: replace this raise with your implementation.
    # raise NotImplementedError('Complete find_login_sequences')

    # Step 1: one pass over the input. Failures go into a dictionary keyed by
    # (username, source_ip, host); successes go into a list.
    failures_by_group = {}
    successes = []
    for row in rows:
        key = (row['username'], row['source_ip'], row['host'])
        if row['result'] == 'FAIL':
            failures_by_group.setdefault(key, []).append(row)
        elif row['result'] == 'SUCCESS':
            successes.append(row)

    # Step 2: evaluate every success on its own.
    window = timedelta(minutes=window_minutes)
    alerts = []
    for success in successes:
        key = (success['username'], success['source_ip'], success['host'])
        success_time = success['timestamp']
        window_start = success_time - window
        # Lower bound included (<=), success instant excluded (<).
        supporting = [f for f in failures_by_group.get(key, [])
                      if window_start <= f['timestamp'] < success_time]
        if len(supporting) < min_failures:
            continue
        supporting = sorted(supporting, key=lambda f: (f['timestamp'], f['event_id']))
        alerts.append({
            'username': success['username'],
            'source_ip': success['source_ip'],
            'host': success['host'],
            'session_id': success['session_id'],
            'success_id': success['event_id'],
            'success_time': success_time,
            'failure_ids': [f['event_id'] for f in supporting],
        })

    # Step 3: deterministic output order.
    return sorted(alerts, key=lambda a: (a['success_time'], a['success_id']))

def correlate_downloads(alerts, file_rows, followup_minutes=10):
    """Enrich each alert with file activity; return a new list of new dicts.

    Input timestamps are aware UTC datetime objects; bytes is already an int.
    For each alert at success_time T, match file rows on ALL of
    (username, host, session_id). Keep only action == 'DOWNLOAD',
    result == 'SUCCESS', and T <= timestamp <= T + timedelta(minutes=followup_minutes).
    Sort matching rows by (timestamp, event_id). Copy the original alert fields
    into a NEW dict, then add:
      download_ids: matching event IDs in that order
      download_count: number of matching events (not distinct paths)
      total_bytes: sum of the matching bytes values
    Keep alerts with no matches: [], 0, 0. Sort returned alerts by descending
    total_bytes, then success_time, then success_id. Empty alerts returns [].
    Do not mutate either input or its nested lists. Do not merge sessions based
    only on a shared account. No hardcoded IDs or outcomes; no extra packages.
    """
    # TODO 2: replace this raise with your implementation.
    # raise NotImplementedError('Complete correlate_downloads')

    followup = timedelta(minutes=followup_minutes)
    results = []
    for alert in alerts:
        start = alert['success_time']
        end = start + followup          # both endpoints included
        matching = []
        for row in file_rows:
            same_session = (row['username'] == alert['username']
                            and row['host'] == alert['host']
                            and row['session_id'] == alert['session_id'])
            if not same_session:
                continue
            if row['action'] != 'DOWNLOAD' or row['result'] != 'SUCCESS':
                continue
            if start <= row['timestamp'] <= end:
                matching.append(row)
        matching = sorted(matching, key=lambda r: (r['timestamp'], r['event_id']))

        enriched = dict(alert)                                # new dict, original untouched
        enriched['failure_ids'] = list(alert['failure_ids'])  # copy the nested list too
        enriched['download_ids'] = [r['event_id'] for r in matching]
        enriched['download_count'] = len(matching)
        enriched['total_bytes'] = sum(r['bytes'] for r in matching)
        results.append(enriched)

    return sorted(results, key=lambda a: (-a['total_bytes'], a['success_time'], a['success_id']))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=['logins', 'all'], default='all')
    args = parser.parse_args()
    try:
        auth, files, audit = load_case(BASE)
    except ValueError as error:
        parser.exit(1, f'Evidence check failed: {error}\n')
    write_json(BASE / 'audit.json', audit)
    print('SHA-256 checks match the supplied manifest.')
    for name in ['auth_log.csv', 'file_log.csv']:
        info = audit[name]
        print(f"{name}: {info['data_rows']} rows; {info['accepted']} accepted; "
              f"{len(info['duplicates'])} duplicate; {len(info['rejected'])} rejected.")
    print('Saved audit.json. A hash match does not prove origin or completeness.')
    try:
        alerts = find_login_sequences(auth)
        write_json(BASE / 'login_alerts.json', alerts)
        print(f'Found {len(alerts)} login sequences; saved login_alerts.json.')
        if args.stage == 'logins':
            return
        findings = correlate_downloads(alerts, files)
    except NotImplementedError as error:
        print(f'Starter ready: {error}. Previously generated outputs may be stale.')
        return
    summary = {'case': 'DF-017 training data only',
               'rule': {'min_failures': 3, 'login_window_minutes': 5, 'followup_minutes': 10},
               'evidence_sha256': audit['sha256'], 'findings': findings,
               'interpretation': 'Rule matches identify sessions for review; they do not prove intrusion, exfiltration, or identity.'}
    write_json(BASE / 'summary.json', summary)
    print('Saved summary.json. Verify event IDs against both original CSV files.')
    for item in findings:
        print(f"{item['success_id']} {item['username']} {item['session_id']}: "
              f"{len(item['failure_ids'])} failures, {item['download_count']} downloads, "
              f"{item['total_bytes']} bytes")

if __name__ == '__main__':
    main()
