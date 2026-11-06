# DF-017 login and file activity investigation

**All records, accounts, hosts, addresses and file paths are invented. The referenced files themselves are not supplied.**

## Case brief

A training evidence portal recorded repeated login failures and file-access
events on 20 October 2026. Determine which successful sessions meet the stated
rule and what subsequent downloads are recorded. Prioritise a session for
review without assuming an intrusion or attributing activity to a person.

The exports are deliberately unsorted and contain duplicate and malformed
records. Their timestamps use Z and +01:00 offsets. Assume both sources use
the same session-ID namespace. Clock accuracy, log completeness and the
real-world identity behind an account have not been independently established.

## Run from this folder

Python 3.10 or newer, standard library only. No notebook, pip install or API key.

| Purpose | macOS or Linux | Windows PowerShell |
| --- | --- | --- |
| Run starter or full analysis | `python3 analyze_case.py` | `py analyze_case.py` |
| Run login stage only | `python3 analyze_case.py --stage logins` | `py analyze_case.py --stage logins` |
| Check function 1 | `python3 check_solution.py LoginChecks` | `py check_solution.py LoginChecks` |
| Check function 2 | `python3 check_solution.py DownloadChecks` | `py check_solution.py DownloadChecks` |
| Run all checks | `python3 check_solution.py` | `py check_solution.py` |

If Windows does not recognise `py`, use `python` after checking that
`python --version` reports Python 3.10 or newer. Otherwise install Python 3.

Implement only `find_login_sequences` and `correlate_downloads` in
`analyze_case.py`. Their docstrings are the exact contracts. The supplied
loader, evidence, manifest and tests remain unchanged.

## Rules and field meanings

1. For every SUCCESS at T, group on `(username, source_ip, host)` and count
   FAIL events where **T - 5 minutes <= time < T**. Flag at least three.
   Each success is evaluated independently; earlier successes do not reset
   the window. A failure may support more than one alert.
2. Join file events using **username AND host AND session_id**. Keep only
   `action == "DOWNLOAD"`, `result == "SUCCESS"`, and **T <= time <= T + 10 minutes**.
   Count events, even if their paths repeat. Sum their integer bytes values.
   Retain alerts with zero matches. Sort by descending byte total, then time
   and success event ID. This ranking measures recorded volume, not guilt.
3. `event_id` identifies one event within its source. `session_id` links the
   two sources. `bytes` is the transfer size recorded by the application;
   independent transfer completion and destination evidence are not supplied.

## Evidence handling supplied for you

`evidence_tools.py` verifies the original CSV byte hashes against
`evidence_manifest.json`, trims outer whitespace, validates rows, requires
explicit timezone offsets, converts times to UTC and byte strings to integers,
and removes identical repeated event IDs. It records duplicate and rejected
CSV row numbers in `audit.json`. Conflicting versions of an ID stop analysis.
Rejected rows remain in the source; they are excluded from computed findings.

The starter writes `audit.json` before stopping at the first TODO. Function 1
adds `login_alerts.json`; the completed program adds `summary.json`. Rerun after
every change: old output files can be stale. A hash match demonstrates agreement
with this supplied baseline; it does not establish authenticity or completeness.
`.gitattributes` preserves CSV bytes through Git on all operating systems.

## Verified results -- complete this section

| Source | Data rows excluding header | Accepted unique | Duplicate | Rejected |
| --- | --- | --- | --- | --- |
| auth_log.csv | 60 | 54 | 1 | 5 |
| file_log.csv | 35 | 30 | 1 | 4 |

- SHA-256 check outcome and what it establishes: Match evidence, Copy is byte identical, not that the logs are authentic/complete.
- One rejected event ID and the exact rejection reason: A900, invalid isoformat string: 'not-a-time'
- Number of flagged successful sessions: 3

| Success ID | Account | Session | Supporting failure IDs | Download IDs | Event count | Total bytes |
| --- | --- | --- | --- | --- | --- | --- |
| A005 | analyst01 | S-104 | A002, A003, A003, A004 |F001,F001,F002,F003 |9 |10752000 |
| A018 | analyst02 | S-304 | A015, A016, A017 |F013,F014 |6 |2002048 |
| A014 | backup_svc | S-204 | A011, A012, A013 |F011,F012 |5 |8192 (Fail) |


## Manual evidence check -- do this without asking AI to count for you

For the highest-volume flagged session, find every supporting failure, the
success and every qualifying download in the original CSV files. Record their
original timestamps and UTC equivalents. Add rows as needed.

| Source and event ID | Original timestamp | UTC timestamp | What the row records |
| --- | --- | --- | --- |
| auth_log.csv A002 |2026-10-20T08:58:00Z |2026-10-20T08:58:00Z | FAIL, analyst01, 203.0.113.44, DF-PORTAL01 |
| auth_log.csv A003 |2026-10-20T09:00:00Z |2026-10-20T09:00:00Z | FAIL (first of two identical copies) |
| auth_log.csv A004 |2026-10-20T10:01:00+01:00 |2026-10-20T09:01:00 | FAIL, +01:00 offset |
| auth_log.csv A005 |2026-10-20T09:03:00Z |2026-10-20T09:03:00Z | SUCCESS, session S-104 |
| file_log.csv F001 |2026-10-20T09:05:00Z |2026-10-20T09:05:00Z | DOWNLOAD evidence_export.zip, 5242880 bytes |
| file_log.csv F002 |2026-10-20T10:07:00+01:00 |2026-10-20T09:07:00 | DOWNLOAD interview_notes.pdf, 262144 bytes |
| file_log.csv F003 |2026-10-20T09:13:00Z |2026-10-20T09:13:00Z | DOWNLOAD hashes.txt, 4096 bytes |


- Manual sum of download bytes, showing the addition: 5242880+262144+4096=5509120bytes
- A001 versus A002: which qualifies for the A005 window and why? A001 before time window by 1 second and not qualified, A002 qualifies as it is on or within time window.
- F003 versus F004: which qualifies for the A005 follow-up and why? F003 qualifies, F004 ouside time window by 1 second.
- Why F005 is excluded even though the account matches: Session_ID = S-OTHER and not the same as S_104
- One +01:00 timestamp and its equivalent UTC time: Subtract 1 hour => 2026-10-20T09:07:00Z
- One limitation of excluding malformed records: The analysisi rejected/excluded some events. It does not mean they are not valid or did not happen and if they did we have possibly not made a complete analysis as we can have missed some.

## Checks actually run

Command, date and actual final result (paste output, including failures if any):

```text

2026-11-04
jorgenhansson@Jorgens-MacBook-Pro JorHan26-DI8001-Exercises-W44_GIT_AI % python3 check_solution.py                 
test_supplied_case (__main__.CaseChecks.test_supplied_case) ... ok
test_closed_window_includes_zero_and_ten_minutes (__main__.DownloadChecks.test_closed_window_includes_zero_and_ten_minutes) ... ok
test_configurable_followup (__main__.DownloadChecks.test_configurable_followup) ... ok
test_does_not_mutate_either_input (__main__.DownloadChecks.test_does_not_mutate_either_input) ... ok
test_empty (__main__.DownloadChecks.test_empty) ... ok
test_keeps_alert_with_no_downloads (__main__.DownloadChecks.test_keeps_alert_with_no_downloads) ... ok
test_ranking_event_ties_and_repeated_paths (__main__.DownloadChecks.test_ranking_event_ties_and_repeated_paths) ... ok
test_requires_session_account_host_action_and_success (__main__.DownloadChecks.test_requires_session_account_host_action_and_success) ... ok
test_conflicting_ids_are_not_silently_discarded (__main__.EvidenceChecks.test_conflicting_ids_are_not_silently_discarded) ... ok
test_equivalent_time_offsets_and_missing_offset (__main__.EvidenceChecks.test_equivalent_time_offsets_and_missing_offset) ... ok
test_hash_mismatch_stops_analysis (__main__.EvidenceChecks.test_hash_mismatch_stops_analysis) ... ok
test_supplied_quality_counts_and_duplicates (__main__.EvidenceChecks.test_supplied_quality_counts_and_duplicates) ... ok
test_account_ip_and_host_must_all_match (__main__.LoginChecks.test_account_ip_and_host_must_all_match) ... ok
test_does_not_mutate_input (__main__.LoginChecks.test_does_not_mutate_input) ... ok
test_empty (__main__.LoginChecks.test_empty) ... ok
test_failures_without_success_are_not_alerts (__main__.LoginChecks.test_failures_without_success_are_not_alerts) ... ok
test_outside_equal_and_future_failures_do_not_count (__main__.LoginChecks.test_outside_equal_and_future_failures_do_not_count) ... ok
test_parameters_and_each_success_window (__main__.LoginChecks.test_parameters_and_each_success_window) ... ok
test_ties_and_output_order (__main__.LoginChecks.test_ties_and_output_order) ... ok
test_unsorted_rows_and_evidence_order (__main__.LoginChecks.test_unsorted_rows_and_evidence_order) ... ok
test_window_includes_exactly_five_minutes (__main__.LoginChecks.test_window_includes_exactly_five_minutes) ... ok

----------------------------------------------------------------------
Ran 21 tests in 0.006s

OK

```

All 21 supplied checks should pass. Passing these checks is limited validation
of the stated classroom rule, not certification of a forensic tool.

## AI interpretation and our final finding

Prompt 3 response about the overstated claim (keep the actual response):


“Belongs to the attacker” — the logs record an account name (analyst01) and an IP, not a person, and nothing supplied shows an intrusion occurred. “Proves this person stole evidence” — the record shows three successful DOWNLOAD events (F001, F002, F003, 5,509,120 bytes) in session S-104 after login A005; file contents, destination, transfer completion and authorisation are not in evidence, and the activity may be legitimate. “Hashes prove the logs are authentic and complete” — a matching SHA-256 shows the CSVs are byte-identical to the supplied manifest baseline only; 9 rows were rejected and clock accuracy is unverified.

Cautious rewrite:

Session S-104 (login A005 at 09:03:00Z, preceded by failures A002–A004) has the largest recorded download volume, 5,509,120 bytes across F001–F003, and therefore merits priority review. The logs are consistent with the supplied manifest, but they do not identify who used the account, show that the downloads were unauthorised or completed, or establish that the export is authentic and complete.

One claim we corrected or independently verified, with event IDs:

Recorded activity: session S-104 is the leading flagged session. Login A005 (analyst01, 203.0.113.44, DF-PORTAL01) succeeded at 09:03:00Z after three failures from the same account, address and host within the preceding five minutes (A002 08:58:00Z, A003 09:00:00Z, A004 09:01:00Z). Within the following ten minutes the file log records three successful DOWNLOAD events in S-104: F001 (09:05:00Z, 5,242,880 bytes), F002 (09:07:00Z, 262,144 bytes) and F003 (09:13:00Z, 4,096 bytes), totalling 5,509,120 bytes. By comparison, session S-304 (A018, analyst02, failures A015–A017) shows one download, F013, of 2,048 bytes, and S-204 (A014, backup_svc) shows none. S-104 is prioritised on recorded volume, not on any conclusion about intent.

Inference and limits: the pattern is consistent with, but does not prove, unauthorised access. A benign explanation is an authorised user mistyping a password and then retrieving case files as part of normal work. Two limitations: nine malformed rows were excluded (five auth, four file), so counts are a lower bound; and clock alignment is unverified—F008 records a download in S-104 one second before A005. The hash check and all 21 supplied checks passed on 2026-11-04; this confirms consistency with the supplied baseline only.

Next evidence requests: the portal’s original authentication and transfer logs for 08:55–09:15Z, and network or endpoint records showing whether F001–F003 completed and to where.


Final 180-220 word finding, reviewed and edited by the pair:

Observed. Session S-104 is the leading flagged session. In auth_log.csv, account analyst01 from 203.0.113.44 on DF-PORTAL01 failed three times (A002 08:58:00Z, A003 09:00:00Z, A004 09:01:00Z) and then logged in successfully (A005, 09:03:00Z). file_log.csv records three successful DOWNLOAD events in S-104 within ten minutes: F001 09:05:00Z (5,242,880 bytes), F002 09:07:00Z (262,144 bytes) and F003 09:13:00Z (4,096 bytes), in total 5,509,120 bytes. The comparison session S-304 (A018, analyst02, failures A015–A017) shows one download, F013, of 2,048 bytes; S-204 (A014, backup_svc) shows none. S-104 is prioritised because of recorded volume, not because intent has been established.

Inferred. The sequence is consistent with password guessing followed by access, but an authorised user who mistyped a password and then retrieved case files as normal work is an equally plausible explanation. A logged DOWNLOAD does not identify a person, show lack of authorisation, or prove that data left the system.

Limitations. Nine malformed rows were excluded (five authentication, four file), so all counts are a lower bound. Clock alignment is unverified: F008 records a download in S-104 one second before login A005. The hash check and the 21 supplied checks passed on 2026-11-04, which only shows consistency with the supplied baseline.

Next evidence. (1) The portal's original authentication and transfer logs for 08:55–09:15Z, to validate the export and the excluded rows. (2) Network or endpoint records showing whether F001–F003 completed and their destination.

It must cite evidence IDs, separate observation from inference, include a
comparison session, two limitations, one benign explanation and two next
evidence requests. Do not claim that an account or IP identifies a person.

## AI use and pair review

- Names of both partners: Jörgen Hansson (Alone)
- GenAI tool/ChatGPT date and displayed model: Claude (claude.ai), model shown as Claude Fable 5.1, used 2 and 4 November 2026
- Prompts used and what they produced: Prompt 1 produced find_login_sequences with pseudocode and an explanation of the (username, source_ip, host) grouping key and the <= / < boundaries. Prompt 2 produced correlate_downloads with an explanation of the three-field session join, the closed time window and why zero-download alerts stay in. Prompt 3 produced the critique of the overstated claim (pasted above). Prompt 4 produced the draft finding, which I verified against my manual timeline and edited.
- One follow-up question or correction, with a short response excerpt: When identifying failures for A005 I counted A002, A006 and A007. The tool corrected this: "A006 and A007 fail the grouping test ... A006 — different IP; A007 — different host", and pointed out I had missed A003 (a duplicated row) and A004 (a +01:00 timestamp). Later my manual byte sum (266,240) omitted F001 for the same duplicate-row reason; corrected to 5,242,880 + 262,144 + 4,096 = 5,509,120, matching summary.json.
- Results of code and evidence checks performed: python3 check_solution.py on 2026-11-04: Ran 21 tests, OK. python3 analyze_case.py: SHA-256 match, 54/30 accepted rows, three flagged sessions (A005, A018, A014). Manual timeline for S-104 (A002–A005, F001–F003) agrees with login_alerts.json and summary.json; byte total verified by hand.


## Submit

Submit one public repository URL per pair through the course route. Include the ten
starter project files and the newly generated `audit.json`, `login_alerts.json`,
and `summary.json`. Complete this README. The repository needs a starting
commit and a finished commit. The accompanying student guide gives the
90-minute schedule; `GitHub_CLI_Guide.docx` covers setup and upload.
Only synthetic exercise files belong in this repository. Keep credentials out.

Optional stretch after the core task: use the interactive Python console to
compare `min_failures=2` with `min_failures=3`, without changing the defaults or
original evidence. Which extra session appears, and does that change what you
can conclude? Record this separately from the required default output.
