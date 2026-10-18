# AWS CloudTrail success-filter regression checks

Successful raw CloudTrail events for these IAM operations omit `errorCode`.
Failed requests include an error code such as `AccessDenied`. See the
[AWS record reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html).

Run from the repository root with Python 3.10 or newer:

```sh
python -m pip install -r tests/requirements.txt
python -m unittest discover -s tests -v
```

The JSON fixtures are synthetic, minimal CloudTrail event fragments with explicit
expected rule matches. The checks evaluate pySigma's parsed conditions, covering
successful requests, denied requests, another error, unrelated activity, and
every policy operation already selected by the rule. They fail on unsupported
condition types rather than silently treating them as nonmatches.

To compare the same tests against an older checkout, set `AWS_DETECTION_REPO`
to its root. The fixtures and test code still come from the current checkout.

These local checks do not execute the Splunk queries or validate ingestion field
mappings. The six affected SPL blocks use the same absent-error condition. The
following isolated replay can be run in Splunk to verify that predicate:

```spl
| makeresults count=2
| streamstats count as case_number
| eval _raw=if(case_number=1,
    "{\"eventName\":\"CreateAccessKey\"}",
    "{\"eventName\":\"CreateAccessKey\",\"errorCode\":\"AccessDenied\"}")
| spath
| search eventName="CreateAccessKey" NOT errorCode=*
| table case_number eventName errorCode
```

Expected: only case 1 is returned. Substituting the previous
`errorCode=success` condition returns no events. Substitute `AttachUserPolicy`
in both fixture records and the search to reproduce the policy-rule case.
