# Shared security workflow

Call `.github/workflows/security.yml` at a reviewed commit SHA. Gitleaks scans the
complete fetched history and Zizmor audits the workflows; both verify their
detectors before scanning the caller repository.

## CodeQL execution mode

The `codeql-mode` input is explicit and defaults to `advanced`:

| Mode | Behavior |
| --- | --- |
| `advanced` | Run the existing CodeQL init/analyze job and upload its results. |
| `default` | Keep GitHub-managed Default setup and verify its independent analysis instead of uploading a duplicate advanced analysis. |
| `unavailable` | Do not run CodeQL in a private repository that explicitly declares Code Security unavailable. The job summary records this coverage limitation. Public repositories cannot select this mode. |

`language` retains its existing meaning in advanced mode. In default mode it is
the comma-separated list of required native analysis jobs, for example
`rust,actions` or `c-cpp`.

Default mode requires an active workflow with GitHub's native
`dynamic/github-code-scanning/codeql` path. For same-repository pull requests
targeting the default or a protected branch it waits for that workflow on the
exact PR head; for updates to the default or protected branch it uses the current
commit. Every requested language must complete successfully. API errors,
missing languages, disabled workflows, failed runs, and timeouts remain failures.
Cross-repository PRs, PRs targeting unprotected non-default branches, and other
branch events report that no analysis is claimed under Default setup's trigger
scope. The separate GitHub CodeQL result check still evaluates findings;
the execution-policy check does not assert the absence of vulnerabilities.

The caller grants `actions: read`, `contents: read`, and
`security-events: write` to the reusable call. The policy job uses only
`actions: read` and `contents: read`; the advanced analysis job retains the
existing write permission.
No administration token, repository-setting changes, or automatic license
activation is used. Selecting unavailable mode does not provide replacement SAST;
Gitleaks and workflow security continue as independent blocking checks.

Run `python3 -m unittest discover -s tests -v` to exercise the exact inline policy,
including rejection controls. The self-test workflow also runs actionlint and
the full reusable workflow with the default advanced mode.
