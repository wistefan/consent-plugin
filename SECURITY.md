# Security Policy

`consent-plugin` gates access to personal data. A defect in it can release data
a subject never consented to, so please treat findings here as sensitive.

## Reporting a vulnerability

**Do not open a public issue for a suspected vulnerability.**

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/wistefan/consent-plugin/security/advisories/new)
on this repository. If that is unavailable to you, contact a maintainer listed in
[CODEOWNERS](.github/CODEOWNERS) directly.

Please include:

- the version, image tag or commit you tested,
- the plugin configuration in use, with secrets redacted,
- what you observed and what you expected — for a gate, "the response was
  released" or "the response was denied" is the key fact,
- a minimal reproduction if you have one.

We aim to acknowledge a report within three working days and to agree a
disclosure timeline with you before anything is published.

## What is in scope

Anything that changes the access decision or leaks data around it, including:

- a response released without a granted consent from the resolved data owner,
- a consent granted to one consuming participant authorising another,
- data ownership being taken from the requestor rather than from the data,
- information about denied data reaching the client (headers, timing, counts),
- credentials or personal data reaching logs, metrics, or the audit sink in a
  form that was not intended,
- a way to make the plugin fail open that the operator did not configure,
- suppressing or forging audit records.

## What is out of scope

- The absence of JWT signature verification. The plugin decodes the token and
  relies on an authentication plugin earlier in the route; this is documented in
  the README and is a deployment requirement, not a defect in the plugin.
- Findings that require an already-compromised APISIX instance or plugin runner.
- The local development stack under `dev/`, which uses fixed credentials on
  purpose and is not for deployment.

## Supported versions

Fixes land on `main` and are published as a new release. Older tags are not
patched; please upgrade.
