# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Email **hello@proteles.com**, the security contact Proteles publishes in
[`https://proteles.com/.well-known/security.txt`](https://proteles.com/.well-known/security.txt).
If the two ever differ, the address in `security.txt` is the one to use, and
its `Policy` link is the disclosure policy.

Please include:

- the package or SDK and the version (`@proteles/bff` 0.3.0, `ProtelesAuth`
  0.1.0, …);
- what an attacker can do, and what they need to do it;
- steps or a proof of concept that reproduces it, against your own app or
  tenant only.

We will acknowledge the report and keep you informed while it is fixed.

## Scope

Everything in this repository: the `@proteles/*` npm packages, the iOS and
Android SDKs, the examples and the scripts. A problem in the Proteles service
itself goes to the same address.

## Supported versions

Fixes are released for the latest npm minor version (all `@proteles/*`
packages share one version) and the latest release of the native SDKs. While
the major version is `0`, upgrading to the latest minor is the fix.
