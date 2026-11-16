# Security policy

Report suspected vulnerabilities privately using
[GitHub private vulnerability reporting](https://github.com/curlewlabs-com/app-store-jws/security/advisories/new).
Include the affected release or source revision, the runtime and its version,
the input that shows the problem (a JWS or certificate, with anything private
removed), and what you observed against what you expected. Do not put a working
forgery in a public issue.

A payload this package returns as verified that the App Store did not sign, or a
certificate the DER reader reads differently from strict DER, is a
vulnerability. So is input that makes it throw instead of refusing. The limits
the README states under "What is verified, and what is not" - no revocation
check, no check of which app or environment a payload is for - are the design,
not vulnerabilities, though reports that one of them is wrongly described are
welcome.

Curlew Labs maintains this repository; Jeffrey Wall
([jeffwall-curlewlabs](https://github.com/jeffwall-curlewlabs)) is the release
and security contact through GitHub. Reports are reviewed on a best-effort basis
without a guaranteed response time. Fixes target the latest release; older
releases have no promised backport.
