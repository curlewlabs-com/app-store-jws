# Contributing

Thanks for your interest in improving `app-store-jws`. The bar for a change is
whether a payload is still returned only when the App Store signed it, and
anything else is still refused rather than thrown on. Bug fixes, support for a
runtime it does not run on yet, test coverage from more of Apple's real
certificates, and clearer docs are all welcome.

Open a pull request that says what behavior changes and how you verified it.
CI runs these on every pull request, with the Node version
`.github/workflows/ci.yml` pins:

```sh
npm ci --ignore-scripts
npm run typecheck
npm test
```

## Before a large change

Open an issue describing the problem first. `src/apple-signed-data.ts` carries
the verification guarantee - the pinned root compared byte for byte, Apple's
role markers on the intermediate and the leaf, certificate validity judged at
the payload's `signedDate` - and `src/x509-certificate.ts` accepts only DER's
one encoding of each element it reads. The README's "What is verified, and what
is not" records what is left out by design. A short discussion up front saves
rework. A fix for a vulnerability goes through [SECURITY.md](SECURITY.md)
instead.

## Releasing

A patch or minor release needs no approval: whoever cuts it follows the steps
below in order, on a `main` commit whose required checks have passed. A major
version, a 1.0, or a minor before 1.0 that changes an interface consumers use
needs the maintainer's explicit approval before its tag is pushed.

A release is a fixed `vMAJOR.MINOR.PATCH` tag on a `main` commit and the GitHub
Release published on it, with the `npm pack` tarball as its asset. The package
is not on the npm registry: consumers install that asset by its URL.

1. Set the version in the pull request that makes the change: `version` in
   `package.json` and `package-lock.json`, and the install line in the README.
   A fix is a patch release. Under 0.x, a change to what consumers import is a
   minor release.
2. After it merges, check its merge commit on `main`: the CI and CodeQL runs on
   that commit passed, CodeQL analyzed each language its default setup lists,
   and `main` has no open code scanning alert.

   ```sh
   repo=curlewlabs-com/app-store-jws
   gh run list --commit <commit>
   gh api "repos/$repo/code-scanning/analyses?ref=refs/heads/main" \
     --jq '.[] | [.commit_sha, .category] | @tsv'
   gh api "repos/$repo/code-scanning/alerts?state=open&ref=refs/heads/main" \
     --jq length
   ```

3. Tag that commit and push the tag:

   ```sh
   git tag -a v0.2.1 -m v0.2.1 <commit>
   git push origin v0.2.1
   ```

4. The tag starts the Release workflow (`.github/workflows/release.yml`). It
   runs CI on the tagged commit, builds the tarball with `npm pack`, attests
   its build provenance, and creates a draft release with the tarball attached
   and notes giving the install line and the tarball's integrity. The workflow
   says what it refuses before any of that.
5. Check the draft against a local build. Pack the tagged commit yourself, with
   the Node version the workflows pin, and compare it with the draft's asset:
   the two are byte-identical. Then verify the attestation.

   ```sh
   git switch --detach v0.2.1
   npm ci --ignore-scripts
   mkdir ../local
   npm pack --pack-destination ../local
   gh release download v0.2.1 --pattern '*.tgz' --dir ../draft
   cmp ../local/*.tgz ../draft/*.tgz
   gh attestation verify ../draft/*.tgz -R curlewlabs-com/app-store-jws
   ```

6. Put a paragraph at the top of the draft's notes saying what changed for a
   consumer, naming the pull request, and keep the install line and integrity
   below it. Then publish the draft:

   ```sh
   gh release view v0.2.1 --json body --jq .body > notes.md
   # add the paragraph to notes.md
   gh release edit v0.2.1 --notes-file notes.md --draft=false
   ```

Publishing cannot be undone. The repository refuses updates and deletions of
`v*.*.*` tags, and a published release, its tag and its asset are immutable, so
a mistake in a published release is fixed by a new version.
