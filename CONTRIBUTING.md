# Contributing

## Where this repository lives

The canonical **public** repository is
<https://forgejo.xtrape.com/xtrape-project/linux-ops-widget-nodejs> — anonymously
readable and clonable, mirrored one-way to the platforms listed at
<https://xtrape.com/source>. No GitHub repository is published for this project
at this time; none is canonical.

Development happens on the maintainers' private Forgejo organisation; the
public repository receives the reviewed content of each merge as one
append-only snapshot commit. A pull request opened on the public repository
therefore cannot be merged there — that is a staging decision recorded in the
contribution policy, and it is stated plainly so nobody spends a weekend on a
change that cannot be taken.

## What is open right now

**Issues and patches, not code review by pull request.** Use the public
repository's issue tracker (where available) or the project role address
published at <https://xtrape.com/governance/> for reproducible bugs,
documentation problems, feature requests and contribution proposals.

If you have a fix you want to contribute, open an Issue describing it and
attach a patch (`git format-patch`) or link a branch on your fork. A maintainer
applies it internally with your authorship and DCO sign-off preserved. It is
slower than a pull request; it exists so a real contribution is not simply
refused.

Whether external pull requests open, and on what terms, is a `0.8.x`
evaluation recorded in the contribution policy — a planned decision, not a
schedule. Fork pull requests never receive secrets.

## Standards

Xtrape uses **Developer Certificate of Origin 1.1** sign-off (`git commit -s`).
Report what you actually tested, and disclose material AI assistance.

Canonical policy: <https://xtrape.com/governance/>

## Historical

An earlier (`0.7.x`) plan named a GitHub organisation as the public home and
issue intake. It was never carried out; it is not a current instruction.
