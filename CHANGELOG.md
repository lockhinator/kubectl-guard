# Changelog

## [0.3.0](https://github.com/lockhinator/kubectl-guard/compare/v0.2.3...v0.3.0) (2026-07-09)


### Features

* audited automation escape hatch --yes / KUBECTL_GUARD_CONFIRM ([#17](https://github.com/lockhinator/kubectl-guard/issues/17)) ([#57](https://github.com/lockhinator/kubectl-guard/issues/57)) ([1646cf0](https://github.com/lockhinator/kubectl-guard/commit/1646cf018a83d6ede4b1b75e285cc09490e3f185))
* headless / non-TTY setup via env vars, --no-prompt, and config init ([#16](https://github.com/lockhinator/kubectl-guard/issues/16)) ([#56](https://github.com/lockhinator/kubectl-guard/issues/56)) ([b050726](https://github.com/lockhinator/kubectl-guard/commit/b05072672faa49a69b0d7cb0dfd8de8ac7fc2aaa))
* PATH-shadowing install + doctor interception check ([#15](https://github.com/lockhinator/kubectl-guard/issues/15)) ([#55](https://github.com/lockhinator/kubectl-guard/issues/55)) ([d849525](https://github.com/lockhinator/kubectl-guard/commit/d8495250cfd349790e8eb90cdfbb2b4896c0fbc2))
* stamp actor identity (KUBECTL_GUARD_ACTOR) into audit log ([#14](https://github.com/lockhinator/kubectl-guard/issues/14)) ([#54](https://github.com/lockhinator/kubectl-guard/issues/54)) ([7f4286b](https://github.com/lockhinator/kubectl-guard/commit/7f4286b926df97f706a758d4a6d5df483500decf))
* structured exit codes + JSON output for agent frameworks ([#13](https://github.com/lockhinator/kubectl-guard/issues/13)) ([#53](https://github.com/lockhinator/kubectl-guard/issues/53)) ([f1a9357](https://github.com/lockhinator/kubectl-guard/commit/f1a9357714189880fe1c2174dacc7ee86f762079))

## [0.2.3](https://github.com/lockhinator/kubectl-guard/compare/v0.2.2...v0.2.3) (2026-07-09)


### Bug Fixes

* drop Windows build targets to fix GoReleaser release ([#50](https://github.com/lockhinator/kubectl-guard/issues/50)) ([a339780](https://github.com/lockhinator/kubectl-guard/commit/a339780016029ef8e5a15049f61f95a8d113e2ed))

## [0.2.2](https://github.com/lockhinator/kubectl-guard/compare/v0.2.1...v0.2.2) (2026-07-09)


### Bug Fixes

* ensure version is properly injected in release builds ([#48](https://github.com/lockhinator/kubectl-guard/issues/48)) ([425f979](https://github.com/lockhinator/kubectl-guard/commit/425f97962ead7c45a3b27959a3525c45e19854d3))

## [0.2.0](https://github.com/lockhinator/kubectl-guard/compare/v0.1.1...v0.2.0) (2026-07-08)


### Features

* comprehensive audit logging + AI-agent positioning ([#6](https://github.com/lockhinator/kubectl-guard/issues/6)) ([d618184](https://github.com/lockhinator/kubectl-guard/commit/d618184df3ceb0ff03a879426e0d0a582d1be202))

## [0.1.1](https://github.com/lockhinator/kubectl-guard/compare/v0.1.0...v0.1.1) (2026-07-08)


### Bug Fixes

* **ci:** chain GoReleaser after release-please, enable publishing ([73ff055](https://github.com/lockhinator/kubectl-guard/commit/73ff055bfb85d69e2ade391e91a0a98f5cb64741))
* **ci:** chain GoReleaser after release-please, enable release publishing ([e0d7b90](https://github.com/lockhinator/kubectl-guard/commit/e0d7b90d6a679f9da0805e3b68ebf4bd059e63ef))

## 0.1.0 (2026-07-08)


### Miscellaneous Chores

* release 0.1.0 ([3711843](https://github.com/lockhinator/kubectl-guard/commit/3711843f6872fd6482d65f8d21cf1995e4a19020))
