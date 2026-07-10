# Changelog

## [0.5.0](https://github.com/lockhinator/kubectl-guard/compare/v0.4.0...v0.5.0) (2026-07-10)


### Features

* agent-relayable approval flow (needs-confirmation signal) ([f771ce7](https://github.com/lockhinator/kubectl-guard/commit/f771ce7b34e13b8524d22fc72b25453dfbaa645c))
* agent-relayable approval flow (needs-confirmation signal) ([1461432](https://github.com/lockhinator/kubectl-guard/commit/146143208dd0596c6635ba02f778556584ad08de)), closes [#23](https://github.com/lockhinator/kubectl-guard/issues/23)
* secure-default headless bootstrap (no silent fail-open) ([02ae7f5](https://github.com/lockhinator/kubectl-guard/commit/02ae7f525384e269508cc0eb885ceb210f8d820c))
* secure-default headless bootstrap (no silent fail-open) ([cee3a58](https://github.com/lockhinator/kubectl-guard/commit/cee3a588be0c7cc117f9be4b17df49faed8aa43c)), closes [#74](https://github.com/lockhinator/kubectl-guard/issues/74)


### Bug Fixes

* gate kubectl --raw API paths past resource protection ([66771bf](https://github.com/lockhinator/kubectl-guard/commit/66771bf218b2d788baf003bbc4d3fd975d3dc0a7))
* gate kubectl --raw API paths past resource protection ([210947a](https://github.com/lockhinator/kubectl-guard/commit/210947a277fd08dbc1543f8dbf4c2071fab5210d)), closes [#80](https://github.com/lockhinator/kubectl-guard/issues/80)
* gate kubectl port-forward and proxy (and close the verb-shift bypass) ([6f01573](https://github.com/lockhinator/kubectl-guard/commit/6f015732de3a4367743c494fc093044ea827d157))
* gate port-forward and proxy, and close the verb-shift bypass ([480970e](https://github.com/lockhinator/kubectl-guard/commit/480970e3494907c7045eee27f6537ca05a2bcb43)), closes [#71](https://github.com/lockhinator/kubectl-guard/issues/71)
* redact secret values from the audit log, --json, and messages ([0b202b3](https://github.com/lockhinator/kubectl-guard/commit/0b202b3c807110843ca6c85b0cfa961e2d016a73)), closes [#89](https://github.com/lockhinator/kubectl-guard/issues/89)
* redact secret values from the audit log, --json, and prompts ([8ef411a](https://github.com/lockhinator/kubectl-guard/commit/8ef411ae9a4900b875e42e242dd37c28ef8bc4f1))

## [0.4.0](https://github.com/lockhinator/kubectl-guard/compare/v0.3.0...v0.4.0) (2026-07-09)


### Features

* dry-run / diff before confirm ([#21](https://github.com/lockhinator/kubectl-guard/issues/21)) ([#65](https://github.com/lockhinator/kubectl-guard/issues/65)) ([f7bb495](https://github.com/lockhinator/kubectl-guard/commit/f7bb4957ee17df86097abc2a178ab960a8d12ab5))
* hard block mode for protected contexts/namespaces ([#20](https://github.com/lockhinator/kubectl-guard/issues/20)) ([#64](https://github.com/lockhinator/kubectl-guard/issues/64)) ([405b252](https://github.com/lockhinator/kubectl-guard/commit/405b252072ee0271220581f755bace84d13a1f39))
* honor targeting & identity flags (--server/--as/--token) for protection + audit ([#18](https://github.com/lockhinator/kubectl-guard/issues/18)) ([#61](https://github.com/lockhinator/kubectl-guard/issues/61)) ([a847c52](https://github.com/lockhinator/kubectl-guard/commit/a847c520225944ec90fae453430be4c67278ce41))
* namespace-level protection (protected_namespaces) ([#19](https://github.com/lockhinator/kubectl-guard/issues/19)) ([#63](https://github.com/lockhinator/kubectl-guard/issues/63)) ([82e509f](https://github.com/lockhinator/kubectl-guard/commit/82e509f77812f21559595923bbc35369e5ad2229))


### Bug Fixes

* harden dry-run/namespace parsing and resolve namespace from context ([2c02f72](https://github.com/lockhinator/kubectl-guard/commit/2c02f7228c396a2ba8f29cd8e152b152a75befee))
* memoize context-namespace lookup so message matches the gated decision ([33e06c1](https://github.com/lockhinator/kubectl-guard/commit/33e06c1b86f3fcbd04606998ea74af32a638b02e))
* skip the prompt for --dry-run commands (cry-wolf reduction) ([#22](https://github.com/lockhinator/kubectl-guard/issues/22)) ([#66](https://github.com/lockhinator/kubectl-guard/issues/66)) ([c37d707](https://github.com/lockhinator/kubectl-guard/commit/c37d707271cb527747f10ebcd2dedf8e067441f8))

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
