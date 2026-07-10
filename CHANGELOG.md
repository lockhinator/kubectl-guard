# Changelog

## [0.6.0](https://github.com/lockhinator/kubectl-guard/compare/v0.5.0...v0.6.0) (2026-07-10)


### Features

* actor-aware policy — per-actor context/namespace mode overrides ([#91](https://github.com/lockhinator/kubectl-guard/issues/91)) ([16c06f0](https://github.com/lockhinator/kubectl-guard/commit/16c06f0f0dc413bac104e1afe7ac63dd72765f46))
* actor-aware policy — per-actor context/namespace mode overrides ([#91](https://github.com/lockhinator/kubectl-guard/issues/91)) ([57c36a6](https://github.com/lockhinator/kubectl-guard/commit/57c36a6ede3d3084a24e2ef3eb18c67861a8467a))
* audit + optionally gate config changes that weaken protection ([#90](https://github.com/lockhinator/kubectl-guard/issues/90)) ([fa6d5bf](https://github.com/lockhinator/kubectl-guard/commit/fa6d5bf24deedb384af579041210ae923a43ed04))
* audit + optionally gate config changes that weaken protection ([#90](https://github.com/lockhinator/kubectl-guard/issues/90)) ([081448d](https://github.com/lockhinator/kubectl-guard/commit/081448dd480cf19ebafef2d35ef7190ad8d9ef4e))
* audit log rotation + shipping (webhook/syslog) ([#24](https://github.com/lockhinator/kubectl-guard/issues/24)) ([399f40f](https://github.com/lockhinator/kubectl-guard/commit/399f40fa4dfee775eb3b03c8c0c3054423ddcd5a))
* audit log rotation + shipping (webhook/syslog) ([#24](https://github.com/lockhinator/kubectl-guard/issues/24)) ([f052e42](https://github.com/lockhinator/kubectl-guard/commit/f052e429b2a879c5fb86fb3bb5215cee4940906a))
* blast-radius gating for wide/bulk mutations ([#81](https://github.com/lockhinator/kubectl-guard/issues/81)) ([6683eb3](https://github.com/lockhinator/kubectl-guard/commit/6683eb38b0abb7e4c04a536743b606a39e373f18))
* blast-radius gating for wide/bulk mutations ([#81](https://github.com/lockhinator/kubectl-guard/issues/81)) ([f11e614](https://github.com/lockhinator/kubectl-guard/commit/f11e6148446425b27eb728878b4734997815a3b3))
* confirmation prompt timeout (fail-safe abort) ([50b0a7c](https://github.com/lockhinator/kubectl-guard/commit/50b0a7c32ff5c7e8c6893889265305d2f04a9505))
* confirmation prompt timeout (fail-safe abort) ([4290748](https://github.com/lockhinator/kubectl-guard/commit/42907483d19e4b09eb348c06a7adee0ff954c580)), closes [#84](https://github.com/lockhinator/kubectl-guard/issues/84)
* define in-cluster / no-named-context behavior ([a2a849f](https://github.com/lockhinator/kubectl-guard/commit/a2a849f5f03dabd2943c4fade3b78c1a1342fbb3))
* define in-cluster / no-named-context behavior ([1edebae](https://github.com/lockhinator/kubectl-guard/commit/1edebae3cb3a222be870fb1af80bb466dbb07dfd)), closes [#83](https://github.com/lockhinator/kubectl-guard/issues/83)
* discover CRD short names via kubectl api-resources ([b71c54f](https://github.com/lockhinator/kubectl-guard/commit/b71c54f40ab994002ec626b4dfcb6c58d04755d2))
* discover CRD short names via kubectl api-resources ([86ea317](https://github.com/lockhinator/kubectl-guard/commit/86ea317caa6b86867e985f566a5b8e1a350ba5c5)), closes [#29](https://github.com/lockhinator/kubectl-guard/issues/29)
* guard explain / preflight command ([#75](https://github.com/lockhinator/kubectl-guard/issues/75)) ([152ef0b](https://github.com/lockhinator/kubectl-guard/commit/152ef0b2caf6009acd9bdb58ab6ff8a10e1cfb8b))
* guard explain / preflight command ([#75](https://github.com/lockhinator/kubectl-guard/issues/75)) ([d0ba4a9](https://github.com/lockhinator/kubectl-guard/commit/d0ba4a984d87b20282a61ea50317b1fca863b672))
* preview affected resources before confirming delete/scale ([#82](https://github.com/lockhinator/kubectl-guard/issues/82)) ([07fab57](https://github.com/lockhinator/kubectl-guard/commit/07fab578cb076a6dd50c2d6f8314f2e3f3ce1bcd))
* preview affected resources before confirming delete/scale ([#82](https://github.com/lockhinator/kubectl-guard/issues/82)) ([b4f8d4d](https://github.com/lockhinator/kubectl-guard/commit/b4f8d4d2eca64b44d8698aa21b975b6f92fd3785))
* scrolling + filtering for the setup wizard ([e2128a1](https://github.com/lockhinator/kubectl-guard/commit/e2128a142b778cfbf53c48a9b14486a3a4743ff5))
* scrolling + filtering for the setup wizard ([7b9c9f6](https://github.com/lockhinator/kubectl-guard/commit/7b9c9f6343073e9fb53288628bcb7e0af6384d43)), closes [#27](https://github.com/lockhinator/kubectl-guard/issues/27)
* stream large manifests instead of reading them into memory ([3afb23b](https://github.com/lockhinator/kubectl-guard/commit/3afb23bcf76d28157eb2bb2c587e85d9eaa824c9))
* stream large manifests instead of reading them into memory ([5566d63](https://github.com/lockhinator/kubectl-guard/commit/5566d63a925e220d40cb3e6cf9313d770ade9f92)), closes [#25](https://github.com/lockhinator/kubectl-guard/issues/25)
* strict mode — gate/deny unknown verbs on protected targets ([#72](https://github.com/lockhinator/kubectl-guard/issues/72)) ([9774235](https://github.com/lockhinator/kubectl-guard/commit/97742350ff125a8b6cbf6165f88748f168fd33d0))
* strict mode — gate/deny unknown verbs on protected targets ([#72](https://github.com/lockhinator/kubectl-guard/issues/72)) ([eedab80](https://github.com/lockhinator/kubectl-guard/commit/eedab8065ac8b1c2ccbba5dd664bfa6d7caf19ae))
* treat exec/cp/attach as sensitive access regardless of context ([#73](https://github.com/lockhinator/kubectl-guard/issues/73)) ([8ff7f43](https://github.com/lockhinator/kubectl-guard/commit/8ff7f436404adc50b498fb2d1fe0d4393422add0))
* treat exec/cp/attach as sensitive access regardless of context ([#73](https://github.com/lockhinator/kubectl-guard/issues/73)) ([8a5261e](https://github.com/lockhinator/kubectl-guard/commit/8a5261ea1b913b4b3b5de757a669d36e74f71b11))
* user-configurable command classification (command_overrides) ([#28](https://github.com/lockhinator/kubectl-guard/issues/28)) ([f268e61](https://github.com/lockhinator/kubectl-guard/commit/f268e61b466d05412d536860c82deae210eb0d9f))
* user-configurable command classification (command_overrides) ([#28](https://github.com/lockhinator/kubectl-guard/issues/28)) ([7f17bf0](https://github.com/lockhinator/kubectl-guard/commit/7f17bf04a705e7eeb6a12728e171ea9ac179d33b))
* validate config on load and add `config validate` ([b5db99b](https://github.com/lockhinator/kubectl-guard/commit/b5db99b2351189f34aa5c152cd3375d8264e039b)), closes [#26](https://github.com/lockhinator/kubectl-guard/issues/26)
* validate config on load and add config validate command ([bdf9853](https://github.com/lockhinator/kubectl-guard/commit/bdf985314631e114752ff82cb7687f0c722a2b69))


### Bug Fixes

* gate delete/edit of a protected namespace by name ([24366a6](https://github.com/lockhinator/kubectl-guard/commit/24366a6c66ff13b54b1cd4be3aafe3b62ddde4eb))
* gate delete/edit of a protected namespace by name ([cfd770e](https://github.com/lockhinator/kubectl-guard/commit/cfd770e88d689b6abb05db2d5f125201dadabdd7)), closes [#92](https://github.com/lockhinator/kubectl-guard/issues/92)
* use real glob matching for contexts and namespaces ([0fb2403](https://github.com/lockhinator/kubectl-guard/commit/0fb240358af17f51bb8fa91693d8248ac4cd26e4))
* use real glob matching for contexts and namespaces ([d2478b8](https://github.com/lockhinator/kubectl-guard/commit/d2478b86bdb3f1955389b4fdd50ec161e11286a5)), closes [#30](https://github.com/lockhinator/kubectl-guard/issues/30)

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
