# Changelog

## [1.1.1](https://github.com/lockhinator/kubectl-guard/compare/v1.1.0...v1.1.1) (2026-07-18)


### Bug Fixes

* register sensitive-access config command ([226afdb](https://github.com/lockhinator/kubectl-guard/commit/226afdb6f89deb4c12904ce3df12747eec5a96da))
* register sensitive-access config command ([d43b7d8](https://github.com/lockhinator/kubectl-guard/commit/d43b7d8746be78dc4d3da8ccd93d9406721eeccf))

## [1.1.0](https://github.com/lockhinator/kubectl-guard/compare/v1.0.0...v1.1.0) (2026-07-18)


### Features

* add authenticated one-shot approvals ([f77be9d](https://github.com/lockhinator/kubectl-guard/commit/f77be9d9a05e995c52aea58e0d88d28e7e25ab3c))
* add authenticated one-shot approvals for v1.1.0 ([ad65a84](https://github.com/lockhinator/kubectl-guard/commit/ad65a840ebd41e9bc281c93cb9bbe87c652e9473))


### Bug Fixes

* ensure kubectl shim wins PATH ordering ([43fced4](https://github.com/lockhinator/kubectl-guard/commit/43fced463ccd05814688a5059d71178c28ae18c6))
* harden authenticated approval boundary ([6f53e41](https://github.com/lockhinator/kubectl-guard/commit/6f53e4141f4b7b12ced16b2000b4f53be512172a))
* require human-presence approval setup ([526a874](https://github.com/lockhinator/kubectl-guard/commit/526a87405e43b754ab6fe50f9e96a5785d8580e9))

## [1.0.0](https://github.com/lockhinator/kubectl-guard/compare/v0.6.0...v1.0.0) (2026-07-11)


### Features

* capture a justification on confirmation (compliance) ([e462aba](https://github.com/lockhinator/kubectl-guard/commit/e462abaa94f3b8b26708ef62676d30074ada560f)), closes [#95](https://github.com/lockhinator/kubectl-guard/issues/95)
* capture justification on confirmation (compliance) ([5d393c8](https://github.com/lockhinator/kubectl-guard/commit/5d393c81e89cfccfc4eebf6618b2362f89c2626f))
* config file permission check on load (tamper signal) ([b0c6dd9](https://github.com/lockhinator/kubectl-guard/commit/b0c6dd9033c164bc07fbf8b8e178043b0ef3c85e))
* configurable config and audit-log locations via env vars ([b47a67f](https://github.com/lockhinator/kubectl-guard/commit/b47a67f8d049afda62c7902b3860faf8d8c6c704)), closes [#36](https://github.com/lockhinator/kubectl-guard/issues/36)
* configurable config location (KUBECTL_GUARD_CONFIG env var) ([3387cc0](https://github.com/lockhinator/kubectl-guard/commit/3387cc0c73dd5ce7ae1504a391631b52ea0b8b75))
* consistent error reporting (single sink, --json aware) ([ca5e598](https://github.com/lockhinator/kubectl-guard/commit/ca5e598f905e400de250a57cfef02a016a834a34))
* consistent, --json-aware error reporting ([cbe5a56](https://github.com/lockhinator/kubectl-guard/commit/cbe5a5642016874ddf246fb64eb8bc8fa6365cb8)), closes [#38](https://github.com/lockhinator/kubectl-guard/issues/38)
* distribution channels — Homebrew cask + deb/rpm/apk ([12bb8a5](https://github.com/lockhinator/kubectl-guard/commit/12bb8a5b2190f39df56e17797dcddf1b2e8bd47e))
* distribution channels — Homebrew cask + deb/rpm/apk ([f42d487](https://github.com/lockhinator/kubectl-guard/commit/f42d487b9c9f25613143fffce840e962d36439ce)), closes [#96](https://github.com/lockhinator/kubectl-guard/issues/96)
* doctor command (verify interception, config, audit, posture) ([224ac66](https://github.com/lockhinator/kubectl-guard/commit/224ac665cc361f709db0a57e7678852da7867af6))
* doctor command (verify interception, config, audit, posture) ([d3a67f4](https://github.com/lockhinator/kubectl-guard/commit/d3a67f414e47b7524aa4df2776dc1c8d9907bc7a)), closes [#37](https://github.com/lockhinator/kubectl-guard/issues/37)
* document native Windows as a non-goal (WSL2), compile-safe ([10c3c52](https://github.com/lockhinator/kubectl-guard/commit/10c3c52e2423685952fd73b6b1e950558f927d07))
* document native Windows as a non-goal (WSL2), compile-safe ([2eb7736](https://github.com/lockhinator/kubectl-guard/commit/2eb77363c4cf7f8b4f79adeece05bb7072c0fd43)), closes [#88](https://github.com/lockhinator/kubectl-guard/issues/88)
* global read-only / freeze mode (incident panic button) ([0287078](https://github.com/lockhinator/kubectl-guard/commit/0287078ab579470339195d0b0391c00aaa9861f9))
* global read-only / freeze mode (incident panic button) ([248e179](https://github.com/lockhinator/kubectl-guard/commit/248e1791930ef216c5c558c033a2ba7e3607eda6)), closes [#94](https://github.com/lockhinator/kubectl-guard/issues/94)
* graceful SIGINT/SIGTERM handling during the confirmation prompt ([4969508](https://github.com/lockhinator/kubectl-guard/commit/4969508a4e2759bce64b26f55f3ea44ee343b73f)), closes [#35](https://github.com/lockhinator/kubectl-guard/issues/35)
* identity-based context protection (match cluster server URL) ([1f45887](https://github.com/lockhinator/kubectl-guard/commit/1f45887e9097dd094587a13b81657bff5688e6f0))
* identity-based context protection (match cluster server URL) ([b28bb90](https://github.com/lockhinator/kubectl-guard/commit/b28bb900efe7d34fb3b5e67c3865502110945bb8)), closes [#85](https://github.com/lockhinator/kubectl-guard/issues/85)
* layered/enforced config (system baseline + user, most-restrictive) ([cce750b](https://github.com/lockhinator/kubectl-guard/commit/cce750b626f551c71fa614fe7416aabae0e25297))
* layered/enforced config (system baseline + user, most-restrictive) ([24c957a](https://github.com/lockhinator/kubectl-guard/commit/24c957a54e0193073e8ffc9fa331cff4280f5763)), closes [#86](https://github.com/lockhinator/kubectl-guard/issues/86)
* opt-in scoped structured output redaction (redact_output) ([c280765](https://github.com/lockhinator/kubectl-guard/commit/c2807650276c8ea21d2c8c5c489504ece104b2a0))
* opt-in scoped structured output redaction (redact_output) ([eebe9cb](https://github.com/lockhinator/kubectl-guard/commit/eebe9cb955388bab44cafc1918956af8a7487e7e)), closes [#108](https://github.com/lockhinator/kubectl-guard/issues/108)
* per-pattern policy overrides (mode per context/namespace pattern) ([eb5996d](https://github.com/lockhinator/kubectl-guard/commit/eb5996d7c48b399fc09429ffd2ba8950febfe52e))
* per-pattern policy overrides (mode per context/namespace pattern) ([ba18077](https://github.com/lockhinator/kubectl-guard/commit/ba18077709c3cbaf25ac767f76fe03cab74a3166)), closes [#79](https://github.com/lockhinator/kubectl-guard/issues/79)
* read kubeconfig directly (clientcmd) instead of shelling out ([31b4ac4](https://github.com/lockhinator/kubectl-guard/commit/31b4ac4c8820306f2d0a9203bbf600aa445adf26))
* resolve context/namespace by parsing kubeconfig (clientcmd) ([f672c60](https://github.com/lockhinator/kubectl-guard/commit/f672c6096cfb79c28ddf3ebb3ddcbf871f068013)), closes [#31](https://github.com/lockhinator/kubectl-guard/issues/31)
* sensitive-kind mutation gating ([19e3eb6](https://github.com/lockhinator/kubectl-guard/commit/19e3eb633518bfde9db028e225ec477c88b60ed3)), closes [#93](https://github.com/lockhinator/kubectl-guard/issues/93)
* sensitive-kind mutation gating (gate mutations to a kind anywhere, allow reads) ([9b8d1f3](https://github.com/lockhinator/kubectl-guard/commit/9b8d1f347be02b6747cad9c7640c207b0493da8a))
* shell completions (bash/zsh/fish) ([add1d58](https://github.com/lockhinator/kubectl-guard/commit/add1d5806280b080d7a432f0b62ca61f17bcf60c))
* shell completions (bash/zsh/fish/powershell) ([f92f12d](https://github.com/lockhinator/kubectl-guard/commit/f92f12da49c11a41e432758a5a3fe6115321e3aa)), closes [#39](https://github.com/lockhinator/kubectl-guard/issues/39)
* sign releases with cosign + SLSA provenance + SBOM ([b8c4041](https://github.com/lockhinator/kubectl-guard/commit/b8c4041c3d3c23102d0adef95f7404143af99296))
* sign releases with cosign + SLSA provenance + SBOM ([a2a5ea3](https://github.com/lockhinator/kubectl-guard/commit/a2a5ea3fd69903c00cd5d856c1e37d146dbc9b97)), closes [#77](https://github.com/lockhinator/kubectl-guard/issues/77)
* signal handling (graceful SIGINT/SIGTERM with audit) ([4bfbd6b](https://github.com/lockhinator/kubectl-guard/commit/4bfbd6bafa227133b57f078b19c85f27a1f07ffb))
* tamper-evident audit log (hash-chained + verify) ([658f56a](https://github.com/lockhinator/kubectl-guard/commit/658f56a4ced1097e2357d6b7a1c4499f017cae7c)), closes [#78](https://github.com/lockhinator/kubectl-guard/issues/78)
* tamper-evident audit log (hash-chained integrity + verify) ([2bb755c](https://github.com/lockhinator/kubectl-guard/commit/2bb755c9c763c6e1cf6e6d2316d071fe41430696))
* uninstall command (remove shim, guided PATH cleanup, --purge) ([b997f09](https://github.com/lockhinator/kubectl-guard/commit/b997f09f93551dd87f301087843a7e557a92b678))
* uninstall command (remove shim, guided PATH cleanup, --purge) ([96ee4b1](https://github.com/lockhinator/kubectl-guard/commit/96ee4b1e4449c636e4ccd29fc7aaeab5ed34a3ee)), closes [#87](https://github.com/lockhinator/kubectl-guard/issues/87)
* warn or fail closed on a tamperable config (permission check) ([f449d99](https://github.com/lockhinator/kubectl-guard/commit/f449d9930f14c48c573a6bda94109bae73c5fa87)), closes [#34](https://github.com/lockhinator/kubectl-guard/issues/34)


### Bug Fixes

* close in-cluster namespace fail-open; correct explain/doctor attribution ([40cd32a](https://github.com/lockhinator/kubectl-guard/commit/40cd32aefef52284e0ff24a62d7cb89255e181c3))
* close in-cluster namespace fail-open; correct explain/doctor attribution ([9112d1b](https://github.com/lockhinator/kubectl-guard/commit/9112d1bbd4c3624a6338b3e774731baa0d909adc))
* handle kubectl-not-found gracefully with an actionable message ([87f8d79](https://github.com/lockhinator/kubectl-guard/commit/87f8d7953422dcc9f76b35c61fe33072288de853))
* surface an actionable message when kubectl is missing ([37f693e](https://github.com/lockhinator/kubectl-guard/commit/37f693e22e50201996268f4fc1d6ddb06eebd938)), closes [#33](https://github.com/lockhinator/kubectl-guard/issues/33)


### Miscellaneous Chores

* release v1.0.0 ([6fcf7e8](https://github.com/lockhinator/kubectl-guard/commit/6fcf7e832ca47a648de16abfb8169a6d3e10565d))

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
