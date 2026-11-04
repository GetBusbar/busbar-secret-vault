# Vault assertion migration (incremental)

Plugin source freeze: `68b9a6d1750091cf9dcec6a8b1965daf2c33cd64`. SDK remains `a35493a5e74cc935ff7dcc15c1af869290da91cb`, TCP remains `b896c5e6ef34dc6ea179f0dbcb4c7262cc117ca9`, HTTP remains `744b75731e7297a98d6e6c03f916906abc35da87`. No public pin or lock source retarget.

## Bounded-response test transfer

Every preexisting test and assertion in `secret-vault-plugin/tests/bounded_response.rs` remains. Only its test setup and call orchestration changed:

| Old dependency/helper | Ordinary replacement |
| --- | --- |
| `Subject`, `Leg`, `suite::load` | Local two-value origin enum, actual `LinkedRow::of(busbar_secret_vault::door::door)` and `load_linked`; actual `load_dropped` on absolute `BUSBAR_PLUGIN_CDYLIB`, missing artifact hard failure |
| `suite::dispatcher_serving`, `ServicesDouble/Double(ClockOnly)` | Production `Dispatcher::with_services` and `KernelServices::new().with_mono_clock(dispatch::now_ns)` |
| `conformance_host::host` | Local production Connector wiring actual TCP/HTTP Dispatched transports, real process reactor and IO, loopback-only judge, real client TLS |
| `suite::open` | Explicit `OpenIn/OpenOut`; token lent as BLOB_OCTETS + BLOB_SECRET in the declared first secret slot |
| `suite::validate`, `suite::close` | Explicit lifecycle frames and calls |
| Generic zeroed `input/output`, JSON helper | Explicit ResolveIn/ResolveOut fields and local JSON Blob construction |
| `suite::on_ticket_frame` | Mint, submit_lent, wait_done, recycle, retain Called + output frame |
| `suite::woken` | Per-owned-dispatcher `stats().deadline_without_wake == 0` |

Preserved test cases, both actual origins:

1. Short answer names exact needed length and leaves no partial material.
2. Response at cap accepted and one byte over refused.
3. Unfinished oversized responses preserve each status 200/400/403/404/503 and close.
4. Redirect refuses without contacting its location or forwarding token.
5. Invalid operator CA passes syntax validation then refuses open before network; no token/CA in refusal.
6. Escaped material succeeds; malformed nested JSON refuses without buffer disclosure.
7. Cancellation of partial escaped reply has ABORTED disposition and untouched host buffer.
8. Configured timeout closes silent TLS establishment within existing bound.
9. Configured timeout closes partial response within existing bound and no partial secret.
10. Huge configured timeout succeeds using outer cap without overflow refusal.

All resolves still assert lease zero, refusal contains neither token nor material, Ready points into host buffer with positive bounded length, refusal returns null/empty blob and an untouched zeroed buffer, close Ready, no deadline completion without wake. Request server still verifies exact GET path and X-Vault-Token. No fake transport/plugin implementation was added.

## Remaining framework coverage

`conformance.rs` and `support/conformance_host.rs` macros remain, preserving their assertions while migration proceeds. This commit does not claim kit removal. The published suite contributes canary including log records, equal linked/dropped counted/ticketed lifecycle/resolve folds, loader ABI/layout/statement/wrongkind/connection/ready negatives, declares equality, and requested profile. Pure comparator selfchecks and early-return branches must be separately identified before retirement, as in env's exact 20-test ledger.

The host macro's four active generated tests remain: `the_hosts_tls_upgrade_verifies_against_the_suites_test_anchors`, `red_with_the_anchors_withheld_the_hosts_tls_upgrade_is_refused`, `the_conformance_host_guard_refuses_a_private_destination`, and `an_http_need_reaches_a_local_http_listener_through_the_hosts_framer`. They cannot be silently retired as setup code.

## Validation limits

Rustfmt and source diff checks only. No build/test execution without the shared build lane. The new production kernel dev dependency is the existing exact SDK source already in this lock; the only lock edit adds it to this plugin's dependency list. Native compilation and fresh artifact execution remain required; CI freshness wiring is pending. Absolute file existence does not prove freshness.

## Ordinary TLS, guard, canary and counters (second increment)

The bounded tests now record/audit diagnostic and log text plus metric labels through `AuditSink` and check both current and original configured token/material canaries in all errors. Direct lifecycle helpers read actual public per-instance entry/resume counters. Ticketed Vault resolves pin one actual first-entry crossing independently of resumes, with network Ready requiring an actual wake/resume; cancellation retains its original ABORTED assertion and permits the separate cancellation crossing. Ready results now explicitly check BLOB_OCTETS and BLOB_SECRET; refusals check no secret flag.

`the_actual_vault_http_need_verifies_a_local_tls_leaf_and_refuses_withheld_anchors` uses rcgen to mint a fresh private CA/localhost leaf and standard rustls ServerConnection/StreamOwned on a real ephemeral local listener. Both actual plugin doors resolve material over the actual TCP+HTTP Connector when trusted; withholding the anchor refuses before an HTTP request reaches the endpoint. This preserves trust-positive/trust-negative and real HTTP route/header/material behavior without calling a Busbar TLS kit. Production PEM parsing uses rustls pki-types directly.

`the_production_guard_refuses_private_and_metadata_dials_and_admits_operator_loopback` declares only narrow ReadNeed values on the real Connector. It retains all original guard cases: private and loopback under default class refused, metadata under operator infrastructure refused, no refused dial reaches the listener, and operator loopback control reaches it and closes. It contains no connector implementation.

The original host macro and conformance macro remain while composition and the remaining full positive lifecycle transfer proceed; no assertion is retired. Generic loader negatives still need owner ACK. The standalone host HTTP test also counted exactly one response-head piece and body `hello`; that exact low-level piece assertion is still held by the retained host macro and is not claimed replaced by the plugin material check. No native build or execution was run. rcgen/rustls use the existing fleet versions; lock edits only add direct plugin membership, no source retarget.

## Monday-audit composition decision

Normal merge retains exact parents `fce78f0babb933d9b8f9fe1c8646eae4754cd0b8` and `c6c2384b96a66f3ca80d9f7725eae809d80f749e`. Root explicitly chose selected JSON null -> INVALID/no material, while string `"null"` and nulls nested inside otherwise valid objects/arrays remain valid. This is authorized audit composition, not primary-1.5.5 proof or signed oracle difference.

Hunk dispositions:

- `door.rs` import conflict is formatting only. Retain `set_timeout_ms` and `exchange_sealed_bounded_with_head`, byte cap, head/status preservation, cancellation and wiping. Retain audit lazy `framed` request builder, adapting its infallible error signature to the exact pinned SDK's String builder API. Never revert to donor's unbounded/plain exchange.
- The retained head-boundary handler first reconstructs status-bearing oversized replies as before. Other failures consume `ExchangeFailure::into_cause`, preserving a real `ConnFailure` class for audit's typed `Exchanged`/`judge`; an impossible error from the locally infallible request constructor is classed as internal Fault. Consuming the failure retains SDK head wiping. No typed class is flattened to a string at the exchange boundary.
- `lib.rs` preserves custom owned/wiping config parser, VaultConfig clone/drop guards, custom response parser and all non-string JSON semantics except the explicitly decided selected-null case. Retain audit 429 Unavailable, typed failure classification, truncated-PEM and blank-reference fixes, and number/bool/key wiping. Body-cap prose describes the actual bounded exchange rather than stale donor REPLY_MAX buffering.
- `tests/lib_tests.rs` unions donor strict base64/DER/truncated-PEM/blank-path/429/classification cases with existing custom-parser equivalence and malformed/unicode/depth cases. The positive selected `null` expectation is replaced by string `"null"`; nested null coverage remains. Donor selected-null INVALID test and explicit string/nested-null controls are retained.
- `bounded_response.rs` adds both actual-door selected-null refusal and string-null success; existing host-buffer/secret-flag/lease/canary checks establish no material or partial write on refusal. All prior actual TLS/guard/bound/cancellation tests remain.
- Independently merged audit control-character token checks, needs assertions and additional wiping tests remain.

Only rustfmt/source/diff checks ran. Native build/execution and source peer qualification remain pending; no test skip, no SDK/public-pin/registry change, and framework macros remain pending their full ordinary migration.


## Completed ordinary source cutover

The generated conformance macro and its host macro/support file are removed. `conformance.rs` now contains actual-product metadata-only ABI ±1, layout ^1/0, Statement mismatch/version and every-other-kind negative tests with honest linked/dropped twins; all operation pointers remain the real product's static table. `bounded_response.rs` preserves the original bounded/timeout/cancel tests plus both-origin lifecycle, ready, validate/open refusal reasons, pure CHECK, repeated known/unknown/malformed/short/recalled resolution, invalid-refresh state retention, successful refresh, unknown release, tick/close and caller-buffer/material/zero-lease predicates. Actual per-instance first/resume counts and envelope canaries remain asserted.

The four former host-generated predicates have concrete owners: trusted/withheld actual local TLS leaf is `the_actual_vault_http_need_verifies_a_local_tls_leaf_and_refuses_withheld_anchors`; production private/metadata refusal and loopback control is `the_production_guard_refuses_private_and_metadata_dials_and_admits_operator_loopback`; actual HTTP framer route/header/material is asserted by those and the bounded response tests, using actual TCP+HTTP transports and production Connector.

Generic loader failure and connection-custody source transfer ACK: core `8227f0138ef2e44d4cefd25ce8fd3d51a9604b6a` ordinary_load_negatives for metadata and failed-ready; source ACK `ef00f652` / actual GitHub image `abd7663` for undeclared need, cross-instance connection and absent connection-table arms. This is source ownership, not a claim of core native qualification. Per-product pack/version/layout/origin checks remain locally explicit above.

Retired generated branches that did no Secret product work: plane billable class/layout, transport frame-piece, three outbound-auth plants and newer-store-schema. Comparator count mutation was a check of the retired recorder; actual physical entry/resume predicates remain direct. No missing-artifact skip is present. Native qualification and normal same-pin lock reconciliation follow on this exact source.

The final lifecycle fixture withholds each actual HTTP response until its actual worker driver has physically RESUMED on a real chunked-response prefix; the server sends valid JSON whitespace chunks while withholding the terminal JSON material, so the response gate cannot depend on receiving its own withheld data, then permits the response and asserts at least one physical RESUME. This preserves the old named known/repeated/unknown/after-refresh pending predicates deterministically, including known resolution after every refused settings push. An unrelated immediately available HTTP result is allowed to be READY without a RESUME; the original huge-timeout test never required a delay. The default SDK CHECK is tested as the pure object check the actual Vault door supplies; malformed reference grammar remains an INVALID RESOLVE assertion, rather than inventing a custom Vault CHECK callback.
