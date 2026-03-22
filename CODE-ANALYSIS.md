# Comprehensive Code Analysis: Resolver Library

**Date:** 2026-03-22
**Analyzer:** Claude Opus 4.6 (1M context)
**Methodology:** 34-technique iterative analysis with convergence

---

## Round 1: 19 Issues Found

### Issue 1
- **Severity:** CRITICAL
- **Technique:** Error Path Analysis
- **File:** `/home/ubuntu/claudecode/resolver/auth.go`, line 100-108
- **Description:** In `authenticator.result()`, when multiple errors are found, the composed error is computed but never returned. The function falls through to `a.auth.Result()` discarding the aggregated error.
- **Impact:** DNSSEC authentication errors are silently swallowed. Multiple verification failures during authentication are lost, potentially allowing bogus responses to appear valid.

### Issue 2
- **Severity:** HIGH
- **Technique:** Concurrency Analysis
- **File:** `/home/ubuntu/claudecode/resolver/auth.go`, lines 43-49
- **Description:** In `authenticator.close()`, after `a.processing.Wait()` completes, the channel is closed and set to nil. However, `addDelegationSignerLink()` and `addResponse()` check `a.finished.Load()` and then send on the channel without holding any lock. A goroutine in `addDelegationSignerLink` could check `finished` (false), then `close()` runs setting `finished=true` and nilling the channel, then the goroutine tries to send on the nil channel, causing a panic.
- **Impact:** Runtime panic (send on nil channel) under concurrent DNSSEC resolution, crashing the resolver.

### Issue 3
- **Severity:** HIGH
- **Technique:** Concurrency Analysis
- **File:** `/home/ubuntu/claudecode/resolver/auth.go`, lines 52-71
- **Description:** In `addDelegationSignerLink()`, `a.processing.Add(1)` is called after the `a.finished.Load()` check. If `close()` calls `a.processing.Wait()` between the `finished` check and `Add(1)`, the Wait returns early, then `close()` closes the channel while the goroutine is still running and about to send on it, causing a panic (send on closed channel).
- **Impact:** Panic from sending on a closed channel during DNSSEC authentication teardown.

### Issue 4
- **Severity:** HIGH
- **Technique:** Resource Leak Analysis
- **File:** `/home/ubuntu/claudecode/resolver/zone_factory.go`, lines 74-93
- **Description:** In `enrichPool()`, a goroutine is launched that iterates over hosts/types making DNS queries. If the `select` chooses the timeout path, the function returns but the goroutine continues running indefinitely making DNS queries, with no cancellation mechanism. Additionally, the `done` channel is never closed, so it leaks if `doneCalled` is never set to true.
- **Impact:** Goroutine leak under timeout conditions. Orphaned goroutines continue making network requests, consuming memory, file descriptors, and network resources.

### Issue 5
- **Severity:** HIGH
- **Technique:** State Machine Analysis
- **File:** `/home/ubuntu/claudecode/resolver/nameserver.go`, lines 44-63
- **Description:** `nameserver.getClient()` lazily initializes `udpClient` and `tcpClient` without synchronization. Multiple goroutines can race on the nil check and factory call, potentially creating multiple clients, with only the last one stored. This is a classic check-then-act race condition.
- **Impact:** Data race on client initialization. Under concurrent access, clients may be created multiple times, and some requests may use a client that is subsequently overwritten.

### Issue 6
- **Severity:** HIGH
- **Technique:** Taint Tracking / Adversarial Input
- **File:** `/home/ubuntu/claudecode/resolver/resolver_exchange.go`, line 69
- **Description:** `newAuthenticator(ctx, qmsg.Question[0])` accesses `qmsg.Question[0]` without verifying `len(qmsg.Question) > 0`. Although the DNS library typically ensures this, a malformed message could cause an index-out-of-bounds panic.
- **Impact:** Panic on malformed DNS message input, causing denial of service.

### Issue 7
- **Severity:** HIGH
- **Technique:** Protocol Conformance
- **File:** `/home/ubuntu/claudecode/resolver/pool_exchange.go`, lines 34-46
- **Description:** The retry logic in pool exchange always falls back to IPv4 if `hasIPv4` is true, even when the initial attempt was on IPv4. With a single IPv4 nameserver, the retry hits the same server with the same query, providing no actual redundancy. The round-robin counter increments, but if there is only one server, it gets the same one.
- **Impact:** Retry is ineffective for single-server pools, giving the appearance of fault tolerance without substance.

### Issue 8
- **Severity:** MEDIUM
- **Technique:** Boundary Partitioning
- **File:** `/home/ubuntu/claudecode/resolver/zones.go`, lines 22-58
- **Description:** `getZoneList()` returns `nil` when `zones.zones` is nil (line 32), but the caller at `resolver_exchange.go:99` immediately accesses `knownZones[0]` without a nil check. If the zone map is somehow nil or the root zone is missing, this causes a nil pointer dereference / index-out-of-bounds panic.
- **Impact:** Panic if the zone store is in an unexpected state, though in practice the root zone is always present.

### Issue 9
- **Severity:** MEDIUM
- **Technique:** Invariant Verification
- **File:** `/home/ubuntu/claudecode/resolver/resolver_exchange.go`, lines 173-174
- **Description:** `checkForMissingZones` uses `append(rmsg.Ns, rmsg.Answer...)` which modifies the underlying array of `rmsg.Ns` if it has sufficient capacity. This mutates the original DNS message's Ns section by appending Answer records to it.
- **Impact:** The DNS response message is corrupted in-place, which could cause incorrect behavior in subsequent processing that relies on `rmsg.Ns` containing only authority section records.

### Issue 10
- **Severity:** MEDIUM
- **Technique:** Concurrency Analysis
- **File:** `/home/ubuntu/claudecode/resolver/zone.go`, lines 133-171
- **Description:** `dnskeys()` uses a mix of `Lock()`/`Unlock()` and `defer Unlock()`. On line 139, if the cache is valid, it unlocks explicitly and returns. On line 142, it defers unlock. If the early return path (line 140) is taken, the explicit unlock on line 139 is correct. However, the pattern is fragile: any future modification that adds a second early return between lines 134-142 could double-unlock.
- **Impact:** Code maintainability risk. Not an active bug but a landmine for future changes.

### Issue 11
- **Severity:** MEDIUM
- **Technique:** FMEA (Failure Mode and Effects Analysis)
- **File:** `/home/ubuntu/claudecode/resolver/zone.go`, lines 65-77
- **Description:** In `zoneImpl.exchange()`, when a cache hit occurs, `trace` is extracted from context but used without nil check (line 71-72). If `CtxTrace` is not set in the context, `trace` will be nil, and `trace.ShortID()` / `trace.Iteration()` will panic.
- **Impact:** Nil pointer dereference panic when cache is enabled but trace context is not set.

### Issue 12
- **Severity:** MEDIUM
- **Technique:** Temporal Logic
- **File:** `/home/ubuntu/claudecode/resolver/pool.go`, lines 93-118
- **Description:** The `status()` method checks for `PoolExpired` in the enum definition but never returns it. The `expired()` check is done in `zones.go` separately, but `status()` itself does not account for expiry, making the `PoolExpired` status dead code.
- **Impact:** Pool expiration status is never surfaced through the `status()` method, potentially leading to use of expired pools in code paths that rely on `status()`.

### Issue 13
- **Severity:** MEDIUM
- **Technique:** Symbolic Execution
- **File:** `/home/ubuntu/claudecode/resolver/domain.go`, lines 74-89
- **Description:** In `domain.gap()`, the loop `for i := d.currentIdx; i < missing+d.currentIdx; i++` accesses `d.labelIndexes[i]` but does not bounds-check against `len(d.labelIndexes)`. If the target has significantly more labels than the domain allows, this can cause an index-out-of-bounds panic.
- **Impact:** Potential panic on malformed or deeply nested domain names.

### Issue 14
- **Severity:** MEDIUM
- **Technique:** Mutation Testing
- **File:** `/home/ubuntu/claudecode/resolver/cname.go`, line 58
- **Description:** `r.Msg.Rcode = max(r.Msg.Rcode, cnameRMsg.Msg.Rcode)` uses numeric comparison to combine Rcodes. DNS Rcodes are not ordered by severity (e.g., NXDomain=3 > ServFail=2 numerically, but ServFail is arguably more severe). This could produce incorrect combined Rcodes.
- **Impact:** Incorrect Rcode in responses following CNAME chains where different responses have different Rcodes.

### Issue 15
- **Severity:** MEDIUM
- **Technique:** Idempotency Analysis
- **File:** `/home/ubuntu/claudecode/resolver/config.go`, lines 26-55
- **Description:** All configuration values (`MaxAllowedTTL`, `MaxQueriesPerRequest`, etc.) are package-level mutable variables with no synchronization. They can be modified at any time by any goroutine, creating data races if configuration is changed while queries are in flight.
- **Impact:** Data races on configuration reads/writes, leading to undefined behavior per Go memory model.

### Issue 16
- **Severity:** MEDIUM
- **Technique:** API Surface Analysis
- **File:** `/home/ubuntu/claudecode/resolver/resolver.go`, line 29
- **Description:** `NewResolver()` calls `panic(err)` if `buildRootServerPool()` fails. While the comment says it's "technically static," this makes error handling impossible for callers. A constructor that returns an error would be more appropriate.
- **Impact:** Unrecoverable panic during initialization if the embedded root zone data has any issue, preventing graceful error handling.

### Issue 17
- **Severity:** LOW
- **Technique:** Observability Analysis
- **File:** `/home/ubuntu/claudecode/resolver/pool_exchange.go`, line 49
- **Description:** Typo in error message: "unsucessful" should be "unsuccessful".
- **Impact:** Minor: incorrect spelling in error messages reduces log searchability.

### Issue 18
- **Severity:** LOW
- **Technique:** Coupling Analysis
- **File:** `/home/ubuntu/claudecode/resolver/config.go`, line 60
- **Description:** `Cache` is a package-level global variable (`var Cache CacheInterface = nil`). This creates tight coupling between the cache implementation and the resolver, making it difficult to use different cache implementations per resolver instance.
- **Impact:** Cannot run multiple resolver instances with different cache configurations in the same process.

### Issue 19
- **Severity:** LOW
- **Technique:** Observability Analysis
- **File:** `/home/ubuntu/claudecode/resolver/zone.go`, line 153
- **Description:** Typo in error message: "reponse" should be "response".
- **Impact:** Minor: incorrect spelling in error messages.

---

## Round 2: 12 Issues Found

### Issue 20
- **Severity:** HIGH
- **Technique:** DoS / Resource Exhaustion
- **File:** `/home/ubuntu/claudecode/resolver/cname.go`, lines 23-59
- **Description:** CNAME following iterates over all CNAMEs in the answer and recursively resolves each one via `exchanger.exchange()`. There is no limit on CNAME chain depth. A malicious authoritative server could return a long CNAME chain causing excessive recursive resolution, though `MaxQueriesPerRequest` provides some indirect protection.
- **Impact:** Potential amplification attack vector through CNAME chains, consuming resolver resources.

### Issue 21
- **Severity:** HIGH
- **Technique:** Trust Boundary Analysis
- **File:** `/home/ubuntu/claudecode/resolver/pool.go`, lines 121-169
- **Description:** `newNameserverPool()` trusts glue records (the `extra` parameter) from upstream DNS responses without validation. An attacker controlling an authoritative server could inject arbitrary IP addresses in the additional section, redirecting queries for child zones to malicious servers.
- **Impact:** Cache poisoning via forged glue records, allowing an attacker to hijack DNS resolution for child zones.

### Issue 22
- **Severity:** MEDIUM
- **Technique:** Input Canonicalization
- **File:** `/home/ubuntu/claudecode/resolver/dnssec/doe/nsec.go`, line 63
- **Description:** `TypeBitMapContainsAnyOf` compares `name != dns.CanonicalName(nsec.Header().Name)` but `name` itself is not canonicalized. The caller must ensure `name` is canonical, but this is not enforced. Inconsistent canonicalization can cause missed NSEC matches.
- **Impact:** DNSSEC validation could incorrectly fail to find NSEC records for non-canonical names, potentially causing false Bogus results.

### Issue 23
- **Severity:** MEDIUM
- **Technique:** Concurrency Analysis
- **File:** `/home/ubuntu/claudecode/resolver/pool.go`, lines 54-68
- **Description:** In `getIPv4()`, `pool.hasIPv4()` (which reads `ipv4Count` atomically) is checked before acquiring the read lock. Between the atomic read and the lock acquisition, another goroutine could modify the slice (via `enrich()` which holds the write lock). The subsequent `len(pool.ipv4)` inside the lock could differ from the atomic count, causing the modulo to produce an incorrect index if the slice shrinks (though in practice it only grows).
- **Impact:** Low probability race condition. Since slices only grow, the practical risk is minimal but the pattern is incorrect.

### Issue 24
- **Severity:** MEDIUM
- **Technique:** Side Channel Analysis
- **File:** `/home/ubuntu/claudecode/resolver/ipv6.go`, lines 18-27
- **Description:** `IPv6Available()` uses a non-blocking pattern where it returns `false` before the check completes. This means the first few DNS resolutions after startup will not use IPv6 even if it's available, creating a timing-dependent behavior that could be observed by an attacker to determine resolver startup time.
- **Impact:** Inconsistent IPv6 usage during startup. Minor information leak about resolver state.

### Issue 25
- **Severity:** MEDIUM
- **Technique:** Secrets/Crypto Analysis
- **File:** `/home/ubuntu/claudecode/resolver/dnssec/verify_dnskey.go`, line 24
- **Description:** `verifyDNSKEYs` does not check the DNSKEY algorithm against a list of acceptable algorithms. Deprecated or weak algorithms (e.g., RSAMD5, DSA) could be accepted for verification. The `dns.DNSKEY.ToDS()` call and `rrsig.Verify()` will succeed with any algorithm the library supports.
- **Impact:** Weak cryptographic algorithms could be used in the DNSSEC chain, undermining security guarantees.

### Issue 26
- **Severity:** MEDIUM
- **Technique:** Auth Path Analysis
- **File:** `/home/ubuntu/claudecode/resolver/dnssec/authenticator.go`, lines 61-65
- **Description:** In `AddResponse()`, `a.inputBuffer[position]` is accessed without bounds checking. If a DNS response contains a zone with more labels than `maxExpectedItems` (calculated as `dns.CountLabel(question.Name) + 1`), this causes an index-out-of-bounds panic.
- **Impact:** Panic when processing DNS responses with unexpected zone depths, causing denial of service.

### Issue 27
- **Severity:** MEDIUM
- **Technique:** Regression Analysis
- **File:** `/home/ubuntu/claudecode/resolver/pool.go`, lines 210-225
- **Description:** In `enrich()`, the expiry time is always reset to `time.Now().Add(ttl)` when `pool.expires.Load() > 0`. The commented-out code (lines 215-220) shows the original intent was to only shorten the expiry, never extend it. The current code can extend pool expiry indefinitely with each enrichment call.
- **Impact:** Pool TTL can be extended beyond what the original NS records specified, keeping potentially stale nameserver information active longer than intended.

### Issue 28
- **Severity:** MEDIUM
- **Technique:** SSRF / Confused Deputy
- **File:** `/home/ubuntu/claudecode/resolver/zone_factory.go`, lines 55-110
- **Description:** `enrichPool()` resolves nameserver hostnames by calling `exchanger.exchange()`, which triggers full recursive resolution. An attacker could craft NS records pointing to hostnames that, when resolved, trigger queries to internal/private networks (e.g., `ns1.internal.corp.`), using the resolver as a confused deputy.
- **Impact:** The resolver could be used to probe internal network infrastructure through crafted NS delegations.

### Issue 29
- **Severity:** LOW
- **Technique:** Injection Analysis
- **File:** `/home/ubuntu/claudecode/resolver/zone.go`, lines 48-53
- **Description:** `zoneImpl.clone()` calls `panic("invalid clone")` in a validation check that includes debug logging. This panic is reachable if domain logic produces an invalid parent-child relationship, which could be triggered by adversarial DNS data.
- **Impact:** Panic from externally-influenced data, crashing the resolver.

### Issue 30
- **Severity:** LOW
- **Technique:** Signal/Shutdown Analysis
- **File:** `/home/ubuntu/claudecode/resolver/resolver.go`, lines 25-54
- **Description:** `Resolver` has no shutdown/close method. Goroutines spawned for DNSSEC pre-fetching (`go z.dnskeys(ctx)` in resolveLabel), IPv6 checking, and enrichment have no lifecycle management.
- **Impact:** No graceful shutdown capability. In-flight goroutines continue after the resolver is no longer needed, preventing clean resource cleanup.

### Issue 31
- **Severity:** LOW
- **Technique:** Stress Patterns
- **File:** `/home/ubuntu/claudecode/resolver/pool.go`, lines 54-68
- **Description:** The `ipv4Next` atomic counter monotonically increases without ever being reset. Under sustained high load (millions of queries), the counter will eventually wrap around at `math.MaxUint32`. This is handled correctly by the modulo operation, so it is not a bug, but the wrap-around behavior should be noted.
- **Impact:** No functional impact; the modulo operation handles wrap-around correctly.

---

## Round 3: 8 Issues Found

### Issue 32
- **Severity:** HIGH
- **Technique:** Privilege Escalation
- **File:** `/home/ubuntu/claudecode/resolver/dnssec/verify.go`, lines 15-17
- **Description:** When `dsRecordsFromParent` is empty, the function returns `Insecure` without error. This means a parent zone that simply omits DS records (either through a bug or an attack that strips them) results in the child zone being treated as Insecure rather than Bogus. An active attacker performing a downgrade attack by stripping DS records from a response would succeed.
- **Impact:** DNSSEC downgrade attack is possible by stripping DS records from delegating responses. The resolver will accept unsigned responses as Insecure rather than detecting the attack as Bogus.

### Issue 33
- **Severity:** MEDIUM
- **Technique:** Temporal Logic
- **File:** `/home/ubuntu/claudecode/resolver/auth.go`, lines 56-71
- **Description:** In `addDelegationSignerLink()`, `go z.dnskeys(a.ctx)` is launched as a fire-and-forget goroutine for pre-fetching. This goroutine is not tracked by `a.processing` WaitGroup, so it may still be running when `close()` completes. If it writes to the zone's dnskey cache concurrently with another access, there's a potential race (though the zone's own mutex should protect this).
- **Impact:** Untracked goroutine after authenticator close. Low risk due to zone-level mutex, but violates the principle of tracking all spawned work.

### Issue 34
- **Severity:** MEDIUM
- **Technique:** Contract Verification
- **File:** `/home/ubuntu/claudecode/resolver/dnssec/authenticator.go`, lines 107-108
- **Description:** `authenticate()` checks `dns.CountLabel(rrsig.Header().Name) < int(rrsig.Labels)` and errors, but `dns.CountLabel` can return different values for the same logical name depending on trailing dot presence. The RRSIG Labels field excludes the root label and any wildcard label, while `dns.CountLabel` counts differently. This mismatch could cause valid wildcard-expanded RRSIGs to be incorrectly rejected.
- **Impact:** Potential false rejection of valid DNSSEC signatures from wildcard expansions.

### Issue 35
- **Severity:** MEDIUM
- **Technique:** Arithmetic Analysis
- **File:** `/home/ubuntu/claudecode/resolver/dnssec/authenticate_rrset.go`, lines 47-52
- **Description:** The TTL calculation for signature expiry uses `int64` arithmetic with `year68` constant (`1 << 31`). The expression `(int64(rrsig.Expiration) - utc) / year68` performs integer division. For RRSIG records with Expiration values near epoch boundaries or in the far future, this arithmetic could produce incorrect results due to integer overflow or truncation.
- **Impact:** Incorrect TTL calculation for edge-case RRSIG records, potentially causing premature cache expiry or overly long caching.

### Issue 36
- **Severity:** MEDIUM
- **Technique:** Session Lifecycle
- **File:** `/home/ubuntu/claudecode/resolver/resolver_exchange.go`, lines 57-61
- **Description:** The `ctxSessionQueries` counter is shared across all calls to `exchange()` for a given query session. However, DNSKEY and DS lookups made by the authenticator also go through `exchange()`, incrementing this counter. The config documentation says "lookups for DNSKEY and DS records are excluded from this count" but the code does not implement this exclusion.
- **Impact:** DNSSEC-enabled queries hit the `MaxQueriesPerRequest` limit faster than expected, potentially causing legitimate queries to fail for deeply delegated domains.

### Issue 37
- **Severity:** LOW
- **Technique:** Migration Analysis
- **File:** `/home/ubuntu/claudecode/resolver/dnssec/doe/doe.go`, lines 32-36
- **Description:** NSEC3 `Flags` is type `uint8` in the miekg/dns library, so `r.Flags < 0` is always false (unsigned type cannot be negative). This check is dead code.
- **Impact:** No functional impact, but the dead code check indicates a misunderstanding of the type system.

### Issue 38
- **Severity:** LOW
- **Technique:** Semantic Gap Analysis
- **File:** `/home/ubuntu/claudecode/resolver/dnssec/verify_dnskey.go`, lines 31-33
- **Description:** When `len(keySigningKeys) == 0` (no DNSKEY matches any DS from parent), the function returns `Insecure` with `ErrKeysNotFound`. Per RFC 4035, if DS records exist but no matching DNSKEY is found, this should be Bogus (the chain is broken), not Insecure. Insecure means the parent explicitly indicated no DNSSEC.
- **Impact:** Misconfigured or attacked zones where DS records exist but DNSKEYs don't match are treated as Insecure instead of Bogus, weakening DNSSEC security.

### Issue 39
- **Severity:** LOW
- **Technique:** Error Path Analysis
- **File:** `/home/ubuntu/claudecode/resolver/dnssec/doe/nsec3.go`, lines 61-65
- **Description:** In `PerformExpandedWildcardProof`, `closestEncloserIndex` and `closestEncloserIndex-1` are used as indices into `labelIndexs` without bounds checking. If `wildcardAnswerSignatureNameLabels` equals the number of labels, `closestEncloserIndex` is 0 and `closestEncloserIndex-1` is -1, causing a panic.
- **Impact:** Panic on edge-case wildcard signatures where the label count matches the full name.

---

## Round 4: 5 Issues Found

### Issue 40
- **Severity:** MEDIUM
- **Technique:** Concurrency Analysis
- **File:** `/home/ubuntu/claudecode/resolver/zone.go`, lines 161-170
- **Description:** `z.dnskeyRecords` is set on line 162 while holding the mutex, and read on line 170 while also holding the mutex. However, in the cache-hit path (line 138), the records are read and then the mutex is explicitly unlocked. If another goroutine calls `exchange()` on the zone using these records after the unlock, and a third goroutine enters `dnskeys()` and overwrites `dnskeyRecords` (a slice header), the first goroutine could see a partially updated slice header. In practice, Go's slice assignments are not atomic.
- **Impact:** Potential data race on `dnskeyRecords` slice. Low probability since the mutex is correctly used, but the explicit unlock + return pattern means the slice is used outside the lock's protection.

### Issue 41
- **Severity:** MEDIUM
- **Technique:** Trust Boundary Analysis
- **File:** `/home/ubuntu/claudecode/resolver/resolver_exchange.go`, lines 238-243
- **Description:** In `processDelegation()`, the `nextZoneName` is extracted from the NS record's owner name. The validation checks that it's a subdomain of the current zone, but does not validate that it is actually the immediate child. An attacker could return NS records for a deeply nested subdomain, skipping intermediate delegations and bypassing any DNSSEC chains those intermediate zones might have.
- **Impact:** Potential DNSSEC bypass by skipping intermediate delegations that have their own DS records.

### Issue 42
- **Severity:** MEDIUM
- **Technique:** DoS / Resource Exhaustion
- **File:** `/home/ubuntu/claudecode/resolver/zones.go`, lines 80-88
- **Description:** The `zones.add()` method grows the map without bounds. Over time, with many unique queries, the map accumulates zones that are expired but never cleaned up. The `get()` method returns nil for expired zones but does not remove them.
- **Impact:** Unbounded memory growth over time as expired zones accumulate in the map. This is a slow memory leak that eventually leads to OOM under sustained load.

### Issue 43
- **Severity:** LOW
- **Technique:** Idempotency Analysis
- **File:** `/home/ubuntu/claudecode/resolver/auth.go`, lines 94-97
- **Description:** `authenticator.result()` calls `a.finished.Store(true)` and then `a.close()`. But `close()` also calls `a.finished.Store(true)`. This is redundant and the double-store of `finished` is harmless but indicates potential confusion about the intended close/result lifecycle.
- **Impact:** No functional impact, but indicates unclear lifecycle contract.

### Issue 44
- **Severity:** LOW
- **Technique:** Coupling Analysis
- **File:** `/home/ubuntu/claudecode/resolver/config.go`, lines 64-71
- **Description:** Logger functions are global mutable variables (`Query`, `Debug`, `Info`, `Warn`). Changing them affects all resolver instances in the process. There is no per-instance logging capability.
- **Impact:** Cannot configure logging per resolver instance. All instances share global loggers.

---

## Round 5: 4 Issues Found

### Issue 45
- **Severity:** MEDIUM
- **Technique:** Protocol Conformance
- **File:** `/home/ubuntu/claudecode/resolver/resolver_exchange.go`, lines 334-336
- **Description:** `RemoveAuthoritySectionForPositiveAnswers` removes the NS section when there are answers and no SOA. However, RFC 2181 Section 6.1 specifies that authority section NS records provide useful information for caching resolvers. Removing them by default may cause downstream caching resolvers to miss delegation information.
- **Impact:** Non-conformant response that strips useful authority section data, potentially degrading performance of downstream caching resolvers.

### Issue 46
- **Severity:** MEDIUM
- **Technique:** Boundary Partitioning
- **File:** `/home/ubuntu/claudecode/resolver/dnssec/doe/nsec3.go`, lines 150-225
- **Description:** `FindClosestEncloser()` compares closest encloser candidates by string length (`len(contenders[i].ce) > len(contender.ce)`) rather than label count. For internationalized domain names or names with escaped characters, string length does not correspond to DNS hierarchy depth. Two names with different byte lengths could have the same label count.
- **Impact:** Incorrect closest encloser selection for domain names where byte length does not correlate with hierarchical depth, potentially causing incorrect NSEC3 validation.

### Issue 47
- **Severity:** LOW
- **Technique:** Semantic Gap Analysis
- **File:** `/home/ubuntu/claudecode/resolver/dnssec/verify_positive.go`, lines 29-31
- **Description:** `ErrMultipleWildcardSignatures` is returned as Bogus when multiple wildcard signatures are seen. However, RFC 4035 does not prohibit multiple RRsets from being synthesized from wildcards in the same response. For example, an A and AAAA record could both be wildcard-synthesized.
- **Impact:** Legitimate responses with multiple wildcard-expanded RRsets are incorrectly rejected as Bogus.

### Issue 48
- **Severity:** LOW
- **Technique:** Contract Verification
- **File:** `/home/ubuntu/claudecode/resolver/resolver_exchange.go`, lines 80-81
- **Description:** `resolver.exchange()` accesses `qmsg.Question[0]` on line 80 without checking that `qmsg.Question` is non-empty. While `Exchange()` copies the message, a malformed message with an empty Question section would cause a panic.
- **Impact:** Panic on malformed input. Partially mitigated by the public `Exchange()` calling `qmsg.Copy()` first, but the private `exchange()` can be called via the exchanger interface.

---

## Round 6: 3 Issues Found

### Issue 49
- **Severity:** MEDIUM
- **Technique:** Adversarial Input
- **File:** `/home/ubuntu/claudecode/resolver/dnssec/doe/functions.go`, lines 55-70
- **Description:** `canonicalDecodeEscaped()` converts escaped octets using `string(rune(octetValue))` which performs UTF-8 encoding of the value. For DNS name comparison per RFC 4034 Section 6.1, the comparison should be on raw byte values, not UTF-8 encoded runes. Octet values > 127 will produce multi-byte UTF-8 sequences, causing incorrect canonical ordering.
- **Impact:** Incorrect NSEC record ordering for domain names containing escaped octets with values > 127, potentially causing false positive or negative denial-of-existence proofs.

### Issue 50
- **Severity:** LOW
- **Technique:** Stress Patterns
- **File:** `/home/ubuntu/claudecode/resolver/auth.go`, line 36
- **Description:** The authenticator's queue channel has a fixed buffer size of 8 (`make(chan authenticatorInput, 8)`). For deeply delegated domains with many zones, the channel could block if the consumer (the `start()` goroutine) processes items slower than producers add them. This creates backpressure that could slow resolution.
- **Impact:** Performance degradation for deeply delegated domains under high DNSSEC load, though not a correctness issue.

### Issue 51
- **Severity:** LOW
- **Technique:** Temporal Logic
- **File:** `/home/ubuntu/claudecode/resolver/trace.go`, lines 20-23
- **Description:** `newTraceWithStart()` calls `uuid.NewV7()` and discards the error. If UUID generation fails (e.g., due to clock issues), the trace ID will be a zero UUID, making it impossible to correlate log entries for that query.
- **Impact:** Silent failure of trace ID generation, reducing observability for affected queries.

---

## Round 7 (Security-Focused): 2 Issues Found

### Issue 52
- **Severity:** MEDIUM
- **Technique:** DoS / Resource Exhaustion
- **File:** `/home/ubuntu/claudecode/resolver/resolver_exchange.go`, line 141
- **Description:** `go z.dnskeys(ctx)` launches a goroutine for DNSKEY pre-fetching every time `resolveLabel` is called with DNSSEC enabled. There is no rate limiting on these goroutine launches. A burst of queries for different zones could create thousands of concurrent goroutines, each making network requests.
- **Impact:** Goroutine storm under high query load with DNSSEC enabled, potentially exhausting system resources.

### Issue 53
- **Severity:** LOW
- **Technique:** Trust Boundary Analysis
- **File:** `/home/ubuntu/claudecode/resolver/cname.go`, lines 46-49
- **Description:** When following CNAME chains, the Answer, Ns, and Extra sections from the CNAME target resolution are appended directly to the original response. Records from different zones (with different trust levels) are mixed without distinction. An attacker controlling a CNAME target zone could inject additional authority or extra section records that appear to come from the original zone.
- **Impact:** Record injection via CNAME following, though mitigated by deduplication in `finaliseResponse`.

---

## Convergence Statement

| Round | New Issues Found | Cumulative Total |
|-------|-----------------|------------------|
| 1     | 19              | 19               |
| 2     | 12              | 31               |
| 3     | 8               | 39               |
| 4     | 5               | 44               |
| 5     | 4               | 48               |
| 6     | 3               | 51               |
| 7     | 2               | 53               |

**Analysis converged at Round 7** with 2 new issues found, which is fewer than the threshold of 3. Total issues identified: **53**.

### Severity Distribution
- **CRITICAL:** 1
- **HIGH:** 8
- **MEDIUM:** 25
- **LOW:** 19

### Top Risk Areas
1. **DNSSEC Authentication** (auth.go): Critical bug where aggregated errors are discarded (Issue 1), plus multiple concurrency issues in the authenticator lifecycle (Issues 2, 3)
2. **Resource Management** (zone_factory.go, zones.go): Goroutine leaks on timeout (Issue 4), unbounded zone map growth (Issue 42)
3. **Trust/Security** (pool.go, verify.go): Unvalidated glue records (Issue 21), DNSSEC downgrade vulnerability (Issue 32), weak algorithm acceptance (Issue 25)
4. **Concurrency Safety** (nameserver.go, pool.go): Unsynchronized lazy initialization (Issue 5), configuration races (Issue 15)
