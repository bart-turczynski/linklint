Feature: Layer 2 online resolution protocol, safety, and partial-state matrix
  The async resolution enrichers (redirect-chain, divergence probe, embedded
  wrapper) run over a deterministic fixture transport with a frozen clock and
  ZERO real network. These scenarios pin the protocol mechanics, the SSRF safety
  boundary, and the partial/degraded states each source must surface explicitly.

  # --- Deterministic mechanics (exact assertions, no precision/recall) --------

  Scenario: A bounded 302 to 200 chain expands to ordered hops
    Given the resolution fixture responds:
      | url                                | status | location  | contentType |
      | https://origin.example/start       | 302    | /landing  |             |
      | https://origin.example/landing     | 200    |           | text/plain  |
    When I resolve "https://origin.example/start" through the redirect-chain enricher
    Then the status is one of "ok,suspicious,likely_malicious,malicious"
    And checksRun contains "resolution:redirect-chain.http"
    And the enrichment outcome subjects are "https://origin.example/start,https://origin.example/landing"
    And the fixture transport is exhausted

  Scenario: A redirect loop stops with an explicit failure
    Given the resolution fixture responds:
      | url                          | status | location |
      | https://origin.example/start | 302    | /start   |
    When I resolve "https://origin.example/start" through the redirect-chain enricher
    Then an enrichment outcome with status "failure" has cause "redirect-loop"
    And checksSkipped contains "resolution:redirect-chain.http"
    And the fixture transport is exhausted

  Scenario: A hop cap stops with an explicit failure
    Given the resolution fixture responds:
      | url                          | status | location |
      | https://origin.example/start | 302    | /next    |
    When I resolve "https://origin.example/start" through the redirect-chain enricher capped at 1 hops
    Then an enrichment outcome with status "failure" has cause "hop-limit"
    And checksSkipped contains "resolution:redirect-chain.http"
    And the fixture transport is exhausted

  Scenario: SSRF safety - a hop resolving to cloud metadata is skipped before connect
    Given the resolution fixture responds:
      | url                          | status |
      | https://origin.example/start | 200    |
    And host "origin.example" resolves to the cloud metadata address
    When I resolve "https://origin.example/start" through the redirect-chain enricher
    Then an enrichment outcome with status "skipped" has cause "prohibited-address"
    And an enrichment evidence record of type "transport.attempt" exists
    And the fixture transport is exhausted

  Scenario: An embedded Microsoft Safe Links wrapper decodes to a re-inspected destination
    When I decode a Microsoft Safe Links wrapper for "https://paypa1.com/secure/login" through the embedded-wrapper enricher
    Then checksRun contains "resolution:embedded-wrapper.local"
    And an enrichment outcome subject is "https://paypa1.com/secure/login"
    And the reasons contain "brand_homoglyph"

  # --- Additive evidence and partial states -----------------------------------

  Scenario: An observed open redirect landing on the payload domain is confirmed additively
    Given the resolution fixture responds:
      | url                                                   | status | location                    | contentType |
      | https://example.com/login?next=https://evil.com/phish | 302    | https://evil.com/phish      |             |
      | https://evil.com/phish                                | 200    |                             | text/plain  |
    When I resolve "https://example.com/login?next=https://evil.com/phish" through the redirect-chain enricher
    Then the reasons contain "open_redirect_param"
    And the reasons contain "open_redirect_observed"
    And the reason "open_redirect_observed" has weight 0
    And the fixture transport is exhausted

  Scenario: Declared PNG that sniffs to executable HTML without nosniff flags a mismatch
    Given the resolution fixture responds:
      | url                          | status | contentType | body                                    |
      | https://origin.example/asset | 200    | image/png   | <script>alert(document.cookie)</script> |
    When I resolve "https://origin.example/asset" through the redirect-chain enricher
    Then the reasons contain "content_type_mismatch"
    And an enrichment evidence record of type "resolution.mime-evidence" exists
    And the fixture transport is exhausted

  Scenario: The same mismatch under nosniff records evidence but raises no reason
    Given the resolution fixture responds:
      | url                          | status | contentType | nosniff | body                                    |
      | https://origin.example/asset | 200    | image/png   | yes     | <script>alert(document.cookie)</script> |
    When I resolve "https://origin.example/asset" through the redirect-chain enricher
    Then the reasons do not contain "content_type_mismatch"
    And an enrichment evidence record of type "resolution.mime-evidence" exists
    And the fixture transport is exhausted

  Scenario: A HEAD hop leaves MIME evidence incomplete with no body to sniff
    Given the resolution fixture responds:
      | url                          | status | method | contentType | body                                    |
      | https://origin.example/asset | 200    | HEAD   | image/png   | <script>alert(document.cookie)</script> |
    When I resolve "https://origin.example/asset" through the redirect-chain enricher using HEAD
    Then an enrichment evidence record of type "resolution.mime-evidence" has "status" equal to "incomplete"
    And the reasons do not contain "content_type_mismatch"
    And the fixture transport is exhausted

  Scenario: A UA-conditioned divergence is recorded as evidence without any new reason
    Given the resolution fixture responds:
      | url                          | status | location                       | contentType             | body                          |
      | https://origin.example/page  | 200    |                                | text/html; charset=utf-8 | <html><body>real</body></html> |
      | https://origin.example/page  | 302    | https://evil.example/landing   |                         |                               |
    When I resolve "https://origin.example/page" through the divergence probe
    Then an enrichment evidence record of type "resolution.divergence" has "divergent" equal to "true"
    And the reasons equal the synchronous inspection of "https://origin.example/page"
    And the fixture transport is exhausted

  Scenario: A challenge-gated variant is an explicit resolution-incomplete skip
    Given the resolution fixture responds:
      | url                          | status | contentType             | body                                                                                                                              |
      | https://origin.example/page  | 200    | text/html; charset=utf-8 | <html><body>real</body></html>                                                                                                    |
      | https://origin.example/page  | 403    | text/html; charset=utf-8 | <html><head><title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page"></script></head></html> |
    When I resolve "https://origin.example/page" through the divergence probe
    Then an enrichment outcome with status "skipped" has cause "challenge-gate"
    And checksSkipped contains "resolution:divergence-probe.http"
    And the fixture transport is exhausted

  # --- Zero-network offline invariant -----------------------------------------

  Scenario: Async inspection with no enrichers is identical to sync inspection
    When I inspect "https://paypa1.com/secure/login" asynchronously with no enrichers
    Then the async result matches the synchronous inspection
