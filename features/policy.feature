Feature: Caller-configurable policy layer

  The policy layer is a separate, caller-owned channel layered on top of the
  built-in deception analysis. Each axis (TLD, host, scheme, port) supports an
  allow and/or deny mode. Policy hits surface in reasons[] with layer "policy"
  and weight 0, so they annotate without ever moving the deception score or
  severity, and "policy" appears in checksRun only when an axis is configured.

  Scenario: denyTlds flags a listed TLD (deny mode)
    When I inspect "https://promo.ru/" with policy:
      | denyTlds | ru,cn |
    Then the status is "ok"
    And the reasons contain "tld_denied"
    And the reason "tld_denied" has layer "policy"
    And the reason "tld_denied" has weight 0
    And checksRun is "lexical,policy"

  Scenario: allowTlds flags a TLD that is not allow-listed (allow mode)
    When I inspect "https://example.org/" with policy:
      | allowTlds | com,de |
    Then the reasons contain "tld_not_allowlisted"
    And the reason "tld_not_allowlisted" has layer "policy"

  Scenario: denyHosts flags a listed registrable domain (deny mode)
    When I inspect "https://www.evil.com/" with policy:
      | denyHosts | evil.com |
    Then the reasons contain "host_denied"
    And the reason "host_denied" has weight 0

  Scenario: allowHosts corporate lockdown flags an outside host (allow mode)
    When I inspect "https://random.io/" with policy:
      | allowHosts | mycompany.com,vendor.io |
    Then the reasons contain "host_not_allowlisted"
    And the reason "host_not_allowlisted" has layer "policy"

  Scenario: denySchemes flags a listed scheme (deny mode)
    When I inspect "ftp://example.com/" with policy:
      | denySchemes | ftp,data |
    Then the reasons contain "scheme_denied"
    And the reason "scheme_denied" has weight 0

  Scenario: allowSchemes https-only lockdown flags http (allow mode)
    When I inspect "http://example.com/" with policy:
      | allowSchemes | https |
    Then the reasons contain "scheme_denied"
    And the reason "scheme_denied" has layer "policy"

  Scenario: denyPorts flags a listed explicit port (deny mode)
    When I inspect "https://example.com:8080/" with policy:
      | denyPorts | 8080,31337 |
    Then the reasons contain "port_denied"
    And the reason "port_denied" has weight 0

  Scenario: denyNonStandardPorts flags a non-default port (deny mode)
    When I inspect "https://example.com:8080/" with policy:
      | denyNonStandardPorts | true |
    Then the reasons contain "port_denied"
    And the reason "port_denied" has layer "policy"

  Scenario: a fully-locked-down corporate policy passes a legitimate input
    When I inspect "https://app.mycompany.com/" with policy:
      | allowTlds    | com           |
      | allowHosts   | mycompany.com |
      | allowSchemes | https         |
    Then the status is "ok"
    And the score is 0
    And the severity is "info"
    And the reasons do not contain "tld_not_allowlisted"
    And the reasons do not contain "host_not_allowlisted"
    And the reasons do not contain "scheme_denied"
    And checksRun is "lexical,policy"

  Scenario: channel separation — a benign input keeps its severity while gaining a policy reason
    When I inspect "https://www.example.com/" with policy:
      | denyTlds   | com         |
      | denyHosts  | example.com |
    Then the severity is "info"
    And the score is unchanged from the no-policy baseline
    And the reasons contain "tld_denied"
    And the reason "tld_denied" has weight 0
    And checksRun is "lexical,policy"

  Scenario: channel separation — a deceptive input keeps its critical severity while gaining a policy reason
    When I inspect "javascript:alert(1)" with policy:
      | denySchemes | javascript |
    Then the severity is "critical"
    And the score is unchanged from the no-policy baseline
    And the reasons contain "dangerous_scheme"
    And the reasons contain "scheme_denied"
    And the reason "scheme_denied" has weight 0
    And the reason "dangerous_scheme" has layer "lexical"
