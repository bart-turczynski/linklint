Feature: Success criteria — core lexical (PRD §7)

  The capstone matrix for SC-1 / SC-1a / SC-2 / SC-2a. (SC-3 is in
  mcp_prefetch.feature; SC-4 is covered by the runtime-compat tests.)

  Scenario Outline: SC-1 — the canonical attack set scores >= medium with the right reason code
    When I inspect "<input>"
    Then the status is "ok"
    And the severity is at least "medium"
    And the reasons contain "<reason>"

    Examples:
      | input                                          | reason                       |
      | https://pаypal.com                             | mixed_script                 |
      | https://paypal.com@evil.com/login              | userinfo_present             |
      | http://2130706433/                             | ip_obfuscation               |
      | https://paypal.com.spoof.info/                 | embedded_domain_in_subdomain |
      | javascript:alert(1)                            | dangerous_scheme             |
      | data:text/html,<script>                        | dangerous_scheme             |

  Scenario Outline: SC-1a — informational-only cases annotate (weight 0) and stay benign
    When I inspect "<input>"
    Then the status is "ok"
    And the score is 0
    And the severity is "info"
    And the reasons contain "<reason>"
    And the reason "<reason>" has weight 0

    Examples:
      | input                              | reason              |
      | https://xn--bcher-kva.de/          | normalization_delta |
      | https://пример.com                 | confusable_char     |

  Scenario Outline: SC-2 — legitimate single-script IDNs are not flagged
    When I inspect "<input>"
    Then the status is "ok"
    And the score is 0
    And the severity is "info"
    And the reasons do not contain "mixed_script"

    Examples:
      | input                       |
      | https://bücher.de/          |
      | https://müller.de/          |
      | https://日本語.jp/           |
      | https://пример.com          |

  Scenario: SC-2a — unparseable input is invalid, not benign
    When I inspect "ht!tp://%%%not a url"
    Then the status is "invalid"
    And score is null
    And severity is null
    And the reasons contain "parse_error"
