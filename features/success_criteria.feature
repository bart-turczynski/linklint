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

  # ── Epic J — parser-differential & structural-obfuscation detectors ──────

  Scenario Outline: Epic J — parser-differential attacks score >= medium with the right reason
    When I inspect "<input>"
    Then the status is "ok"
    And the severity is at least "medium"
    And the reasons contain "<reason>"

    Examples:
      | input                               | reason              |
      | http://foo@evil.com:80@google.com/  | ambiguous_authority |
      | http://target.com/////evil.com      | ambiguous_authority |
      | https://github.com∕x@evil.zip       | separator_lookalike |
      | http://127.0.0.1:6379/%0D%0ASLAVEOF | control_char        |
      | http://example.com/%250D%250Aevil   | control_char        |
      | https://[::ffff:127.0.0.1]/         | ip_obfuscation      |
      | https://invoice.zip/                | file_extension_tld  |

  Scenario Outline: Epic J — low-weight structural signals score >= low (meaningful in combination)
    When I inspect "<input>"
    Then the status is "ok"
    And the severity is at least "low"
    And the reasons contain "<reason>"

    Examples:
      | input                             | reason          |
      | https://g00gle.com                | ascii_homoglyph |
      | https://paypa1.com                | ascii_homoglyph |
      | https://evil.com/paypal.com/login | brand_in_path   |

  Scenario Outline: Epic J — IDNA mapping ambiguity annotates (weight 0) and stays benign
    When I inspect "<input>"
    Then the status is "ok"
    And the score is 0
    And the severity is "info"
    And the reasons contain "idna_mapping_ambiguity"
    And the reason "idna_mapping_ambiguity" has weight 0

    Examples:
      | input                  |
      | https://wordpreß.com   |
      | https://ｇｏｏｇｌｅ.com      |

  Scenario Outline: Epic J — a structurally ambiguous but unresolvable URL is invalid yet explained
    When I inspect "<input>"
    Then the status is "invalid"
    And score is null
    And the reasons contain "<reason>"

    Examples:
      | input                        | reason              |
      | //evil.com                   | ambiguous_authority |
      | http://127.0.0.1:11211:80/   | ambiguous_authority |
      | http://google。com           | separator_lookalike |

  Scenario Outline: Epic J — must not over-flag legitimate look-alikes (SC-2)
    When I inspect "<input>"
    Then the status is "ok"
    And the score is 0
    And the severity is "info"
    And the reasons do not contain "<forbidden>"

    Examples:
      | input                                              | forbidden          |
      | https://[::1]:8080/                                | ip_obfuscation     |
      | https://s3.amazonaws.com/my-bucket/key             | ascii_homoglyph    |
      | https://github.com/anthropics/repo/archive/main.zip | file_extension_tld |
      | https://paypal.com/login                           | brand_in_path      |
      | https://straße.de/                                 | mixed_script       |
