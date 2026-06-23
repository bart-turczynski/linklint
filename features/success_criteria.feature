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
    When I inspect "<input>" allowing IDNs
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
    When I inspect "<input>" allowing IDNs
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

  Scenario Outline: V2 — internationalized domains are blocked by default (idn_host)
    When I inspect "<input>"
    Then the status is "ok"
    And the severity is at least "high"
    And the reasons contain "idn_host"

    Examples:
      | input                      |
      | https://münchen.de         |
      | https://пример.com         |
      | https://xn--mnchen-3ya.de/ |

  Scenario: V2 — the IDN block is opt-out (idnPolicy allow)
    When I inspect "https://münchen.de" allowing IDNs
    Then the status is "ok"
    And the score is 0
    And the severity is "info"
    And the reasons do not contain "idn_host"

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

  Scenario Outline: Epic J — IDNA mapping ambiguity annotates (weight 0) and stays benign
    When I inspect "<input>" allowing IDNs
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
    When I inspect "<input>" allowing IDNs
    Then the status is "ok"
    And the score is 0
    And the severity is "info"
    And the reasons do not contain "<forbidden>"

    Examples:
      | input                                              | forbidden          |
      | https://s3.amazonaws.com/my-bucket/key             | ascii_homoglyph    |
      | https://github.com/anthropics/repo/archive/main.zip | file_extension_tld |
      | https://straße.de/                                 | mixed_script       |

  # ── V1b — literal-IP range classifier (loopback / private / link-local / metadata / reserved) ──

  Scenario Outline: V1b — the cloud instance-metadata endpoint scores >= medium with ip_cloud_metadata
    When I inspect "<input>"
    Then the status is "ok"
    And the severity is at least "medium"
    And the reasons contain "ip_cloud_metadata"

    Examples:
      | input                                  |
      | http://169.254.169.254/latest/meta-data/ |
      | https://[fd00:ec2::254]/               |

  Scenario Outline: V1b — generic internal-range literals score >= low with their bucket reason
    When I inspect "<input>"
    Then the status is "ok"
    And the severity is at least "low"
    And the reasons contain "<reason>"
    And the reasons do not contain "ip_obfuscation"

    Examples:
      | input                       | reason         |
      | http://127.0.0.1:3000/      | ip_loopback    |
      | http://127.5.6.7/           | ip_loopback    |
      | https://[::1]:8080/         | ip_loopback    |
      | 192.168.1.1                 | ip_private     |
      | http://10.1.2.3/admin       | ip_private     |
      | https://[fd12:3456:789a::1]/ | ip_private     |
      | http://169.254.10.20/       | ip_link_local  |
      | https://[fe80::abcd]/       | ip_link_local  |
      | http://0.0.0.10/            | ip_reserved    |
      | http://100.64.1.1/          | ip_reserved    |
      | http://239.0.0.1/           | ip_reserved    |
      | https://[ff02::1]/          | ip_reserved    |

  Scenario Outline: V1b — precedence: the most-specific bucket wins
    When I inspect "<input>"
    Then the status is "ok"
    And the reasons contain "<expected>"
    And the reasons do not contain "<forbidden>"

    Examples:
      | input                  | expected          | forbidden     |
      | http://169.254.169.254/ | ip_cloud_metadata | ip_link_local |

  Scenario Outline: V1b — IPv4-in-IPv6 embeddings classify by the embedded IPv4
    When I inspect "<input>"
    Then the status is "ok"
    And the reasons contain "<reason>"

    Examples:
      | input                            | reason            |
      | https://[::ffff:127.0.0.1]/      | ip_loopback       |
      | https://[::ffff:169.254.169.254]/ | ip_cloud_metadata |

  # ── Epic I — download / redirect / subdomain-depth detectors ─────────────

  Scenario Outline: Epic I — download & redirect lures score >= medium with the right reason
    When I inspect "<input>"
    Then the status is "ok"
    And the severity is at least "medium"
    And the reasons contain "<reason>"

    Examples:
      | input                                                 | reason               |
      | https://cdn.example.com/setup.exe                     | suspicious_extension |
      | https://files.example.com/invoice.pdf.exe             | suspicious_extension |
      | https://example.com/login?next=https://evil.com/phish | open_redirect_param  |

  Scenario Outline: Epic I — excessive subdomain depth scores >= low (meaningful in combination)
    When I inspect "<input>"
    Then the status is "ok"
    And the severity is at least "low"
    And the reasons contain "excessive_subdomain_depth"

    Examples:
      | input                                |
      | https://a.b.c.d.e.example.com/       |
      | https://a.b.c.d.paypal.com.evil-login.tk/ |

  Scenario Outline: Epic I — must not over-flag legitimate links (SC-2)
    When I inspect "<input>"
    Then the status is "ok"
    And the score is 0
    And the severity is "info"
    And the reasons do not contain "<forbidden>"

    Examples:
      | input                                              | forbidden                 |
      | https://files.example.com/report.pdf               | suspicious_extension      |
      | https://example.com/login?next=/dashboard          | open_redirect_param       |
      | https://cdn.assets.eu-west-1.svc.example.com/      | excessive_subdomain_depth |

  # ── Epic G — brand-proximity family (homoglyph / lookalike / combosquat / bait) ──

  Scenario Outline: Epic G — exact-fold brand homoglyphs score >= high with brand_homoglyph
    When I inspect "<input>"
    Then the status is "ok"
    And the severity is at least "high"
    And the reasons contain "brand_homoglyph"

    Examples:
      | input                |
      | https://paypa1.com   |
      | https://g00gle.com   |
      | https://revo1ut.com  |

  Scenario Outline: Epic G — fuzzy look-alikes score >= medium with the right reason
    When I inspect "<input>"
    Then the status is "ok"
    And the severity is at least "medium"
    And the reasons contain "<reason>"

    Examples:
      | input                       | reason            |
      | https://gogole.com          | brand_lookalike   |
      | https://microsoftt.com      | brand_lookalike   |
      | https://paypal.co           | brand_lookalike   |

  Scenario: Epic G — a bait-stacked host scores >= low with bait_tokens (corroborating, low weight)
    When I inspect "https://secure-account-verify-login.com"
    Then the status is "ok"
    And the severity is at least "low"
    And the reasons contain "bait_tokens"

  Scenario Outline: Epic G (T2) — phonetic homophones of a brand score >= medium with brand_soundsquat
    When I inspect "<input>"
    Then the status is "ok"
    And the severity is at least "medium"
    And the reasons contain "brand_soundsquat"

    Examples:
      | input                  |
      | https://netflicks.com  |
      | https://dropboks.com   |

  Scenario Outline: Epic G (T3) — single-bit-flip neighbors of a brand carry brand_bitsquat (low weight)
    When I inspect "<input>"
    Then the status is "ok"
    And the severity is at least "low"
    And the reasons contain "brand_bitsquat"

    Examples:
      | input                |
      | https://netfliz.com  |
      | https://amazgn.com   |

  Scenario Outline: Epic E3 — single-script whole-label homographs score >= medium with homograph_skeleton_collision
    When I inspect "<input>"
    Then the status is "ok"
    And the severity is at least "medium"
    And the reasons contain "homograph_skeleton_collision"
    And the reasons do not contain "mixed_script"

    Examples:
      | input                  |
      | https://сһаѕе.com      |
      | https://ехреԁіа.com    |

  Scenario Outline: Epic G — must not over-flag legitimate brand domains (SC-2)
    When I inspect "<input>" allowing IDNs
    Then the status is "ok"
    And the score is 0
    And the severity is "info"
    And the reasons do not contain "<forbidden>"

    Examples:
      | input                              | forbidden                     |
      | https://paypal.com                 | brand_lookalike               |
      | https://google.com                 | brand_homoglyph               |
      | https://accounts.google.com        | brand_lookalike               |
      | https://login.microsoftonline.com  | bait_tokens                   |
      | https://amazonaws.com              | brand_lookalike               |
      | https://example.com/account/login  | bait_tokens                   |
      | https://netflix.com                | brand_soundsquat              |
      | https://ups.com                    | brand_soundsquat              |
      | https://amazon.com                 | brand_bitsquat                |
      | https://oetfliz.com                | brand_bitsquat                |
      | https://chase.com                  | homograph_skeleton_collision  |
      | https://пример.com                 | homograph_skeleton_collision  |
