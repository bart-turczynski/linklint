Feature: Success criteria — core lexical walking skeleton

  The corpus is the canonical acceptance matrix for SC-1 / SC-1a / SC-2 /
  SC-2a and detector-family coverage. These scenarios keep the Cucumber
  user-facing contract wired without duplicating the corpus rows.

  Scenario: SC-1 — a canonical attack scores with the right reason code
    When I inspect "https://pаypal.com"
    Then the status is "ok"
    And the severity is at least "medium"
    And the reasons contain "mixed_script"

  Scenario: SC-1a — informational-only cases annotate and stay benign
    When I inspect "https://xn--bcher-kva.de/" allowing IDNs
    Then the status is "ok"
    And the score is 0
    And the severity is "info"
    And the reasons contain "normalization_delta"
    And the reason "normalization_delta" has weight 0

  Scenario: SC-2 — legitimate links are not over-flagged
    When I inspect "https://www.example.com/path?q=1#x"
    Then the status is "ok"
    And the score is 0
    And the severity is "info"

  Scenario: SC-2a — unparseable input is invalid, not benign
    When I inspect "ht!tp://%%%not a url"
    Then the status is "invalid"
    And score is null
    And severity is null
    And the reasons contain "parse_error"
