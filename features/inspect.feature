Feature: Core inspect() contract (walking skeleton)

  The synchronous inspect() entry point returns the stable, versioned schema for
  every input and never throws.

  Scenario: A benign URL is ok with zero score (FR-SCORE-5)
    When I inspect "https://www.example.com/path"
    Then the status is "ok"
    And the score is 0
    And the severity is "info"
    And checksRun is "lexical"
    And checksSkipped is "resolution,reputation"
    And the schemaVersion is "1.12"
    And dataVersions is present

  Scenario: Unparseable input is invalid, not benign (SC-2a)
    When I inspect "ht!tp://%%%not a url"
    Then the status is "invalid"
    And parsed is null
    And score is null
    And severity is null
    And the reasons contain "parse_error"
    And checksRun is empty
    And checksSkipped is "lexical,resolution,reputation"
    And dataVersions is present

  Scenario Outline: inspect() never throws over arbitrary input
    When I inspect "<input>"
    Then the status is one of "ok,invalid"

    Examples:
      | input              |
      | example.com        |
      | javascript:alert(1)|
      |                    |
      | ://                |
      | @@@@@@             |

  # Agent mode (V4a): the agent-gated channel is OFF by default — the default
  # verdict is byte-identical to before the channel existed — and observable in
  # checksRun only when turned on.
  Scenario: An agent-injection URL is clean by default (gated channel off)
    When I inspect "https://example.com/agent?role=system&prompt=ignore"
    Then the status is "ok"
    And checksRun is "lexical"
    And checksSkipped is "resolution,reputation"
    And the reasons do not contain "prompt_injection_url"

  Scenario: Agent mode runs the gated detector and is observable in checksRun
    When I inspect "https://example.com/agent?role=system&prompt=ignore" in agent mode
    Then the status is "ok"
    And checksRun is "lexical,agent"
    And the reasons contain "prompt_injection_url"

  Scenario: A benign URL in agent mode shows the agent channel but no false reason
    When I inspect "https://www.example.com/path" in agent mode
    Then the status is "ok"
    And checksRun is "lexical,agent"
    And the reasons do not contain "prompt_injection_url"
