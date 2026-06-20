Feature: linklint CLI (end-to-end against the built binary)

  Drives the built dist/cli.js as a child process and asserts the exit code and
  streamed verdicts a real user would see.

  Scenario: check a benign URL exits 0
    When I run the CLI with "check https://www.example.com/path --no-color"
    Then the CLI exit code is 0
    And the CLI output contains "INFO"

  Scenario: check a high-risk URL exits 1
    When I run the CLI with "check https://www.gооgle.com@bad.tk/login --no-color"
    Then the CLI exit code is 1
    And the CLI output contains "HIGH"

  Scenario: a medium URL fails when the threshold is lowered
    When I run the CLI with "check https://paypal.com@evil.example.com/login --fail-on medium --no-color"
    Then the CLI exit code is 1
    And the CLI output contains "MEDIUM"

  Scenario: an invalid URL exits 1
    When I run the CLI with "check ht!tp://%%%notaurl --no-color"
    Then the CLI exit code is 1
    And the CLI output contains "INVALID"

  Scenario: an invalid URL with --allow-invalid exits 0
    When I run the CLI with "check ht!tp://%%%notaurl --allow-invalid --no-color"
    Then the CLI exit code is 0
    And the CLI output contains "INVALID"

  Scenario: batch over a file streams multiple verdicts and exits per worst outcome
    When I run the CLI over the batch fixture
    Then the CLI exit code is 1
    And the CLI output contains "INFO"
    And the CLI output contains "MEDIUM"
    And the CLI output contains "HIGH"

  Scenario: stdin piping yields multiple verdicts
    When I pipe URLs to the CLI and run "check --quiet --no-color"
    Then the CLI exit code is 1
    And the CLI output contains "INFO"
    And the CLI output contains "HIGH"

  Scenario: an unknown flag is a usage error and exits 2
    When I run the CLI with "check --bogus https://www.example.com"
    Then the CLI exit code is 2
    And the CLI error output contains "Usage:"
