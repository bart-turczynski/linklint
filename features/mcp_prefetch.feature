Feature: Agent pre-fetch check over MCP (SC-3)

  An LLM agent calls the linklint MCP check_url tool on an untrusted URL and acts
  on the structured verdict BEFORE fetching it.

  Scenario: A deceptive URL is refused before fetching
    When the agent checks the URL "https://paypal.com@xn--pypal-4ve.ru/login" over MCP
    Then the MCP verdict severity is "high"
    And the MCP verdict has reasons
    And the agent decides not to fetch

  Scenario: A dangerous scheme is refused before fetching
    When the agent checks the URL "javascript:alert(1)" over MCP
    Then the MCP verdict severity is "critical"
    And the agent decides not to fetch

  Scenario: A benign URL is allowed
    When the agent checks the URL "https://www.example.com/" over MCP
    Then the MCP verdict severity is "info"
    And the agent decides to fetch

  Scenario: An unparseable URL is treated as not-checked (not safe)
    When the agent checks the URL "ht!tp://%%%not a url" over MCP
    Then the MCP verdict status is "invalid"
    And the agent decides not to fetch
