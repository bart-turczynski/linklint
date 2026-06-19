Feature: Project scaffold

  Scenario: The scaffold is ready
    Given the project has been created
    When I run the development checks
    Then the TypeScript and feature test setup should be available

