Feature: Session endpoint happy path test

  @session_endpoint_pre_merge_happy
  Scenario: Testing session endpoint
    Given user has the user identity in the form of a signed JWT string
    When user sends a request to session end point
    Then user gets a session-id
