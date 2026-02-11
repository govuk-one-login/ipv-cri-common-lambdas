Feature: Authorization API

  Scenario: a valid authorization code is returned with Session Lambda and Auth Lambda
    Given authorization JAR for test user 681
    And the Session lambda is called
    When user sends a request to session API
    Then user gets a session id
    When session has an authCode
    And the Authorisation lambda is called
    When user sends a valid request to authorization end point
    Then expect a status code of 200 in the response
    And a valid authorization code is returned in the response

  Scenario: no authorization code is returned when client id does not match with Session Lambda and Auth Lambda
    Given authorization JAR for test user 681
    And the Session lambda is called
    When user sends a request to session API
    Then user gets a session id
    When session has an authCode
    And the Authorisation lambda is called
    When user sends a request to authorization end point with invalid client id
    Then expect a status code of 400 in the response
    And a "Session Validation Exception" error with code 1019 is sent in the response

  Scenario: no authorization code is returned when redirect uri does not match with with Session Lambda in '<SessionLambdaImplementation>' and Auth Lambda is in '<AuthLambdaImplementation>'
    Given authorization JAR for test user 681
    And the Session lambda is called
    When user sends a request to session API
    Then user gets a session id
    When session has an authCode
    And the Authorisation lambda is called
    When user sends a request to authorization end point with invalid redirect uri
    Then expect a status code of 400 in the response
    And a "Session Validation Exception" error with code 1019 is sent in the response

  @access_denied
  Scenario: access-denied is returned on /authorization endpoint
    Given authorization JAR for test user 681
    And the Session lambda is called
    When user sends a request to session API
    Then user gets a session id
    And the Authorisation lambda is called
    When user sends a request to authorization end point with access_denied
    Then expect a status code of 403 in the response
    And a "Authorization permission denied" error with code "access_denied" is sent in the response