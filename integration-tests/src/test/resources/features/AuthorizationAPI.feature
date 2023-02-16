Feature: Authorization API

  Scenario Outline: a valid authorization code is returned
    Given authorization JAR for test user 681
    And AccessToken lambda implementation is in '<SessionLambdaImplementation>'
    When user sends a request to session API
    Then user gets a session id
    And Authorisation lambda implementation is in '<AuthLambdaImplementation>'
    When user sends a valid request to authorization end point
    Then expect a status code of 200 in the response
    And a valid authorization code is returned in the response
    Examples:
      |SessionLambdaImplementation|AuthLambdaImplementation|
      |Java                       |Java                    |
      |TS                         |TS                      |

  Scenario Outline: no authorization code is returned when client id does not match
    Given authorization JAR for test user 681
    And AccessToken lambda implementation is in '<SessionLambdaImplementation>'
    When user sends a request to session API
    Then user gets a session id
    And Authorisation lambda implementation is in '<AuthLambdaImplementation>'
    When user sends a request to authorization end point with invalid client id
    Then expect a status code of 400 in the response
    And a "Session Validation Exception" error with code 1019 is sent in the response
    Examples:
      |SessionLambdaImplementation|AuthLambdaImplementation|
      |Java                       |Java                    |
      |TS                         |TS                      |

  Scenario Outline: no authorization code is returned when redirect uri does not match
    Given authorization JAR for test user 681
    And AccessToken lambda implementation is in '<SessionLambdaImplementation>'
    When user sends a request to session API
    Then user gets a session id
    And Authorisation lambda implementation is in '<AuthLambdaImplementation>'
    When user sends a request to authorization end point with invalid redirect uri
    Then expect a status code of 400 in the response
    And a "Session Validation Exception" error with code 1019 is sent in the response
    Examples:
      |SessionLambdaImplementation|AuthLambdaImplementation|
      |Java                       |Java                    |
      |TS                         |TS                      |