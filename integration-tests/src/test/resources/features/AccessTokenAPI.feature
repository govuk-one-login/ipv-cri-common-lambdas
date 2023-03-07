Feature: Access Token API

  Scenario Outline: access token is returned with Session Lambda in '<SessionLambdaImplementation>' , Access Token Lambda in '<AccessTokenLambdaImplementation>' and Auth Lambda is in '<AuthLambdaImplementation>'
    Given authorization JAR for test user 681
    And Session lambda implementation is in '<SessionLambdaImplementation>'
    When user sends a request to session API
    Then user gets a session id
    When session has an authCode
    And Authorisation lambda implementation is in '<AuthLambdaImplementation>'
    When user sends a valid request to authorization end point
    Then expect a status code of 200 in the response
    And a valid authorization code is returned in the response
    And AccessToken lambda implementation is in '<AccessTokenLambdaImplementation>'
    When user sends a request to access token end point
    Then expect a status code of 200 in the response
    And a valid access token is returned in the response
    Examples:
      |SessionLambdaImplementation|AccessTokenLambdaImplementation|AuthLambdaImplementation|
      |Java                       |Java                           |Java                    |
      |Java                       |Java                           |TS                      |
      |Java                       |TS                             |Java                    |
      |Java                       |TS                             |TS                      |
      |TS                         |Java                           |Java                    |
      |TS                         |Java                           |TS                      |
      |TS                         |TS                             |Java                    |
      |TS                         |TS                             |TS                      |

  Scenario Outline: no access token is returned when request has invalid authorization code with Session Lambda in '<SessionLambdaImplementation>' , Access Token Lambda in '<AccessTokenLambdaImplementation>' and Auth Lambda is in '<AuthLambdaImplementation>'
    Given authorization JAR for test user 681
    And Session lambda implementation is in '<SessionLambdaImplementation>'
    When user sends a request to session API
    Then user gets a session id
    When session has an authCode
    And Authorisation lambda implementation is in '<AuthLambdaImplementation>'
    When user sends a valid request to authorization end point
    Then expect a status code of 200 in the response
    And a valid authorization code is returned in the response
    And AccessToken lambda implementation is in '<AccessTokenLambdaImplementation>'
    When user sends a request to access token end point with incorrect authorization code
    Then expect a status code of 403 in the response
    And a "Access token expired" error with code 1026 is sent in the response
    Examples:
      |SessionLambdaImplementation|AccessTokenLambdaImplementation|AuthLambdaImplementation|
      |Java                       |Java                           |Java                    |
      |Java                       |Java                           |TS                      |
      |Java                       |TS                             |Java                    |
      |Java                       |TS                             |TS                      |
      |TS                         |Java                           |Java                    |
      |TS                         |Java                           |TS                      |
      |TS                         |TS                             |Java                    |
      |TS                         |TS                             |TS                      |
