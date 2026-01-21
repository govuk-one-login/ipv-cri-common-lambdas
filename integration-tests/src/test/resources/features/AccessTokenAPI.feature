Feature: Access Token API

  Scenario Outline: access token is returned with Session Lambda in '<SessionLambdaImplementation>' , Access Token Lambda in '<AccessTokenLambdaImplementation>' and Auth Lambda is in '<AuthLambdaImplementation>'
    Given authorization JAR for test user 681
    And the Session lambda is called
    When user sends a request to session API
    Then user gets a session id
    When session has an authCode
    And the Authorisation lambda is called
    When user sends a valid request to authorization end point
    Then expect a status code of 200 in the response
    And a valid authorization code is returned in the response
    And the AccessToken lambda is called
    When user sends a request to access token end point
    Then expect a status code of 200 in the response
    And a valid access token is returned in the response

  Scenario Outline: no access token is returned when request has invalid authorization code with Session Lambda in '<SessionLambdaImplementation>' , Access Token Lambda in '<AccessTokenLambdaImplementation>' and Auth Lambda is in '<AuthLambdaImplementation>'
    Given authorization JAR for test user 681
    And the Session lambda is called
    When user sends a request to session API
    Then user gets a session id
    When session has an authCode
    And the Authorisation lambda is called
    When user sends a valid request to authorization end point
    Then expect a status code of 200 in the response
    And a valid authorization code is returned in the response
    And the AccessToken lambda is called
    When user sends a request to access token end point with incorrect authorization code
    Then expect a status code of 403 in the response
    And a "Access token expired" error with code 1026 is sent in the response
