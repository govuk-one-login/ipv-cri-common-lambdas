Feature: Access Token API

  Background: a session id is returned
    Given authorization JAR for test user 681
    When user sends a request to session API
    Then user gets a session id
    When user sends a valid request to authorization end point
    Then expect a status code of 200 in the response
    And a valid authorization code is returned in the response

  Scenario: access token is returned
    When user sends a request to access token end point
    Then expect a status code of 200 in the response
    And a valid access token is returned in the response

  Scenario Outline: no access token is returned when request parameters are missing
    When user sends a request to access token end point with missing "<parameter>"
    Then expect a status code of 400 in the response
    And a "Token validation error" error with code 1023 is sent in the response
    Examples:
      | parameter             |
      | code                  |
      | client_assertion_type |
      | redirect_uri          |
      | client_assertion      |
      | grant_type            |

  Scenario: no access token is returned when request has invalid grant_type
    When user sends a request to access token end point with incorrect grant type
    Then expect a status code of 400 in the response
    And a "Token validation error" error with code 1023 is sent in the response

  Scenario: no access token is returned when request has invalid authorization code
    When user sends a request to access token end point with incorrect authorization code
    Then expect a status code of 403 in the response
    And a "Access token expired" error with code 1026 is sent in the response