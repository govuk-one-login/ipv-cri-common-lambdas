Feature: Session API

  Scenario Outline: a session id is returned with '<LambdaImplementation>'
    Given authorization JAR for test user 681
    And Session lambda implementation is in '<LambdaImplementation>'
    When user sends a request to session API
    Then user gets a session id
    Examples:
      |LambdaImplementation|
      |Java|
      |TS|

  Scenario Outline: no session id when no request body
    Given user sends an empty request to session end point
    And Session lambda implementation is in '<LambdaImplementation>'
    Then expect a status code of 400 in the response
    Examples:
      |LambdaImplementation|
      |Java|
      |TS|

  Scenario Outline: no session id when no client id in request body
    Given authorization JAR for test user 681
    And Session lambda implementation is in '<LambdaImplementation>'
    And the request body has no client_id
    When user sends a request to session API
    Then expect a status code of 400 in the response
    Examples:
      |LambdaImplementation|
      |Java|
      |TS|

  Scenario Outline: no session id when no request in request body
    Given authorization JAR for test user 681
    And Session lambda implementation is in '<LambdaImplementation>'
    And the request body has no request
    When user sends a request to session API
    Then expect a status code of 400 in the response
    Examples:
      |LambdaImplementation|
      |Java|
      |TS|
