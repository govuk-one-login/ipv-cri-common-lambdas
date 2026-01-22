Feature: Session API

  Scenario Outline: a session id is returned with '<LambdaImplementation>'
    Given authorization JAR for test user 681
    And the Session lambda is called
    When user sends a request to session API
    Then user gets a session id

  Scenario Outline: no session id when no request body with '<LambdaImplementation>'
    Given the Session lambda is called
    When user sends an empty request to session end point
    Then expect a status code of 400 in the response

  Scenario Outline: no session id when no client id in request body with '<LambdaImplementation>'
    Given authorization JAR for test user 681
    And the Session lambda is called
    And the request body has no client_id
    When user sends a request to session API
    Then expect a status code of 400 in the response

  Scenario Outline: no session id when no request in request body
    Given authorization JAR for test user 681
    And the Session lambda is called
    And the request body has no request
    When user sends a request to session API
    Then expect a status code of 400 in the response
