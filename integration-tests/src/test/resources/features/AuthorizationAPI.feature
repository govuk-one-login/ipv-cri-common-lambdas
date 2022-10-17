Feature: Authorization API

  Background: a session id is returned
    Given authorization JAR for test user 681
    When user sends a request to session API
    Then user gets a session id
    #This is a pre-requisite step before calling the authorization end point
    And user sends an address

  Scenario: a valid authorization code is returned
   When user sends a request to authorization end point
    Then expect a status code of 200 in the response
    And a valid authorization code is returned in the response

#  Scenario: no authorization code is returned when client id does not match
#    When user sends a request to authorization end point
#    And the request body has no client_id
#    Then expect a status code of 400 in the response








