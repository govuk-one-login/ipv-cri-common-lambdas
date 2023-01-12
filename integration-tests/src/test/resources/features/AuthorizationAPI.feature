# Feature: Authorization API

#   Background: a session id is returned
#     Given authorization JAR for test user 681
#     When user sends a request to session API
#     Then user gets a session id

#   Scenario: a valid authorization code is returned
#    When user sends a valid request to authorization end point
#     Then expect a status code of 200 in the response
#     And a valid authorization code is returned in the response

#   Scenario: no authorization code is returned when client id does not match
#     When user sends a request to authorization end point with invalid client id
#     Then expect a status code of 400 in the response
#     And a "Session Validation Exception" error with code 1019 is sent in the response

#   Scenario: no authorization code is returned when redirect uri does not match
#     When user sends a request to authorization end point with invalid redirect uri
#     Then expect a status code of 400 in the response
#     And a "Session Validation Exception" error with code 1019 is sent in the response
