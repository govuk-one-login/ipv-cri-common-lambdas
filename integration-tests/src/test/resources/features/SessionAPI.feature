# Feature: Session API

#   Scenario: a session id is returned
#     Given authorization JAR for test user 681
#     When user sends a request to session API
#     Then user gets a session id

#   Scenario: no session id when no request body
#     Given user sends an empty request to session end point
#     Then expect a status code of 400 in the response

#   Scenario: no session id when no client id in request body
#     Given authorization JAR for test user 681
#     And the request body has no client_id
#     When user sends a request to session API
#     Then expect a status code of 400 in the response

#   Scenario: no session id when no request in request body
#     Given authorization JAR for test user 681
#     And the request body has no request
#     When user sends a request to session API
#     Then expect a status code of 400 in the response
