# NodeJS Lambdas

## Project structure

The NodeJS lambdas are stores inside the Lambdas directory. Each individual `handlers` file is one Lambda. For the Cloudformation config, the ESBuild will point to the handler file and build from that.

## AccessToken Lambda

This endpoint takes grant_type, code, client_assertion_type, client_assertion and redirect_uri with content type application/x-www-form-urlencoded and returns Access Token

## How to run tests

To run all tests, run `npm run test`. This will compile and run all tests in the `/tests` directory.

### How to run an individual test file

To run an individual test file, you must pass the file name to the test command. For example `npm run test -- -t app.test.ts`. This will only execute the test file in question.

### How to run an individual test

To run an individual test, you must pass the file name to test command but also modify the test with the `only` attribute.

For example:

```Javascript
it.only("will only run this test in this file",() => );
```

Note that if you dont specify Jest to run just the file with the test, then it will also run the other files in parallel.
