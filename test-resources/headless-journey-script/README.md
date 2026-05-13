# headless-journey-script

This tool presents a simple CLI for completing a headless CRI journey. To use it, `cd` into this directory and run:

```sh
# install correct node version (NB: requires node >=24 for running TS code natively)
nvm install

# install dependencies
npm install

# authenticate with AWS

# execute the script, passing relevant AWS auth if necessary
# (eg, for SSO you could prefix the command with AWS_PROFILE=your-sso-profile)
npm run journey -- [...]
```

## Usage

The full list of arguments can be found in [src/cli-args.ts](src/cli-args.ts).

Here's a handy command template:

```sh
npm run journey -- \
  --journeyIdentifier SOME_CRI_HAPPY \
  --criSubdomain review-z \
  --privateApiGatewayId abcdefghij \
  --publicApiGatewayId klmnopqrst
```

AWS authentication is used to retrieve information from AWS and invoke API Gateways with your credentials, using the
same functionality as the 'Test' tab in the AWS API Gateway dashboard. The gateways are invoked in this way to ensure
compatibility with different CRI environments - localdev stacks may be public, but stacks deployed using the pipeline
system are deliberately less accessible from the open Internet. The recommended method for doing this is to use
short-lived credentials from AWS SSO or `aws-vault` as these avoid the need to directly interact with or store secret
credentials.

At time of writing, the above are the only mandatory arguments. Note the `--` between `npm run journey` and the
arguments for the programme. Without this, your arguments would be passed to `npm`, not to the script.

Feel free to add further journey definitions if needed. Any `.sh` files are gitignored in this directory, so you may
find it useful to create your own shell scripts to invoke your team's CRIs as well.

## Implementation

The top-level logic is in [src/index.ts](src/index.ts). It contains the high-level definitions for each request to be
made when completing a CRI.

Additionally, [src/journey-config.ts](src/journey-config.ts) implements a mapping from a journey ID to a set of
definitions that allow the script to complete a particular CRI journey (eg, `CHECK_HMRC_HAPPY`). The necessary data will
be injected into the script depending on the selected journey ID. Adding a new CRI journey to the script should
theoretically only require changes in this file.

The remaining files in `src` are helpers which implement useful functions, such as those for JWT signing and invoking
API Gateway endpoints.
