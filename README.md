# Strobilus

## Structure
```
\crates
 |- strobilus (API)
 |- strobilus-core (stroblius implementation)
 |- strobilus-cli (CLI for use strobilus)
```

## API note
Unlike Cedar, Strobilus' Authorizer incorporates an interpreter for the commands.
So, in order to mantain "compatibility" with the Cedar API usage, the function `is_authorized` will evaluate a policy and execute an obbligation.