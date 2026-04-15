# Strobilus

## Structure
```
\crates
 |- strobilus (API)
 |- strobilus-core (Stroblius implementation)
```

## API note
Unlike Cedar, Strobilus' Authorizer incorporates an interpreter for the commands.
So, in order to mantain "compatibility" with the Cedar API usage, the function `is_authorized` will evaluate a policy and execute an obbligation.

## License
This project is licensed under the Apache-2.0 License.
