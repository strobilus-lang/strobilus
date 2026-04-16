# Strobilus
This crate is the one intended to be used by user.

## Usage
```rust
let policies = PolicySet::from_str(&std::fs::read_to_string("./policy.cedar")?)?;
let entities = Entities::from_json_str(&std::fs::read_to_string("./entities.json")?, None)?;
let obligations = parse_obligations_file("./rules.strobilus")?;

// The stateful auhtorizer is represented by the StrobilusAuthorizer structure
let mut authorizer = StrobilusAuthorizer::new(policies, obligations, entities);

// Print the store before the authorization
println!(
    "--- Entity store BEFORE: {:?}",
    authorizer.to_json_value()
);

// Create the request for the authorizer
let request = Request::new(
    r#"User::"Max""#.parse()?,
    r#"Action::"read""#.parse()?,
    r#"Document::"file.docx""#.parse()?,
    Context::empty(),
    None
)?;

// Here there is the evaluation of the request
let decision = authorizer.is_authorized(request);

// Print the store before the authorization
println!(
    "--- Entity store AFTER: {:?}",
    authorizer.to_json_value()
);
```

## Examples
In the `./examples` directory, there are two examples you can run:
- `counter`, where after each request, a user's counter is decremented by one;
- `microservices`, in which two microservices (A and B, respectively) can communicate with each other until B communicates with C.

## License
This project is licensed under the Apache-2.0 License.
