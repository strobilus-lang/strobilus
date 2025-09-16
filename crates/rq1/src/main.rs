use std::collections::{HashMap, HashSet};
use std::hash::RandomState;
use std::path::Path;
use std::str::FromStr;
use std::{fs, iter};
use std::{
    fs::File,
    io::{self, Write},
};

use cedar_policy::{Entities, EntityUid};
use cpu_time::ProcessTime;
use strobilus::authorization::Authorizer;
use strobilus::{read_entities, read_obligations, read_policies};

fn load_policies_from_file(path: &str) -> cedar_policy::PolicySet {
    match fs::read_to_string(path) {
        Ok(content) => cedar_policy::PolicySet::from_str(&content)
            .expect("Failed to parse Cedar policies from file"),
        Err(_) => cedar_policy::PolicySet::new(),
    }
}

fn load_entities_from_file(path: &str) -> cedar_policy::Entities {
    match fs::read_to_string(path) {
        Ok(content) => cedar_policy::Entities::from_json_str(&content, None)
            .expect("Failed to parse entities from file"),
        Err(_) => cedar_policy::Entities::empty(),
    }
}

fn save_matrix_as_csv_manual(matrix: &Vec<Vec<u128>>, path: &str) -> io::Result<()> {
    let path_obj = Path::new(path);

    // Create parent directories if they don't exist
    if let Some(parent) = path_obj.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = File::create(path_obj)?;

    for row in matrix {
        let line = row
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",");
        writeln!(file, "{}", line)?;
    }

    Ok(())
}

fn strobilus(iterations: i32, requests: usize) {
    let mut matrix: Vec<Vec<u128>> = vec![vec![0; requests]; 0];

    let policies = read_policies("policy.cedar").expect("Can't find policies");
    let entities = read_entities("entities.json").expect("Can't find entities");
    let obligations = read_obligations("rules.strobilus").expect("Can't find obligations");

    let request = Authorizer::request(
        r#"User::"Alice""#,
        r#"Action::"get""#,
        r#"Resource::"thesis.tex""#,
    )
    .expect("Can't create request correctly");

    for _i in 0..iterations {
        // Cloning state
        let mut authorizer =
            Authorizer::new(policies.clone(), obligations.clone(), entities.clone());

        let mut records = Vec::with_capacity(requests);
        for _j in 0..requests {
            // Starting mesuring
            let start = ProcessTime::now();

            let _ = authorizer.is_authorized(&request);

            // End measure
            records.push(start.elapsed().as_nanos());
        }
        matrix.push(records);
    }

    let _ = save_matrix_as_csv_manual(&matrix, "./results/strobilus.csv");
    println!("Iterations: {}, Requests: {}", matrix.len(), matrix[0].len());
}


fn cedar_local_state(iterations: i32, requests: usize) {
    let mut matrix: Vec<Vec<u128>> = vec![vec![0; requests]; 0];

    let policies = load_policies_from_file("policy.cedar");
    let mut data: HashMap<String, i16> = HashMap::new();

    data.insert("Alice".to_owned(), 10);
    data.insert("Bob".to_owned(), 0);

    let action = r#"Action::"get""#.parse().unwrap();
    let principal: cedar_policy::EntityUid = r#"User::"Alice""#.parse().unwrap();
    let resource = r#"Resource::"thesis.tex""#.parse().unwrap();
    let request = cedar_policy::Request::new(
        principal.clone(),
        action,
        resource,
        cedar_policy::Context::empty(),
        None,
    )
    .unwrap();

    let authorizer = cedar_policy::Authorizer::new();

    for _i in 0..iterations {
        let mut records = Vec::with_capacity(requests);

        for _j in 0..requests {
            // Starting measuring
            let start = ProcessTime::now();

            let mut entities_list: Vec<cedar_policy::Entity> = Vec::new();

            for (key, value) in &data {
                let entity = cedar_policy::Entity::new(
                    cedar_policy::EntityUid::from_str(&format!("User::\"{}\"", key))
                        .expect("error in parsing"),
                    {
                        let mut attr = HashMap::new();
                        attr.insert(
                            "counter".to_owned(),
                            cedar_policy::RestrictedExpression::new_long(*value as i64),
                        );
                        attr
                    },
                    HashSet::new(),
                )
                .expect("Error in creating entity");

                entities_list.push(entity);
            }

            let entities = cedar_policy::Entities::from_entities(entities_list.into_iter(), None)
                .expect("Error in converting list of entities to entity store");

            let response = authorizer.is_authorized(&request, &policies, &entities);

            if response.decision() == cedar_policy::Decision::Allow {
                data.entry(principal.id().unescaped().to_owned())
                    .and_modify(|value| {
                        *value = *value - 1;
                    });
            }

            // End measure
            records.push(start.elapsed().as_nanos());
        }
        matrix.push(records);
    }

    let _ = save_matrix_as_csv_manual(&matrix, "./results/cedar-local-state.csv");

    println!("Iterations: {}, Requests: {}", matrix.len(), matrix[0].len());
}

fn cedar_upsert(iterations: i32, requests: usize) {
    let mut matrix: Vec<Vec<u128>> = vec![vec![0; requests]; 0];

    let policies = load_policies_from_file("policy.cedar");
    let entities = load_entities_from_file("entities.json");
    let counter: HashMap<cedar_policy::EntityUid, HashMap<String, i16>, RandomState> =
        HashMap::from_iter(entities.iter().map(|entity| {
            (entity.uid(), {
                let mut attrs = HashMap::new();
                let key = "counter";
                match entity
                    .attr("counter")
                    .expect("Failed to get counter attribute")
                {
                    Ok(cedar_policy::EvalResult::Long(value)) => {
                        attrs.insert(key.to_string(), value as i16)
                    }
                    _ => attrs.insert(key.to_string(), 5),
                };
                attrs
            })
        }));

    let action = r#"Action::"get""#.parse().unwrap();
    let principal: cedar_policy::EntityUid = r#"User::"Alice""#.parse().unwrap();
    let resource = r#"Resource::"thesis.tex""#.parse().unwrap();
    let request = cedar_policy::Request::new(
        principal.clone(),
        action,
        resource,
        cedar_policy::Context::empty(),
        None,
    )
    .unwrap();

    let authorizer = cedar_policy::Authorizer::new();

    for _i in 0..iterations {
        // Cloning state
        let mut _entities = entities.clone();
        let mut _counter = counter.clone();

        let mut records = Vec::with_capacity(requests);
        for _j in 0..requests {
            // Starting mesuring
            let start = ProcessTime::now();

            let response = authorizer.is_authorized(&request, &policies, &_entities);

            if response.decision() == cedar_policy::Decision::Allow {
                _counter.entry(principal.clone()).and_modify(|entity| {
                    if let Some(val) = entity.get_mut("counter") {
                        *val -= 1;
                    }
                });

                
                let entity = _entities.get(&principal).expect("Entity not found");
                let uid = entity.uid();
                let attributes = _counter[&uid].clone();
                let parents = _entities
                    .ancestors(&uid)
                    .expect("Failed to get ancestors")
                    .cloned();
                
                let new_entity = cedar_policy::Entity::new(
                    uid,
                    attributes
                        .iter()
                        .map(|(k, v)| {
                            (
                                k.clone(),
                                cedar_policy::RestrictedExpression::new_long(*v as i64),
                            )
                        })
                        .collect(),
                    parents.collect(),
                )
                .unwrap();
                
                _entities = _entities
                    .clone()
                    .upsert_entities(iter::once(new_entity), None)
                    .expect("Error in upsert entities"); 
            }

            // End measure
            records.push(start.elapsed().as_nanos());
        }
        matrix.push(records);
    }

    let _ = save_matrix_as_csv_manual(&matrix, "./results/cedar-upsert.csv");

    println!("Iterations: {}, Requests: {}", matrix.len(), matrix[0].len());
}

pub fn main() {
    let iterations = 1000;
    strobilus(iterations, 20);
    cedar_local_state(iterations, 20);
    cedar_upsert(iterations, 20);
}
