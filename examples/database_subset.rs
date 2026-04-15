// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Example demonstrating the database-friendly Rego subset parser
//!
//! This example shows how to parse Rego policies that are designed for
//! database translation and reject policies that use unsupported features.

use anyhow::Result;
use regorus::{unstable::DatabaseParser, Source};

fn main() -> Result<()> {
    // Example 1: Valid database-friendly policy
    let valid_policy = r#"
        package authz

        import future.keywords.in

        import data.users
        import data.roles

        # Simple boolean rule
        allow {
            user.role == "admin"
            user.active == true
        }

        # Rule with assignment
        user_level = "premium" {
            user.subscription_tier == "gold"
            user.payment_status == "current"
        }

        # Array comprehension with simple filter
        active_users = [u.name | u = data.users[_]; u.active == true]

        # Set comprehension
        admin_roles = {r | r = data.roles[_]; r.type == "admin"}

        # Set membership
        valid_roles = {"admin", "user", "guest"}
        is_valid_role {
            user.role in valid_roles
        }

        # Arithmetic operations
        discounted_price = product.price * 0.9 {
            user.membership == "premium"
        }
    "#;

    println!("=== Parsing valid database-friendly policy ===");
    let source = Source::from_contents("valid.rego".to_string(), valid_policy.to_string())?;
    let mut parser = DatabaseParser::new(&source)?;

    match parser.parse_database_module() {
        Ok(module) => {
            println!("✅ Successfully parsed database-friendly policy");
            println!("Package: {}", module.package.refr.span().text());
            println!("Number of rules: {}", module.policy.len());
        }
        Err(e) => {
            println!("❌ Unexpected error: {}", e);
        }
    }

    // Example 2: Invalid policy with function calls
    let invalid_policy_functions = r#"
        package test

        result = custom_function(input.value) {
            input.enabled == true
        }
    "#;

    println!("\n=== Parsing policy with function calls (should fail) ===");
    let source = Source::from_contents(
        "invalid_functions.rego".to_string(),
        invalid_policy_functions.to_string(),
    )?;
    let mut parser = DatabaseParser::new(&source)?;

    match parser.parse_database_module() {
        Ok(_) => {
            println!("❌ Unexpected success - should have rejected function calls");
        }
        Err(e) => {
            println!("✅ Correctly rejected policy with function calls");
            println!("Error: {}", e);
        }
    }

    // Example 3: Invalid policy with every statement
    let invalid_policy_every = r#"
        package test

        import future.keywords.every
        import future.keywords.in

        all_valid {
            every user in data.users {
                user.active == true
            }
        }
    "#;

    println!("\n=== Parsing policy with 'every' statement (should fail) ===");
    let source = Source::from_contents(
        "invalid_every.rego".to_string(),
        invalid_policy_every.to_string(),
    )?;
    let mut parser = DatabaseParser::new(&source)?;

    match parser.parse_database_module() {
        Ok(_) => {
            println!("❌ Unexpected success - should have rejected 'every' statements");
        }
        Err(e) => {
            println!("✅ Correctly rejected policy with 'every' statement");
            println!("Error: {}", e);
        }
    }

    // Example 4: Invalid policy with object comprehension
    let invalid_policy_object_compr = r#"
        package test

        user_map = {u.id: u.name | u = data.users[_]}
    "#;

    println!("\n=== Parsing policy with object comprehension (should fail) ===");
    let source = Source::from_contents(
        "invalid_object_compr.rego".to_string(),
        invalid_policy_object_compr.to_string(),
    )?;
    let mut parser = DatabaseParser::new(&source)?;

    match parser.parse_database_module() {
        Ok(_) => {
            println!("❌ Unexpected success - should have rejected object comprehensions");
        }
        Err(e) => {
            println!("✅ Correctly rejected policy with object comprehension");
            println!("Error: {}", e);
        }
    }

    // Example 5: Valid database query
    let valid_query = r#"user.role == "admin""#;

    println!("\n=== Parsing valid database query ===");
    let source = Source::from_contents("query.rego".to_string(), valid_query.to_string())?;
    let mut parser = DatabaseParser::new(&source)?;

    match parser.parse_database_query() {
        Ok(query) => {
            println!("✅ Successfully parsed database query");
            println!("Number of statements: {}", query.stmts.len());
        }
        Err(e) => {
            println!("❌ Unexpected error: {}", e);
        }
    }

    println!("\n=== Summary ===");
    println!("The database subset parser successfully:");
    println!("• Accepts simple boolean rules and expressions");
    println!("• Accepts array/set comprehensions with simple patterns");
    println!("• Accepts arithmetic and comparison operations");
    println!("• Accepts set membership operations");
    println!("• Rejects function calls");
    println!("• Rejects 'every' statements");
    println!("• Rejects object comprehensions");
    println!("• Validates data access patterns");

    Ok(())
}
