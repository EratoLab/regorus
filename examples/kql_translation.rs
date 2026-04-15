// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Example demonstrating KQL translation from database-friendly Rego subset
//!
//! This example shows how to parse database-subset Rego policies and translate
//! them to KQL (Kusto Query Language) for execution in Azure Data Explorer,
//! Azure Monitor, and other Kusto-based services.

use anyhow::Result;
use regorus::{
    unstable::{DatabaseParser, KqlTranslator},
    Source,
};

fn main() -> Result<()> {
    println!("=== Database Rego to KQL Translation Examples ===\n");

    // Example 1: Simple boolean rule
    let simple_rule = r#"
        package authz

        # Check if user is an active admin
        allow {
            user.role == "admin"
            user.active == true
            user.department == "security"
        }
    "#;

    println!("1. Simple Boolean Rule:");
    println!("Rego:");
    println!("{}", simple_rule);
    translate_and_display(simple_rule, "SecurityUsers")?;

    // Example 2: Value assignment rule
    let assignment_rule = r#"
        package authz

        # Calculate user access level
        access_level = "premium" {
            user.subscription_tier == "gold"
            user.payment_status == "current"
            user.account_age_days >= 30
        }

        access_level = "standard" {
            user.subscription_tier == "silver"
            user.payment_status == "current"
        }
    "#;

    println!("\n2. Value Assignment Rules:");
    println!("Rego:");
    println!("{}", assignment_rule);
    translate_and_display(assignment_rule, "Users")?;

    // Example 3: Arithmetic operations
    let arithmetic_rule = r#"
        package pricing

        # Calculate discounted price for premium users
        discounted_price = product.price * 0.8 {
            user.membership == "premium"
            product.category != "restricted"
        }

        # Calculate tax amount
        tax_amount = order.subtotal * tax_rate {
            order.country == "US"
            order.subtotal > 100
        }
    "#;

    println!("\n3. Arithmetic Operations:");
    println!("Rego:");
    println!("{}", arithmetic_rule);
    translate_and_display(arithmetic_rule, "Orders")?;

    // Example 4: Set membership and comparisons
    let membership_rule = r#"
        package access_control

        import future.keywords.in

        # Check if user has valid role
        has_valid_role {
            user.role in {"admin", "manager", "developer"}
            user.status == "active"
        }

        # Check resource access
        can_access_resource {
            resource.visibility == "public"
        }

        can_access_resource {
            resource.visibility == "private"
            user.id == resource.owner_id
        }
    "#;

    println!("\n4. Set Membership and Multiple Rules:");
    println!("Rego:");
    println!("{}", membership_rule);
    translate_and_display(membership_rule, "AccessRequests")?;

    // Example 5: Complex data access patterns
    let data_access_rule = r#"
        package data_access

        # Check if user can access sensitive data
        can_access_sensitive_data {
            user.clearance_level >= 3
            user.department == "security"
            user.background_check_status == "cleared"
            user.last_login_days <= 7
        }

        # Calculate risk score
        risk_score = (user.failed_login_attempts * 10) + (user.days_since_password_change / 30) {
            user.account_status == "active"
        }
    "#;

    println!("\n5. Complex Data Access Patterns:");
    println!("Rego:");
    println!("{}", data_access_rule);
    translate_and_display(data_access_rule, "UserSessions")?;

    // Example 6: User query translation
    let user_query = r#"
        user.role == "admin"; user.active == true; user.last_login_days <= 7
    "#;

    println!("\n6. User Query Translation:");
    println!("Rego Query:");
    println!("{}", user_query);
    translate_query_and_display(user_query, "Users")?;

    println!("\n=== Summary ===");
    println!("The KQL translator successfully converts:");
    println!("• Boolean conditions to KQL where clauses");
    println!("• Arithmetic operations to KQL expressions");
    println!("• Set membership to KQL 'in' operations");
    println!("• Variable assignments to KQL extend operations");
    println!("• Multiple rule alternatives to separate queries");
    println!("• Data field access to KQL column references");

    Ok(())
}

fn translate_and_display(rego_code: &str, table_name: &str) -> Result<()> {
    // Parse with database subset parser
    let source = Source::from_contents("policy.rego".to_string(), rego_code.to_string())?;
    let mut parser = DatabaseParser::new(&source)?;

    match parser.parse_database_module() {
        Ok(module) => {
            // Translate to KQL
            let mut translator = KqlTranslator::new(table_name.to_string());
            match translator.translate_module(&module) {
                Ok(queries) => {
                    println!("Generated KQL Queries:");
                    for (i, query) in queries.iter().enumerate() {
                        println!("Query {}:", i + 1);
                        println!("{}", query);
                        println!();
                    }
                }
                Err(e) => {
                    println!("❌ Translation error: {}", e);
                }
            }
        }
        Err(e) => {
            println!("❌ Parse error: {}", e);
        }
    }

    Ok(())
}

fn translate_query_and_display(query_code: &str, table_name: &str) -> Result<()> {
    // Parse user query
    let source = Source::from_contents("query.rego".to_string(), query_code.to_string())?;
    let mut parser = DatabaseParser::new(&source)?;

    match parser.parse_database_query() {
        Ok(query) => {
            // Translate to KQL
            let mut translator = KqlTranslator::new(table_name.to_string());
            match translator.translate_user_query(&query) {
                Ok(kql_query) => {
                    println!("Generated KQL Query:");
                    println!("{}", kql_query);
                    println!();
                }
                Err(e) => {
                    println!("❌ Translation error: {}", e);
                }
            }
        }
        Err(e) => {
            println!("❌ Parse error: {}", e);
        }
    }

    Ok(())
}
