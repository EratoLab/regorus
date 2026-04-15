// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Complete Rego to KQL IR to KQL Pipeline Example
//!
//! This example demonstrates the complete translation pipeline:
//! 1. Parse Rego policy with database subset parser
//! 2. Translate to KQL IR
//! 3. Optimize KQL IR  
//! 4. Generate final KQL
//! 5. Binary serialization/deserialization of IR

use anyhow::Result;
use regorus::{unstable::*, Source};

fn main() -> Result<()> {
    println!("=== Complete Rego to KQL Translation Pipeline ===\n");

    // Example 1: Simple filter rule
    demonstrate_simple_filter()?;

    // Example 2: Membership rule
    demonstrate_membership_rule()?;

    // Example 3: Arithmetic operations
    demonstrate_arithmetic_rule()?;

    // Example 4: Array comprehension
    demonstrate_comprehension()?;

    // Example 5: Binary serialization
    demonstrate_binary_serialization()?;

    println!("\n=== Pipeline Summary ===");
    println!("✅ Successfully demonstrated complete Rego to KQL pipeline");
    println!("• Rego parsing with database subset validation");
    println!("• Translation to KQL IR");
    println!("• Query optimization");
    println!("• KQL code generation");
    println!("• Binary serialization/deserialization");

    Ok(())
}

fn demonstrate_simple_filter() -> Result<()> {
    println!("=== Example 1: Simple Filter Rule ===");

    let rego_policy = r#"
        package authz
        import future.keywords.in
        
        allow {
            user.role == "admin"
            user.active == true
            user.department == "security"
        }
    "#;

    // Step 1: Parse Rego
    let source = Source::from_contents("policy.rego".to_string(), rego_policy.to_string())?;
    let mut parser = DatabaseParser::new(&source)?;
    let module = parser.parse_database_module()?;

    println!("✅ Parsed Rego policy");
    println!("   Rules: {}", module.policy.len());

    // Step 2: Translate to KQL IR
    let rule = &module.policy[0];
    let mut translator = RegoToKqlIrTranslator::new(None).with_default_table("users".to_string());
    let kql_ir = translator.translate_rule(rule)?;

    println!("✅ Translated to KQL IR");
    println!("   Source table: {}", kql_ir.source);
    println!("   Pipeline operations: {}", kql_ir.pipeline.len());

    // Step 3: Optimize IR
    let optimizer = KqlOptimizer::new();
    let optimized_ir = optimizer.optimize(&kql_ir);

    println!("✅ Optimized KQL IR");
    println!("   Optimized operations: {}", optimized_ir.pipeline.len());

    // Step 4: Generate KQL
    let mut codegen = KqlCodeGenerator::new().with_pretty_print(true);
    let kql = codegen.generate(&optimized_ir);

    println!("✅ Generated KQL:");
    println!("```kql");
    println!("{}", kql);
    println!("```\n");

    Ok(())
}

fn demonstrate_membership_rule() -> Result<()> {
    println!("=== Example 2: Membership Rule ===");

    let rego_policy = r#"
        package authz
        import future.keywords.in
        
        valid_user {
            user.role in {"admin", "user", "guest"}
            user.status == "active"
        }
    "#;

    let source = Source::from_contents("policy.rego".to_string(), rego_policy.to_string())?;
    let mut parser = DatabaseParser::new(&source)?;
    let module = parser.parse_database_module()?;

    let rule = &module.policy[0];
    let mut translator = RegoToKqlIrTranslator::new(None).with_default_table("users".to_string());
    let kql_ir = translator.translate_rule(rule)?;

    let optimizer = KqlOptimizer::new();
    let optimized_ir = optimizer.optimize(&kql_ir);

    let mut codegen = KqlCodeGenerator::new().with_pretty_print(true);
    let kql = codegen.generate(&optimized_ir);

    println!("✅ Generated KQL for membership rule:");
    println!("```kql");
    println!("{}", kql);
    println!("```\n");

    Ok(())
}

fn demonstrate_arithmetic_rule() -> Result<()> {
    println!("=== Example 3: Arithmetic Operations ===");

    let rego_policy = r#"
        package pricing
        
        discounted_price = product.price * 0.9 {
            user.membership == "premium"
            product.category != "restricted"
        }
    "#;

    let source = Source::from_contents("policy.rego".to_string(), rego_policy.to_string())?;
    let mut parser = DatabaseParser::new(&source)?;
    let module = parser.parse_database_module()?;

    let rule = &module.policy[0];
    let mut translator =
        RegoToKqlIrTranslator::new(None).with_default_table("products".to_string());
    let kql_ir = translator.translate_rule(rule)?;

    let optimizer = KqlOptimizer::new();
    let optimized_ir = optimizer.optimize(&kql_ir);

    let mut codegen = KqlCodeGenerator::new().with_pretty_print(true);
    let kql = codegen.generate(&optimized_ir);

    println!("✅ Generated KQL for arithmetic rule:");
    println!("```kql");
    println!("{}", kql);
    println!("```\n");

    Ok(())
}

fn demonstrate_comprehension() -> Result<()> {
    println!("=== Example 4: Array Comprehension ===");

    let rego_query = r#"user.role == "admin""#;

    let source = Source::from_contents("query.rego".to_string(), rego_query.to_string())?;
    let mut parser = DatabaseParser::new(&source)?;
    let query = parser.parse_database_query()?;

    let mut translator = RegoToKqlIrTranslator::new(None).with_default_table("users".to_string());
    let kql_ir = translator.translate_query(&query)?;

    let optimizer = KqlOptimizer::new();
    let optimized_ir = optimizer.optimize(&kql_ir);

    let mut codegen = KqlCodeGenerator::new().with_pretty_print(true);
    let kql = codegen.generate(&optimized_ir);

    println!("✅ Generated KQL for query:");
    println!("```kql");
    println!("{}", kql);
    println!("```\n");

    Ok(())
}

fn demonstrate_binary_serialization() -> Result<()> {
    println!("=== Example 5: Binary Serialization ===");

    // Create a sample KQL IR query
    let query = KqlQueryBuilder::new()
        .from_table("events")
        .where_clause(KqlExpression::equals(
            KqlExpression::column("level"),
            KqlExpression::string_literal("error"),
        ))
        .where_clause(KqlExpression::Binary {
            op: KqlBinaryOp::GreaterThan,
            left: Box::new(KqlExpression::column("timestamp")),
            right: Box::new(KqlExpression::function(
                "ago",
                vec![KqlExpression::string_literal("1h")],
            )),
        })
        .take(100)
        .build()
        .map_err(|e| anyhow::anyhow!(e))?;

    println!("✅ Created sample KQL IR query");

    // Serialize to binary
    let binary_data = query.to_binary().map_err(|e| anyhow::anyhow!(e))?;
    println!("✅ Serialized to binary: {} bytes", binary_data.len());

    // Deserialize from binary
    let deserialized = KqlQuery::from_binary(&binary_data).map_err(|e| anyhow::anyhow!(e))?;
    println!("✅ Deserialized from binary");

    // Verify they're equal
    assert_eq!(query, deserialized);
    println!("✅ Verification passed: original == deserialized");

    // Generate KQL from deserialized IR
    let mut codegen = KqlCodeGenerator::new().with_pretty_print(true);
    let kql = codegen.generate(&deserialized);

    println!("✅ Generated KQL from deserialized IR:");
    println!("```kql");
    println!("{}", kql);
    println!("```\n");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_complete_pipeline() -> Result<()> {
        let rego_policy = r#"
            package test
            import future.keywords.in
            
            allow {
                user.role == "admin"
                user.active == true
            }
        "#;

        // Parse Rego
        let source = Source::from_contents("test.rego".to_string(), rego_policy.to_string())?;
        let mut parser = DatabaseParser::new(&source)?;
        let module = parser.parse_database_module()?;

        // Translate to IR
        let rule = &module.policy[0];
        let mut translator =
            RegoToKqlIrTranslator::new(None).with_default_table("users".to_string());
        let kql_ir = translator.translate_rule(rule)?;

        // Optimize
        let optimizer = KqlOptimizer::new();
        let optimized_ir = optimizer.optimize(&kql_ir);

        // Generate KQL
        let mut codegen = KqlCodeGenerator::new();
        let kql = codegen.generate(&optimized_ir);

        // Verify output contains expected elements
        assert!(kql.contains("users"));
        assert!(kql.contains("where"));
        assert!(kql.contains("role == \"admin\""));
        assert!(kql.contains("active == true"));

        Ok(())
    }

    #[test]
    fn test_ir_round_trip() -> Result<()> {
        let query = KqlQueryBuilder::new()
            .from_table("logs")
            .where_clause(KqlExpression::equals(
                KqlExpression::column("severity"),
                KqlExpression::string_literal("high"),
            ))
            .build()
            .map_err(|e| anyhow::anyhow!(e))?;

        // Binary round trip
        let binary = query.to_binary()?;
        let deserialized = KqlQuery::from_binary(&binary)?;

        assert_eq!(query, deserialized);

        Ok(())
    }
}
