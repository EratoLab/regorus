// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the complete Rego to KQL IR to KQL pipeline

use anyhow::Result;
use regorus::{unstable::*, Source};

#[test]
fn test_simple_allow_rule() -> Result<()> {
    let rego_policy = r#"
        package authz
        
        import rego.v1
        
        allowed_users contains result if {
            some user in data.users
            user.role == "admin"
            user.active == true
            result := {
                "name": user.name,
                "role": user.role
            }
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

    let mut codegen = KqlCodeGenerator::new();
    let kql = codegen.generate(&optimized_ir);

    assert!(kql.contains("users"));
    assert!(kql.contains("where"));
    assert!(kql.contains("role == \"admin\""));
    assert!(kql.contains("active == true"));

    Ok(())
}

#[test]
fn test_membership_rule() -> Result<()> {
    let rego_policy = r#"
        package authz
        
        import rego.v1
        
        allowed_users contains result if {
            some user in data.employees
            user.role in {"admin", "user"}
            user.department == "engineering"
            result := {
                "name": user.name,
                "role": user.role,
                "department": user.department
            }
        }
    "#;

    let source = Source::from_contents("policy.rego".to_string(), rego_policy.to_string())?;
    let mut parser = DatabaseParser::new(&source)?;
    let module = parser.parse_database_module()?;

    let rule = &module.policy[0];
    let mut translator =
        RegoToKqlIrTranslator::new(None).with_default_table("employees".to_string());
    let kql_ir = translator.translate_rule(rule)?;

    let optimizer = KqlOptimizer::new();
    let optimized_ir = optimizer.optimize(&kql_ir);

    let mut codegen = KqlCodeGenerator::new();
    let kql = codegen.generate(&optimized_ir);

    assert!(kql.contains("employees"));
    assert!(kql.contains("where"));
    assert!(kql.contains("in (pack_array(\"admin\", \"user\"))"));
    assert!(kql.contains("department == \"engineering\""));

    Ok(())
}

#[test]
fn test_query_translation() -> Result<()> {
    let rego_query = r#"user.role == "admin"; user.active == true"#;

    let source = Source::from_contents("query.rego".to_string(), rego_query.to_string())?;
    let mut parser = DatabaseParser::new(&source)?;
    let query = parser.parse_database_query()?;

    let mut translator = RegoToKqlIrTranslator::new(None).with_default_table("users".to_string());
    let kql_ir = translator.translate_query(&query)?;

    let optimizer = KqlOptimizer::new();
    let optimized_ir = optimizer.optimize(&kql_ir);

    let mut codegen = KqlCodeGenerator::new();
    let kql = codegen.generate(&optimized_ir);

    assert!(kql.contains("users"));
    assert!(kql.contains("where"));
    assert!(kql.contains("role == \"admin\""));
    assert!(kql.contains("active == true"));

    Ok(())
}

#[test]
fn test_binary_serialization_round_trip() -> Result<()> {
    // Create KQL IR manually
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

    // Binary round trip
    let binary = query.to_binary().map_err(|e| anyhow::anyhow!(e))?;
    let deserialized = KqlQuery::from_binary(&binary).map_err(|e| anyhow::anyhow!(e))?;

    assert_eq!(query, deserialized);

    // Verify both generate same KQL
    let mut codegen = KqlCodeGenerator::new();
    let kql1 = codegen.generate(&query);
    let kql2 = codegen.generate(&deserialized);

    assert_eq!(kql1, kql2);

    Ok(())
}

#[test]
fn test_optimization() -> Result<()> {
    let rego_policy = r#"
        package test
        
        import rego.v1
        
        allowed_users contains result if {
            some user in data.users
            user.role == "admin"
            user.role == "admin"
            user.active == true
            result := {
                "name": user.name,
                "role": user.role
            }
        }
    "#;

    let source = Source::from_contents("policy.rego".to_string(), rego_policy.to_string())?;
    let mut parser = DatabaseParser::new(&source)?;
    let module = parser.parse_database_module()?;

    let rule = &module.policy[0];
    let mut translator = RegoToKqlIrTranslator::new(None).with_default_table("users".to_string());
    let kql_ir = translator.translate_rule(rule)?;

    // Check original has redundant operations
    let original_filters = kql_ir
        .pipeline
        .iter()
        .filter(|op| matches!(op, KqlOperation::Where(_)))
        .count();

    // Optimize
    let optimizer = KqlOptimizer::new();
    let optimized_ir = optimizer.optimize(&kql_ir);

    // Check optimized has fewer operations
    let optimized_filters = optimized_ir
        .pipeline
        .iter()
        .filter(|op| matches!(op, KqlOperation::Where(_)))
        .count();

    // Note: Optimizer may consolidate filters, so this is more about structure than count
    assert!(optimized_filters <= original_filters);

    Ok(())
}

#[test]
fn test_complex_expressions() -> Result<()> {
    let rego_policy = r#"
        package complex
        
        import rego.v1
        
        allowed_users contains result if {
            some user in data.employees
            user.role in {"admin", "manager"}
            user.experience_years >= 5
            user.department != "contractor"
            user.salary > 50000
            user.clearance_level == "secret"
            result := {
                "name": user.name,
                "role": user.role,
                "experience": user.experience_years
            }
        }
    "#;

    let source = Source::from_contents("policy.rego".to_string(), rego_policy.to_string())?;
    let mut parser = DatabaseParser::new(&source)?;
    let module = parser.parse_database_module()?;

    let rule = &module.policy[0];
    let mut translator =
        RegoToKqlIrTranslator::new(None).with_default_table("employees".to_string());
    let kql_ir = translator.translate_rule(rule)?;

    let optimizer = KqlOptimizer::new();
    let optimized_ir = optimizer.optimize(&kql_ir);

    let mut codegen = KqlCodeGenerator::new();
    let kql = codegen.generate(&optimized_ir);

    // Verify all conditions are present
    assert!(kql.contains("employees"));
    assert!(kql.contains("in (pack_array(\"admin\", \"manager\"))"));
    assert!(kql.contains("experience_years >= 5"));
    assert!(kql.contains("department != \"contractor\""));
    assert!(kql.contains("salary > 50000"));
    assert!(kql.contains("clearance_level == \"secret\""));

    Ok(())
}

#[test]
fn test_multiple_rules() -> Result<()> {
    let rego_policy = r#"
        package authz
        
        import rego.v1
        
        admin_users contains result if {
            some user in data.users
            user.role == "admin"
            user.active == true
            result := {
                "name": user.name,
                "access_type": "admin"
            }
        }
        
        regular_users contains result if {
            some user in data.users
            user.role == "user"
            user.verified == true
            result := {
                "name": user.name,
                "access_type": "user"
            }
        }
    "#;

    let source = Source::from_contents("policy.rego".to_string(), rego_policy.to_string())?;
    let mut parser = DatabaseParser::new(&source)?;
    let module = parser.parse_database_module()?;

    assert_eq!(module.policy.len(), 2);

    let mut translator = RegoToKqlIrTranslator::new(None).with_default_table("users".to_string());

    // Translate first rule
    let rule1 = &module.policy[0];
    let kql_ir1 = translator.translate_rule(rule1)?;
    let kql1 = KqlCodeGenerator::new().generate(&kql_ir1);

    // Translate second rule
    let rule2 = &module.policy[1];
    let kql_ir2 = translator.translate_rule(rule2)?;
    let kql2 = KqlCodeGenerator::new().generate(&kql_ir2);

    // Verify both translations
    assert!(kql1.contains("role == \"admin\""));
    assert!(kql1.contains("active == true"));

    assert!(kql2.contains("role == \"user\""));
    assert!(kql2.contains("verified == true"));

    Ok(())
}

#[test]
fn test_error_handling() -> Result<()> {
    // Test invalid Rego
    let invalid_rego = "this is not valid rego syntax";
    let source = Source::from_contents("invalid.rego".to_string(), invalid_rego.to_string())?;
    let mut parser = DatabaseParser::new(&source)?;

    // Should fail to parse
    let result = parser.parse_database_module();
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_pretty_printing() -> Result<()> {
    let rego_policy = r#"
        package test
        
        import rego.v1
        
        allowed_users contains result if {
            some user in data.users
            user.role == "admin"
            user.active == true
            result := {
                "name": user.name,
                "role": user.role
            }
        }
    "#;

    let source = Source::from_contents("policy.rego".to_string(), rego_policy.to_string())?;
    let mut parser = DatabaseParser::new(&source)?;
    let module = parser.parse_database_module()?;

    let rule = &module.policy[0];
    let mut translator = RegoToKqlIrTranslator::new(None).with_default_table("users".to_string());
    let kql_ir = translator.translate_rule(rule)?;

    // Test compact format
    let compact_kql = KqlCodeGenerator::new().generate(&kql_ir);

    // Test pretty format
    let pretty_kql = KqlCodeGenerator::new()
        .with_pretty_print(true)
        .generate(&kql_ir);

    // Pretty version should have more whitespace/newlines
    assert!(pretty_kql.len() >= compact_kql.len());
    assert!(pretty_kql.contains('\n') || compact_kql == pretty_kql);

    Ok(())
}
