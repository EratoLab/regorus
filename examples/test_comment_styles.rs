// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test both comment styles

use regorus::{unstable::*, Source};

fn main() -> anyhow::Result<()> {
    println!("=== Testing Hash Comments (#) ===");
    let rego_hash_comments = r#"
        # Hash style comment
        package authz
        import future.keywords.in
        
        allow {
            user.role == "admin"  # End of line comment
        }
    "#;

    test_comment_style("Hash comments", rego_hash_comments, false)?;

    println!("\n=== Testing Mixed Comments ===");
    let rego_mixed_comments = r#"
        # Package declaration comment
        package authz
        import future.keywords.in  # Import comment
        
        # Rule comment
        allow {
            # Condition comment
            user.role == "admin"  # End of line comment
            user.active == true   # Another condition
        }
    "#;

    test_comment_style("Mixed comments", rego_mixed_comments, false)?;

    Ok(())
}

fn test_comment_style(name: &str, rego_code: &str, _use_c_style: bool) -> anyhow::Result<()> {
    let source = Source::from_contents("test.rego".to_string(), rego_code.to_string())?;
    let mut parser = DatabaseParser::new(&source)?;

    match parser.parse_database_module() {
        Ok(module) => {
            println!("✅ Successfully parsed {}", name);
            println!("   Rules: {}", module.policy.len());

            if !module.policy.is_empty() {
                let rule = &module.policy[0];
                let mut translator =
                    RegoToKqlIrTranslator::new(None).with_default_table("users".to_string());
                match translator.translate_rule(rule) {
                    Ok(kql_ir) => {
                        let mut codegen = KqlCodeGenerator::new().with_pretty_print(true);
                        let kql = codegen.generate(&kql_ir);
                        println!("   Generated KQL: {}", kql.replace('\n', " | "));
                    }
                    Err(e) => println!("❌ KQL translation failed: {}", e),
                }
            }
        }
        Err(e) => {
            println!("❌ Failed to parse {}: {}", name, e);
        }
    }

    Ok(())
}
