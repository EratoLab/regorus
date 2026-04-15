// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test comment parsing

use regorus::{unstable::*, Source};

fn main() -> anyhow::Result<()> {
    let rego_with_comments = r#"
        # This is a comment
        package authz
        import future.keywords.in
        
        # Another comment
        allow {
            # Inline comment
            user.role == "admin"  # End of line comment
            user.active == true
        }
    "#;

    println!("Testing Rego with comments:");
    println!("{}", rego_with_comments);

    let source = Source::from_contents("test.rego".to_string(), rego_with_comments.to_string())?;
    let mut parser = DatabaseParser::new(&source)?;

    match parser.parse_database_module() {
        Ok(module) => {
            println!("✅ Successfully parsed Rego with comments");
            println!("   Package: {:?}", module.package.refr);
            println!("   Rules: {}", module.policy.len());

            if !module.policy.is_empty() {
                let rule = &module.policy[0];
                let mut translator =
                    RegoToKqlIrTranslator::new(None).with_default_table("users".to_string());
                match translator.translate_rule(rule) {
                    Ok(kql_ir) => {
                        let mut codegen = KqlCodeGenerator::new().with_pretty_print(true);
                        let kql = codegen.generate(&kql_ir);
                        println!("✅ Generated KQL:");
                        println!("{}", kql);
                    }
                    Err(e) => println!("❌ KQL translation failed: {}", e),
                }
            }
        }
        Err(e) => {
            println!("❌ Failed to parse Rego with comments: {}", e);
        }
    }

    Ok(())
}
