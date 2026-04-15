// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Complete pipeline example: Database Rego Subset → KQL Translation
//!
//! This example demonstrates the complete workflow from parsing database-subset
//! Rego policies to generating executable KQL queries for Azure services.

use anyhow::Result;
use regorus::{
    unstable::{DatabaseParser, KqlTranslator},
    Source,
};

fn main() -> Result<()> {
    println!("=== Complete Database Rego to KQL Pipeline ===\n");

    // Real-world security policy example
    let security_policy = r#"
        package security.access_control

        import future.keywords.in

        # Multi-factor authentication required for admin access
        require_mfa {
            user.role in {"admin", "security_admin"}
            resource.classification == "confidential"
        }

        # Risk-based access control
        access_risk_level = "high" {
            user.failed_login_attempts >= 5
            user.last_login_days > 30
        }

        access_risk_level = "medium" {
            user.failed_login_attempts >= 3
            user.failed_login_attempts < 5
            user.last_login_days <= 30
        }

        access_risk_level = "low" {
            user.failed_login_attempts < 3
            user.last_login_days <= 7
            user.mfa_enabled == true
        }

        # Data access authorization
        allow_data_access {
            user.role in {"data_scientist", "analyst", "admin"}
            user.department == "analytics"
            user.clearance_level >= data.required_clearance
        }

        allow_data_access {
            user.role == "admin"
            user.emergency_access == true
        }

        # Calculate access score for monitoring
        access_score = (user.trust_level * 10) + (user.tenure_months / 12) {
            user.status == "active"
            user.compliance_training == true
        }
    "#;

    println!("Original Rego Security Policy:");
    println!("{}", security_policy);
    println!("{}", "=".repeat(80));

    // Step 1: Parse with database subset parser
    println!("\n🔍 Step 1: Parsing with Database Subset Parser");
    let source = Source::from_contents(
        "security_policy.rego".to_string(),
        security_policy.to_string(),
    )?;
    let mut parser = DatabaseParser::new(&source)?;

    let module = match parser.parse_database_module() {
        Ok(module) => {
            println!("✅ Successfully parsed database-subset Rego policy");
            println!("   - Package: {}", module.package.refr.span().text());
            println!("   - Rules: {}", module.policy.len());
            println!("   - Imports: {}", module.imports.len());
            module
        }
        Err(e) => {
            println!("❌ Parse error: {}", e);
            return Err(e);
        }
    };

    // Step 2: Translate to KQL
    println!("\n⚡ Step 2: Translating to KQL Queries");
    let mut translator = KqlTranslator::new("UserSessions".to_string());

    let queries = match translator.translate_module(&module) {
        Ok(queries) => {
            println!("✅ Successfully generated {} KQL queries", queries.len());
            queries
        }
        Err(e) => {
            println!("❌ Translation error: {}", e);
            return Err(e);
        }
    };

    // Step 3: Display generated KQL queries
    println!("\n📊 Step 3: Generated KQL Queries for Azure Data Explorer/Monitor");
    println!("{}", "=".repeat(80));

    for (i, query) in queries.iter().enumerate() {
        println!("\n🔹 Query {} - {}:", i + 1, get_query_description(i));
        println!("```kql");
        println!("{}", query);
        println!("```");
    }

    // Step 4: Show practical usage examples
    println!("\n🚀 Step 4: Practical Usage in Azure Services");
    println!("{}", "=".repeat(80));

    println!("\n📈 Azure Monitor - Security Alert Query:");
    println!("```kql");
    println!("// Based on require_mfa rule");
    println!("UserSessions");
    println!("| where user.role in dynamic([\"admin\", \"security_admin\"]) and resource.classification == \"confidential\"");
    println!("| where not(user.mfa_enabled == true)  // Users without MFA");
    println!("| extend AlertSeverity = \"High\"");
    println!("| extend AlertType = \"MFA_Required_Access_Violation\"");
    println!("| project TimeGenerated, user.email, resource.name, AlertSeverity, AlertType");
    println!("```");

    println!("\n🛡️ Azure Security Center - Risk Assessment:");
    println!("```kql");
    println!("// Based on access_risk_level rules");
    println!("UserSessions");
    println!("| extend RiskLevel = case(");
    println!("    user.failed_login_attempts >= 5 and user.last_login_days > 30, \"high\",");
    println!("    user.failed_login_attempts >= 3 and user.failed_login_attempts < 5 and user.last_login_days <= 30, \"medium\",");
    println!("    user.failed_login_attempts < 3 and user.last_login_days <= 7 and user.mfa_enabled == true, \"low\",");
    println!("    \"unknown\")");
    println!("| where RiskLevel in (\"high\", \"medium\")");
    println!("| summarize HighRiskUsers = countif(RiskLevel == \"high\"), MediumRiskUsers = countif(RiskLevel == \"medium\") by bin(TimeGenerated, 1h)");
    println!("```");

    println!("\n📊 Azure Data Explorer - Analytics Dashboard:");
    println!("```kql");
    println!("// Based on access_score rule");
    println!("UserSessions");
    println!("| where user.status == \"active\" and user.compliance_training == true");
    println!("| extend AccessScore = (user.trust_level * 10) + (user.tenure_months / 12)");
    println!("| summarize");
    println!("    AvgAccessScore = avg(AccessScore),");
    println!("    MaxAccessScore = max(AccessScore),");
    println!("    MinAccessScore = min(AccessScore),");
    println!("    UserCount = count()");
    println!("    by user.department");
    println!("| order by AvgAccessScore desc");
    println!("```");

    // Step 5: Integration guidance
    println!("\n🔧 Step 5: Integration with Azure Services");
    println!("{}", "=".repeat(80));

    println!("\n✨ Integration Options:");
    println!("1. 📋 Azure Policy - Convert Rego policies to Azure Policy rules");
    println!("2. 🔍 Azure Monitor - Create custom log analytics queries");
    println!("3. 🛡️ Azure Security Center - Generate security assessments");
    println!("4. 📊 Azure Data Explorer - Build compliance dashboards");
    println!("5. ⚡ Azure Functions - Automated policy evaluation");

    println!("\n🔄 Deployment Pipeline:");
    println!("1. Write Rego policies using database subset");
    println!("2. Validate with DatabaseParser");
    println!("3. Translate to KQL with KqlTranslator");
    println!("4. Deploy queries to Azure services");
    println!("5. Monitor and alert on policy violations");

    // Step 6: Performance and best practices
    println!("\n🎯 Step 6: Performance Best Practices");
    println!("{}", "=".repeat(80));

    println!("\n⚡ Query Optimization Tips:");
    println!("• Use indexed columns in WHERE clauses (user.id, timestamp)");
    println!("• Limit time ranges with datetime filters");
    println!("• Use dynamic() for efficient set membership tests");
    println!("• Leverage summarize for aggregations");
    println!("• Use extend for calculated fields");

    println!("\n📈 Monitoring Recommendations:");
    println!("• Set up alerts for high-risk access patterns");
    println!("• Create dashboards for policy compliance metrics");
    println!("• Use workbooks for interactive analysis");
    println!("• Implement automated response actions");

    println!("\n✅ Summary");
    println!("The database Rego subset enables:");
    println!("• 🔒 Policy-as-code for security and compliance");
    println!("• ⚡ Efficient database-native execution");
    println!("• 🔄 Seamless integration with Azure services");
    println!("• 📊 Real-time monitoring and alerting");
    println!("• 🛡️ Scalable security policy enforcement");

    Ok(())
}

fn get_query_description(index: usize) -> &'static str {
    match index {
        0 => "MFA Requirement Check",
        1 => "High Risk Access Level",
        2 => "Medium Risk Access Level",
        3 => "Low Risk Access Level",
        4 => "Data Access Authorization (Analytics Team)",
        5 => "Data Access Authorization (Emergency Admin)",
        6 => "Access Score Calculation",
        _ => "Additional Query",
    }
}
