// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! YAML-based tests for KQL code generation
//!
//! This module provides YAML-based tests that verify the complete pipeline
//! from Rego to KQL via the intermediate representation.

use anyhow::{bail, Result};
use regorus::unstable::*;
use serde::{Deserialize, Serialize};
use test_generator::test_resources;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct KqlTestCase {
    /// Description of the test case
    note: String,
    /// Rego module source code
    rego: String,
    /// Expected KQL output
    expected_kql: Option<String>,
    /// Expected error message (if translation should fail)
    error: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct KqlYamlTest {
    cases: Vec<KqlTestCase>,
}

fn normalize_kql(kql: &str) -> String {
    // Normalize whitespace, line breaks, and standardize formatting for comparison
    kql.lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .replace("  ", " ") // Remove double spaces
        .replace("| ", " | ") // Standardize pipe spacing
        .trim()
        .to_string()
}

fn kql_test_impl(file: &str) -> Result<()> {
    println!("\nrunning {file}");

    let yaml_str = std::fs::read_to_string(file)?;
    let test: KqlYamlTest = serde_yaml::from_str(&yaml_str)?;

    for case in &test.cases {
        print!("\ncase {} ", case.note);

        let source = Source::from_contents("case.rego".to_string(), case.rego.clone())?;
        let mut parser = DatabaseParser::new(&source)?;
        parser.enable_rego_v1()?;

        match parser.parse_database_module() {
            Ok(module) => {
                if let Some(expected_error) = &case.error {
                    bail!("Expected error `{}` but parsing succeeded.", expected_error);
                }

                // Test that we have at least one rule to translate
                if module.policy.is_empty() {
                    if case.expected_kql.is_some() {
                        bail!("Module has no rules but KQL output was expected.");
                    }
                    println!("passed (empty module)");
                    continue;
                }

                // Translate the first rule
                let rule = &module.policy[0];
                let default_table = "events"; // Default table name
                let mut translator =
                    RegoToKqlIrTranslator::new(None).with_default_table(default_table.to_string());

                match translator.translate_rule(rule) {
                    Ok(kql_ir) => {
                        // Optimize the IR
                        let optimizer = KqlOptimizer::new();
                        let optimized_ir = optimizer.optimize(&kql_ir);

                        // Generate KQL with pretty printing always enabled
                        let mut codegen = KqlCodeGenerator::new().with_pretty_print(true);
                        let actual_kql = codegen.generate(&optimized_ir);

                        if let Some(expected_kql) = &case.expected_kql {
                            let normalized_actual = normalize_kql(&actual_kql);
                            let normalized_expected = normalize_kql(expected_kql);

                            if normalized_actual != normalized_expected {
                                bail!(
                                    "KQL mismatch:\nExpected:\n{}\n\nActual:\n{}\n\nNormalized Expected:\n{}\n\nNormalized Actual:\n{}",
                                    expected_kql,
                                    actual_kql,
                                    normalized_expected,
                                    normalized_actual
                                );
                            }
                        }

                        println!("passed");
                    }
                    Err(translation_error) => {
                        if let Some(expected_error) = &case.error {
                            let error_str = translation_error.to_string();
                            if !error_str.contains(expected_error) {
                                bail!(
                                    "Translation error `{}` does not contain expected `{}`",
                                    error_str,
                                    expected_error
                                );
                            }
                            println!("passed (expected error)");
                        } else {
                            bail!("Unexpected translation error: {}", translation_error);
                        }
                    }
                }
            }
            Err(parse_error) => {
                if let Some(expected_error) = &case.error {
                    let error_str = parse_error.to_string();
                    if !error_str.contains(expected_error) {
                        bail!(
                            "Parse error `{}` does not contain expected `{}`",
                            error_str,
                            expected_error
                        );
                    }
                    println!("passed (expected parse error)");
                } else {
                    bail!("Unexpected parse error: {}", parse_error);
                }
            }
        }
    }

    println!("{} cases passed.", test.cases.len());
    Ok(())
}

fn kql_test(file: &str) -> Result<()> {
    match kql_test_impl(file) {
        Ok(_) => Ok(()),
        Err(e) => {
            // If Err is returned, it doesn't always get printed by cargo test.
            // Therefore, panic with the error.
            panic!("{}", e);
        }
    }
}

#[test_resources("tests/kql_codegen/**/*.yaml")]
fn run_kql_tests(path: &str) {
    kql_test(path).unwrap()
}
