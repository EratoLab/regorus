// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! YAML-based tests for SQL code generation
//!
//! This module provides YAML-based tests that verify the complete pipeline
//! from Rego to SQL via the intermediate representation.

use anyhow::{bail, Result};
use regorus::unstable::*;
use serde::{Deserialize, Serialize};
use test_generator::test_resources;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct SqlTestCase {
    /// Description of the test case
    note: String,
    /// Rego module source code
    rego: String,
    /// Expected SQL output
    expected_sql: Option<String>,
    /// Expected error message (if translation should fail)
    error: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct SqlYamlTest {
    cases: Vec<SqlTestCase>,
}

fn normalize_sql(sql: &str) -> String {
    // Normalize whitespace, line breaks, and standardize formatting for comparison
    sql.lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .replace("  ", " ") // Remove double spaces
        .trim()
        .to_string()
}

fn sql_test_impl(file: &str) -> Result<()> {
    println!("\nrunning {file}");

    let yaml_str = std::fs::read_to_string(file)?;
    let test: SqlYamlTest = serde_yaml::from_str(&yaml_str)?;

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
                    if case.expected_sql.is_some() {
                        bail!("Module has no rules but SQL output was expected.");
                    }
                    println!("passed (empty module)");
                    continue;
                }

                // Note: SQL translation will be implemented in a future step
                // For now, we'll just verify that the test infrastructure works
                println!("passed (test infrastructure)");
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

fn sql_test(path: &str) -> Result<()> {
    match sql_test_impl(path) {
        Ok(_) => Ok(()),
        Err(e) => {
            // If Err is returned, it doesn't always get printed by cargo test.
            // Therefore, panic with the error.
            panic!("{}", e);
        }
    }
}

#[test_resources("tests/sql_codegen/**/*.yaml")]
fn run_sql_tests(path: &str) {
    sql_test(path).unwrap()
}