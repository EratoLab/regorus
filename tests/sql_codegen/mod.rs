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
        .replace(", ", ",") // Remove space after commas
        .replace("( ", "(") // Remove space after opening paren
        .replace(" )", ")") // Remove space before closing paren
        .replace(" FROM", "FROM") // Normalize FROM clause
        .replace(" WHERE", "WHERE") // Normalize WHERE clause
        .replace(" INNER", "INNER") // Normalize JOIN clauses
        .replace(" AND", "AND") // Normalize AND operators
        .replace(" OR", "OR") // Normalize OR operators
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

                // Translate the first rule using RegoToSqlIrTranslator
                let rule = &module.policy[0];
                let default_table = "events"; // Default table name
                let mut translator =
                    RegoToSqlIrTranslator::new(None).with_default_table(default_table.to_string());

                match translator.translate_rule(rule) {
                    Ok(sql_ir) => {
                        // Optimize the IR
                        let optimizer = SqlOptimizer::new();
                        let optimized_ir = optimizer.optimize(&sql_ir);

                        // Generate SQL with pretty printing always enabled
                        let mut codegen = SqlCodeGenerator::new().with_pretty_print(true);
                        let actual_sql = codegen.generate(&optimized_ir);

                        if let Some(expected_sql) = &case.expected_sql {
                            let normalized_actual = normalize_sql(&actual_sql);
                            let normalized_expected = normalize_sql(expected_sql);

                            if normalized_actual != normalized_expected {
                                bail!(
                                    "SQL mismatch:\nExpected:\n{}\n\nActual:\n{}\n\nNormalized Expected:\n{}\n\nNormalized Actual:\n{}",
                                    expected_sql,
                                    actual_sql,
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

// Direct SQL IR and codegen tests
#[cfg(test)]
mod direct_sql_tests {
    use super::*;
    use regorus::unstable::*;

    #[test]
    fn test_simple_select_generation() {
        let query = SqlQueryBuilder::new()
            .from_table("users")
            .where_clause(SqlExpression::equals(
                SqlExpression::column("role"),
                SqlExpression::string_literal("admin"),
            ))
            .project(vec![
                SqlColumn {
                    name: "role".to_string(),
                    expression: SqlExpression::column("role"),
                    alias: None,
                },
                SqlColumn {
                    name: "active".to_string(),
                    expression: SqlExpression::column("active"),
                    alias: None,
                },
            ])
            .limit(10)
            .build()
            .unwrap();

        let optimizer = SqlOptimizer::new();
        let optimized_ir = optimizer.optimize(&query);

        let mut codegen = SqlCodeGenerator::new().with_pretty_print(true);
        let sql = codegen.generate(&optimized_ir);

        assert!(sql.contains("SELECT"));
        assert!(sql.contains("role"));
        assert!(sql.contains("active"));
        assert!(sql.contains("FROM users"));
        assert!(sql.contains("WHERE"));
        assert!(sql.contains("admin"));
        assert!(sql.contains("LIMIT 10"));
    }

    #[test]
    fn test_join_generation() {
        let query = SqlQueryBuilder::new()
            .from_table("users")
            .join(
                SqlJoinKind::Inner,
                "roles",
                vec![SqlJoinCondition {
                    left: SqlExpression::column("users.role_id"),
                    right: SqlExpression::column("roles.id"),
                    operator: SqlBinaryOp::Equal,
                }],
            )
            .project(vec![
                SqlColumn {
                    name: "name".to_string(),
                    expression: SqlExpression::column("users.name"),
                    alias: None,
                },
                SqlColumn {
                    name: "role_name".to_string(),
                    expression: SqlExpression::column("roles.name"),
                    alias: None,
                },
            ])
            .build()
            .unwrap();

        let optimizer = SqlOptimizer::new();
        let optimized_ir = optimizer.optimize(&query);

        let mut codegen = SqlCodeGenerator::new().with_pretty_print(true);
        let sql = codegen.generate(&optimized_ir);

        assert!(sql.contains("SELECT"));
        assert!(sql.contains("FROM users"));
        assert!(sql.contains("INNER JOIN"));
        assert!(sql.contains("roles"));
        assert!(sql.contains("ON"));
    }

    #[test]
    fn test_aggregation_generation() {
        let query = SqlQueryBuilder::new()
            .from_table("events")
            .aggregate(
                vec![SqlExpression::column("category")],
                vec![SqlAggregate {
                    function: SqlAggregateFunction::Count,
                    expression: None,
                    alias: "event_count".to_string(),
                    distinct: false,
                }],
                None,
            )
            .build()
            .unwrap();

        let optimizer = SqlOptimizer::new();
        let optimized_ir = optimizer.optimize(&query);

        let mut codegen = SqlCodeGenerator::new().with_pretty_print(true);
        let sql = codegen.generate(&optimized_ir);

        assert!(sql.contains("SELECT"));
        assert!(sql.contains("FROM events"));
        assert!(sql.contains("GROUP BY"));
        assert!(sql.contains("COUNT(*)"));
        assert!(sql.contains("event_count"));
    }

    #[test]
    fn test_complex_where_clause() {
        let query = SqlQueryBuilder::new()
            .from_table("employees")
            .where_clause(SqlExpression::and(
                SqlExpression::equals(
                    SqlExpression::column("department"),
                    SqlExpression::string_literal("engineering"),
                ),
                SqlExpression::or(
                    SqlExpression::equals(
                        SqlExpression::column("role"),
                        SqlExpression::string_literal("admin"),
                    ),
                    SqlExpression::equals(
                        SqlExpression::column("role"),
                        SqlExpression::string_literal("manager"),
                    ),
                ),
            ))
            .build()
            .unwrap();

        let optimizer = SqlOptimizer::new();
        let optimized_ir = optimizer.optimize(&query);

        let mut codegen = SqlCodeGenerator::new().with_pretty_print(true);
        let sql = codegen.generate(&optimized_ir);

        assert!(sql.contains("SELECT"));
        assert!(sql.contains("FROM employees"));
        assert!(sql.contains("WHERE"));
        assert!(sql.contains("engineering"));
        assert!(sql.contains("AND"));
        assert!(sql.contains("OR"));
    }

    #[test]
    fn test_order_by_generation() {
        let query = SqlQueryBuilder::new()
            .from_table("users")
            .order_by(vec![
                SqlOrderBy {
                    expression: SqlExpression::column("name"),
                    direction: SqlSortDirection::Ascending,
                    null_order: None,
                },
                SqlOrderBy {
                    expression: SqlExpression::column("created_at"),
                    direction: SqlSortDirection::Descending,
                    null_order: None,
                },
            ])
            .limit(100)
            .build()
            .unwrap();

        let optimizer = SqlOptimizer::new();
        let optimized_ir = optimizer.optimize(&query);

        let mut codegen = SqlCodeGenerator::new().with_pretty_print(true);
        let sql = codegen.generate(&optimized_ir);

        assert!(sql.contains("ORDER BY"));
        assert!(sql.contains("ASC"));
        assert!(sql.contains("DESC"));
        assert!(sql.contains("LIMIT 100"));
    }
}
