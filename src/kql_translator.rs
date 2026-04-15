// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! KQL (Kusto Query Language) translator for database-friendly Rego subset
//!
//! This module translates validated database-subset Rego AST nodes into KQL queries
//! that can be executed by Azure Data Explorer, Azure Monitor, and other Kusto-based services.

use crate::ast::*;
use alloc::{
    format,
    string::{String, ToString as _},
    vec::Vec,
};
use anyhow::{bail, Result};

/// KQL query builder and translator
#[derive(Debug)]
pub struct KqlTranslator {
    /// The base table name for queries
    base_table: String,
    /// Generated KQL query parts
    query_parts: Vec<String>,
    /// Variable bindings for comprehensions
    variable_bindings: Vec<(String, String)>,
}

impl KqlTranslator {
    /// Create a new KQL translator
    pub const fn new(base_table: String) -> Self {
        Self {
            base_table,
            query_parts: Vec::new(),
            variable_bindings: Vec::new(),
        }
    }

    /// Translate a database-subset Rego module to KQL queries
    pub fn translate_module(&mut self, module: &Module) -> Result<Vec<String>> {
        let mut queries = Vec::new();

        for rule in &module.policy {
            if let Some(query) = self.translate_rule(rule)? {
                queries.push(query);
            }
        }

        Ok(queries)
    }

    /// Translate a single rule to KQL
    pub fn translate_rule(&mut self, rule: &Ref<Rule>) -> Result<Option<String>> {
        match *rule.as_ref() {
            Rule::Spec {
                ref head,
                ref bodies,
                ..
            } => {
                self.query_parts.clear();
                self.variable_bindings.clear();

                // Start with the base table
                self.query_parts.push(self.base_table.clone());

                // Translate rule head to determine output
                let output_expr = self.translate_rule_head(head)?;

                // Translate rule bodies to filters and conditions
                if !bodies.is_empty() {
                    self.translate_rule_bodies(bodies)?;
                }

                // Build the final query
                let mut query = self.query_parts.join("\n| ");

                // Add projection if needed
                if let Some(output) = output_expr {
                    query.push_str(&format!("\n| extend result = {}", output));
                    query.push_str("\n| project result");
                }

                Ok(Some(query))
            }
            Rule::Default {
                ref refr,
                ref value,
                ..
            } => {
                // Default rules create a simple constant query
                let rule_name = Self::extract_rule_name(refr)?;
                let value_kql = self.translate_expr(value)?;

                let query = format!("print {}_default = {}", rule_name, value_kql);

                Ok(Some(query))
            }
        }
    }

    /// Translate a rule head to determine output expression
    fn translate_rule_head(&mut self, head: &RuleHead) -> Result<Option<String>> {
        match *head {
            RuleHead::Compr {
                ref refr,
                ref assign,
                ..
            } => {
                let rule_name = Self::extract_rule_name(refr)?;

                if let Some(ref assign_val) = *assign {
                    // Rule with assignment: rule_name = expression
                    let expr_kql = self.translate_expr(&assign_val.value)?;
                    Ok(Some(format!("{} = {}", rule_name, expr_kql)))
                } else {
                    // Boolean rule: just rule_name
                    Ok(Some(rule_name))
                }
            }
            RuleHead::Set {
                ref refr, ref key, ..
            } => {
                let rule_name = Self::extract_rule_name(refr)?;

                if let Some(ref key_expr) = *key {
                    // Set rule with key: rule_name[key]
                    let key_kql = self.translate_expr(key_expr)?;
                    Ok(Some(format!("{}[{}]", rule_name, key_kql)))
                } else {
                    // Simple set rule
                    Ok(Some(rule_name))
                }
            }
            RuleHead::Func { .. } => {
                bail!("Function rules are not supported in database subset")
            }
        }
    }

    /// Translate rule bodies to KQL filters
    fn translate_rule_bodies(&mut self, bodies: &[RuleBody]) -> Result<()> {
        for body in bodies {
            if let Some(ref assign) = body.assign {
                // Handle else assignments
                let expr_kql = self.translate_expr(&assign.value)?;
                self.query_parts
                    .push(format!("extend else_value = {}", expr_kql));
            }

            // Translate the query part
            self.translate_query_body(&body.query)?;
        }
        Ok(())
    }

    /// Translate a query to KQL filters
    fn translate_query_body(&mut self, query: &Ref<Query>) -> Result<()> {
        let mut where_conditions = Vec::new();
        let mut extend_expressions = Vec::new();

        for stmt in &query.stmts {
            match stmt.literal {
                Literal::Expr { ref expr, .. } => {
                    match *expr.as_ref() {
                        Expr::AssignExpr {
                            ref lhs,
                            ref rhs,
                            ref op,
                            ..
                        } => {
                            let var_name = Self::extract_variable_name(lhs)?;
                            let rhs_kql = self.translate_expr(rhs)?;

                            match *op {
                                AssignOp::Eq => {
                                    // Variable assignment for binding
                                    extend_expressions.push(format!("{} = {}", var_name, rhs_kql));
                                    self.variable_bindings.push((var_name, rhs_kql));
                                }
                                AssignOp::ColEq => {
                                    // Define assignment
                                    extend_expressions.push(format!("{} = {}", var_name, rhs_kql));
                                }
                            }
                        }
                        _ => {
                            // Regular expression that should evaluate to true
                            let condition = self.translate_expr(expr)?;
                            where_conditions.push(condition);
                        }
                    }
                }
                Literal::NotExpr { ref expr, .. } => {
                    let condition = self.translate_expr(expr)?;
                    where_conditions.push(format!("not ({})", condition));
                }
                Literal::SomeVars { .. } => {
                    // Some variable declarations don't translate directly
                    // They're handled in the context of other expressions
                }
                Literal::SomeIn {
                    ref value,
                    ref collection,
                    ref key,
                    ..
                } => {
                    let value_kql = self.translate_expr(value)?;
                    let collection_kql = self.translate_expr(collection)?;

                    if let Some(ref key_expr) = *key {
                        let key_kql = self.translate_expr(key_expr)?;
                        where_conditions.push(format!("{} in {}", key_kql, collection_kql));
                        extend_expressions.push(format!("some_value = {}", value_kql));
                    } else {
                        where_conditions.push(format!("{} in {}", value_kql, collection_kql));
                    }
                }
                Literal::Every { .. } => {
                    bail!("Every statements are not supported in database subset")
                }
            }
        }

        // Add extend expressions
        for extend in extend_expressions {
            self.query_parts.push(format!("extend {}", extend));
        }

        // Add where conditions
        if !where_conditions.is_empty() {
            let combined_where = where_conditions.join(" and ");
            self.query_parts.push(format!("where {}", combined_where));
        }

        Ok(())
    }

    /// Translate a Rego expression to KQL
    fn translate_expr(&self, expr: &Ref<Expr>) -> Result<String> {
        match *expr.as_ref() {
            // Literals
            Expr::String { ref value, .. } => {
                if let Ok(s) = value.as_string() {
                    Ok(format!("\"{}\"", s.as_ref().replace("\"", "\\\"")))
                } else {
                    bail!("Invalid string value")
                }
            }
            Expr::Number { ref value, .. } => Ok(value.to_json_str()?),
            Expr::Bool { ref value, .. } => {
                if let Ok(b) = value.as_bool() {
                    Ok(if *b {
                        "true".to_string()
                    } else {
                        "false".to_string()
                    })
                } else {
                    bail!("Invalid boolean value")
                }
            }
            Expr::Null { .. } => Ok("null".to_string()),

            // Variables and references
            Expr::Var { ref value, .. } => {
                if let Ok(var_name) = value.as_string() {
                    // Check if this is a bound variable
                    for binding in &self.variable_bindings {
                        if binding.0 == var_name.as_ref() {
                            return Ok(binding.1.clone());
                        }
                    }
                    Ok(var_name.as_ref().to_string())
                } else {
                    bail!("Invalid variable name")
                }
            }

            Expr::RefDot {
                ref refr,
                ref field,
                ..
            } => {
                let base = self.translate_expr(refr)?;
                let field_name = &field.0.text();
                Ok(format!("{}.{}", base, field_name))
            }

            Expr::RefBrack {
                ref refr,
                ref index,
                ..
            } => {
                let base = self.translate_expr(refr)?;
                let index_kql = self.translate_expr(index)?;
                Ok(format!("{}[{}]", base, index_kql))
            }

            // Collections
            Expr::Array { ref items, .. } => {
                let items_kql: Result<Vec<String>> =
                    items.iter().map(|item| self.translate_expr(item)).collect();
                Ok(format!("dynamic([{}])", items_kql?.join(", ")))
            }

            Expr::Set { ref items, .. } => {
                let items_kql: Result<Vec<String>> =
                    items.iter().map(|item| self.translate_expr(item)).collect();
                Ok(format!("dynamic([{}])", items_kql?.join(", ")))
            }

            Expr::Object { ref fields, .. } => {
                let mut field_parts = Vec::new();
                for field in fields {
                    let key_kql = self.translate_expr(&field.1)?;
                    let value_kql = self.translate_expr(&field.2)?;
                    field_parts.push(format!("{}: {}", key_kql, value_kql));
                }
                Ok(format!("dynamic({{{}}})", field_parts.join(", ")))
            }

            // Comprehensions
            Expr::ArrayCompr {
                ref term,
                ref query,
                ..
            } => self.translate_comprehension(term, query, "array"),

            Expr::SetCompr {
                ref term,
                ref query,
                ..
            } => self.translate_comprehension(term, query, "set"),

            // Arithmetic operations
            Expr::ArithExpr {
                ref lhs,
                ref rhs,
                ref op,
                ..
            } => {
                let lhs_kql = self.translate_expr(lhs)?;
                let rhs_kql = self.translate_expr(rhs)?;
                let op_kql = match *op {
                    ArithOp::Add => "+",
                    ArithOp::Sub => "-",
                    ArithOp::Mul => "*",
                    ArithOp::Div => "/",
                    ArithOp::Mod => "%",
                };
                Ok(format!("({} {} {})", lhs_kql, op_kql, rhs_kql))
            }

            // Boolean operations
            Expr::BoolExpr {
                ref lhs,
                ref rhs,
                ref op,
                ..
            } => {
                let lhs_kql = self.translate_expr(lhs)?;
                let rhs_kql = self.translate_expr(rhs)?;
                let op_kql = match *op {
                    BoolOp::Lt => "<",
                    BoolOp::Le => "<=",
                    BoolOp::Eq => "==",
                    BoolOp::Ge => ">=",
                    BoolOp::Gt => ">",
                    BoolOp::Ne => "!=",
                };
                Ok(format!("{} {} {}", lhs_kql, op_kql, rhs_kql))
            }

            // Set operations
            Expr::BinExpr {
                ref lhs,
                ref rhs,
                ref op,
                ..
            } => {
                let lhs_kql = self.translate_expr(lhs)?;
                let rhs_kql = self.translate_expr(rhs)?;
                match *op {
                    BinOp::Union => Ok(format!("array_concat({}, {})", lhs_kql, rhs_kql)),
                    BinOp::Intersection => Ok(format!("set_intersect({}, {})", lhs_kql, rhs_kql)),
                }
            }

            // Membership
            Expr::Membership {
                ref value,
                ref collection,
                ref key,
                ..
            } => {
                let value_kql = self.translate_expr(value)?;
                let collection_kql = self.translate_expr(collection)?;

                if let Some(ref key_expr) = *key {
                    let key_kql = self.translate_expr(key_expr)?;
                    Ok(format!(
                        "({}, {}) in {}",
                        key_kql, value_kql, collection_kql
                    ))
                } else {
                    Ok(format!("{} in {}", value_kql, collection_kql))
                }
            }

            // Unary expressions
            Expr::UnaryExpr { ref expr, .. } => {
                let inner = self.translate_expr(expr)?;
                Ok(format!("-({})", inner))
            }

            // Unsupported in database subset
            Expr::Call { .. } => {
                bail!("Function calls are not supported in database subset")
            }

            Expr::ObjectCompr { .. } => {
                bail!("Object comprehensions are not supported in database subset")
            }

            #[cfg(feature = "rego-extensions")]
            Expr::OrExpr {
                ref lhs, ref rhs, ..
            } => {
                let lhs_kql = self.translate_expr(lhs)?;
                let rhs_kql = self.translate_expr(rhs)?;
                Ok(format!("({} or {})", lhs_kql, rhs_kql))
            }

            _ => bail!("Unsupported expression type for KQL translation"),
        }
    }

    /// Translate comprehensions to KQL subqueries
    fn translate_comprehension(
        &self,
        term: &Ref<Expr>,
        query: &Ref<Query>,
        comp_type: &str,
    ) -> Result<String> {
        // For now, create a placeholder - full comprehension translation
        // would require more complex KQL subquery generation
        let term_kql = self.translate_expr(term)?;

        // Simple case: if it's just a variable binding and filter
        if query.stmts.len() <= 2 {
            if comp_type == "array" {
                Ok(format!("make_list({})", term_kql))
            } else {
                Ok(format!("make_set({})", term_kql))
            }
        } else {
            bail!("Complex comprehensions require subquery support")
        }
    }

    /// Extract rule name from reference expression
    fn extract_rule_name(refr: &Ref<Expr>) -> Result<String> {
        match *refr.as_ref() {
            Expr::Var { ref value, .. } => {
                if let Ok(name) = value.as_string() {
                    Ok(name.as_ref().to_string())
                } else {
                    bail!("Invalid rule name")
                }
            }
            Expr::RefDot {
                ref refr,
                ref field,
                ..
            } => {
                let base = Self::extract_rule_name(refr)?;
                Ok(format!("{}_{}", base, field.0.text()))
            }
            _ => bail!("Unsupported rule name format"),
        }
    }

    /// Extract variable name from expression
    fn extract_variable_name(expr: &Ref<Expr>) -> Result<String> {
        match *expr.as_ref() {
            Expr::Var { ref value, .. } => {
                if let Ok(name) = value.as_string() {
                    Ok(name.as_ref().to_string())
                } else {
                    bail!("Invalid variable name")
                }
            }
            _ => bail!("Expression is not a simple variable"),
        }
    }

    /// Translate a user query to KQL
    pub fn translate_user_query(&mut self, query: &Ref<Query>) -> Result<String> {
        self.query_parts.clear();
        self.query_parts.push(self.base_table.clone());

        self.translate_query_body(query)?;

        Ok(self.query_parts.join("\n| "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{unstable::DatabaseParser, Source};

    fn parse_and_translate(rego_code: &str, table_name: &str) -> Result<Vec<String>> {
        let source = Source::from_contents("test.rego".to_string(), rego_code.to_string())?;
        let mut parser = DatabaseParser::new(&source)?;
        let module = parser.parse_database_module()?;

        let mut translator = KqlTranslator::new(table_name.to_string());
        translator.translate_module(&module)
    }

    #[test]
    fn test_simple_boolean_rule() -> anyhow::Result<()> {
        let rego = r#"
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

        let queries = parse_and_translate(rego, "users")?;
        anyhow::ensure!(
            queries.len() == 1,
            "expected 1 query, got {}",
            queries.len()
        );
        let first = queries
            .first()
            .ok_or_else(|| anyhow::anyhow!("expected query"))?;
        anyhow::ensure!(first.contains("role == \"admin\""), "expected role filter");
        anyhow::ensure!(first.contains("active == true"), "expected active filter");
        Ok(())
    }

    #[test]
    fn test_assignment_rule() -> anyhow::Result<()> {
        let rego = r#"
            package test

            import rego.v1

            premium_users contains result if {
                some user in data.users
                user.score > 100
                result := {
                    "name": user.name,
                    "level": "premium"
                }
            }
        "#;

        let queries = parse_and_translate(rego, "users")?;
        anyhow::ensure!(
            queries.len() == 1,
            "expected 1 query, got {}",
            queries.len()
        );
        let first = queries
            .first()
            .ok_or_else(|| anyhow::anyhow!("expected query"))?;
        anyhow::ensure!(first.contains("score > 100"), "expected score filter");
        Ok(())
    }

    #[test]
    fn test_set_membership() -> anyhow::Result<()> {
        let rego = r#"
            package test

            import rego.v1

            valid_users contains result if {
                some user in data.users
                user.role in {"admin", "user", "guest"}
                result := {
                    "name": user.name,
                    "role": user.role
                }
            }
        "#;

        let queries = parse_and_translate(rego, "users")?;
        anyhow::ensure!(
            queries.len() == 1,
            "expected 1 query, got {}",
            queries.len()
        );
        let first = queries
            .first()
            .ok_or_else(|| anyhow::anyhow!("expected query"))?;
        anyhow::ensure!(first.contains("in"), "expected 'in' operator");
        Ok(())
    }
}
