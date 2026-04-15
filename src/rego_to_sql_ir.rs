// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Rego to SQL IR Translator
//!
//! This module translates database-friendly Rego subset to SQL Intermediate Representation.
//! It converts Rego AST nodes to SQL IR structures that can then be compiled to SQL or
//! optimized further.

use crate::ast::*;
use crate::number::Number;
use crate::sql_ir::*;
use crate::value::Value;

use crate::alloc::{boxed::Box, format, string::String, string::ToString, vec, vec::Vec};
use anyhow::{bail, Result};
/// Translator from Rego to SQL IR
#[derive(Debug)]
pub struct RegoToSqlIrTranslator {
    /// Default table name to use when not specified
    default_table: Option<String>,
    /// Variables in scope for the current translation
    variables: Vec<String>,
    /// Variables that represent table entities
    table_variables: Vec<String>,
    /// Tables we've seen - each entry tracks (table_name, var_name)
    tables_seen: Vec<(String, String)>,
    /// Conditions collected during translation
    conditions: Vec<SqlExpression>,
    /// Intermediate variable assignments (e.g. `t := role.age + 10`)
    variable_assignments: std::collections::HashMap<String, SqlExpression>,
    /// Columns known to be arrays (identified via numeric RefBrack indexing in pre-scan)
    array_columns: std::collections::HashSet<String>,
    /// Bound values for global `input` paths
    input_bindings: std::collections::HashMap<String, SqlInputValue>,
}

impl RegoToSqlIrTranslator {
    pub fn new(default_table: Option<String>) -> Self {
        Self {
            default_table,
            variables: Vec::new(),
            table_variables: Vec::new(),
            tables_seen: Vec::new(),
            conditions: Vec::new(),
            variable_assignments: std::collections::HashMap::new(),
            array_columns: std::collections::HashSet::new(),
            input_bindings: std::collections::HashMap::new(),
        }
    }

    pub fn with_default_table(mut self, table: String) -> Self {
        self.default_table = Some(table);
        self
    }

    pub fn with_input_bindings(
        mut self,
        bindings: std::collections::HashMap<String, SqlInputValue>,
    ) -> Self {
        self.input_bindings = bindings;
        self
    }

    pub fn with_input_binding(mut self, path: String, value: SqlInputValue) -> Self {
        self.input_bindings.insert(path, value);
        self
    }

    /// Translate a Rego rule to SQL IR
    pub fn translate_rule(&mut self, rule: &Rule) -> Result<SqlQuery> {
        match rule {
            Rule::Spec { head, bodies, .. } => {
                self.validate_rule_pattern(head, bodies)?;
                self.translate_rule_spec(head, bodies)
            }
            Rule::Default { .. } => {
                bail!("Default rules not supported in SQL translation")
            }
        }
    }

    /// Validate that the rule follows the expected pattern
    fn validate_rule_pattern(&self, head: &RuleHead, bodies: &[RuleBody]) -> Result<()> {
        match head {
            RuleHead::Set { .. } => {
                // Check that at least one body contains "some var in table"
                let has_some_in = bodies.iter().any(|body| {
                    body.query
                        .stmts
                        .iter()
                        .any(|stmt| matches!(stmt.literal, Literal::SomeIn { .. }))
                });

                if !has_some_in {
                    bail!("SQL translation requires at least one 'some var in table' statement");
                }
                Ok(())
            }
            _ => {
                bail!("Only 'rule_name contains var if {{ ... }}' rule patterns are supported for SQL translation");
            }
        }
    }

    /// Translate a rule specification to SQL IR
    fn translate_rule_spec(&mut self, _head: &RuleHead, bodies: &[RuleBody]) -> Result<SqlQuery> {
        // Reset state for each rule
        self.tables_seen.clear();
        self.conditions.clear();
        self.table_variables.clear();
        self.variables.clear();
        self.variable_assignments.clear();
        self.array_columns.clear();

        // We only handle single-body rules for simplicity
        if bodies.len() != 1 {
            bail!("Only single-body rules are supported for SQL translation");
        }

        let body = &bodies[0];

        // Step 1 (pass 1): Scan all SomeIn statements to collect every table before
        // translating any expressions. This ensures that conditions written before a
        // second `some` binding still get the correct table-aliased column references.
        let mut source_table = String::new();
        for stmt in &body.query.stmts {
            if let Literal::SomeIn {
                value, collection, ..
            } = &stmt.literal
            {
                let var_name = self.extract_var_name(value)?;
                let table_name = self.extract_table_name(collection)?;
                self.table_variables.push(var_name.clone());
                self.variables.push(var_name.clone());
                self.tables_seen.push((table_name.clone(), var_name));
                if source_table.is_empty() {
                    source_table = table_name;
                }
            }
        }

        // Pre-scan: walk the AST to find which columns are accessed as arrays (numeric index)
        // so that count(col) can be mapped to ARRAY_LENGTH vs LENGTH.
        let mut array_cols = std::collections::HashSet::new();
        for stmt in &body.query.stmts {
            if let Literal::Expr { expr, .. } = &stmt.literal {
                Self::collect_array_columns_in_expr(expr, &mut array_cols);
            }
        }
        self.array_columns = array_cols;

        // Step 2 (pass 2): Now translate all non-SomeIn statements with full table info.
        let mut projections = Vec::new();
        for stmt in &body.query.stmts {
            if !matches!(&stmt.literal, Literal::SomeIn { .. }) {
                self.process_statement(stmt, &mut source_table, &mut projections)?;
            }
        }

        // Step 3: Process assignments (for projections)
        if let Some(assign) = &body.assign {
            self.process_assignment_value(&assign.value, &mut projections)?;
        }

        // Step 3: Determine source table and set up JOINs
        let final_source = if let Some(table) = &self.default_table {
            if source_table.is_empty() {
                table.clone()
            } else {
                source_table
            }
        } else {
            if source_table.is_empty() {
                bail!("No table found in rule and no default table specified");
            }
            source_table
        };

        // Step 4: Build query with JOIN support.
        //
        // Aliases are derived from variable names (not table names) so that self-joins
        // work correctly: `some employee in data.Employees; some manager in data.Employees`
        // → aliases "e" and "m", not both "e".
        //
        // Alias rule: concatenate the first character of each `_`-separated word in the
        // variable name.  Examples:
        //   user             → u
        //   role_assignment  → ra
        //   employee         → e
        //   manager          → m
        let var_aliases: std::collections::HashMap<String, String> = self
            .tables_seen
            .iter()
            .map(|(_, var_name)| (var_name.clone(), Self::derive_alias(var_name)))
            .collect();

        // A set of all known aliases (used for join-condition detection).
        let all_aliases: std::collections::HashSet<String> =
            var_aliases.values().cloned().collect();

        // Extract JOIN conditions from regular conditions.
        let (join_conditions, where_conditions): (Vec<_>, Vec<_>) = self
            .conditions
            .iter()
            .partition(|cond| self.is_join_condition(cond, &all_aliases));

        // Build FROM clause – only add alias for multi-table queries.
        let main_var = self
            .tables_seen
            .first()
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        let main_alias = var_aliases.get(main_var).map(|s| s.as_str()).unwrap_or("");
        let from_clause = if self.tables_seen.len() > 1 && !main_alias.is_empty() {
            format!("{} {}", final_source, main_alias)
        } else {
            final_source.clone()
        };

        let mut query_builder = SqlQueryBuilder::new().from_table(&from_clause);

        // Add JOINs for every table after the first.
        for (idx, (table_name, var_name)) in self.tables_seen.iter().enumerate().skip(1) {
            let alias = var_aliases.get(var_name).map(|s| s.as_str()).unwrap_or("");
            let join_source = if !alias.is_empty() {
                format!("{} {}", table_name, alias)
            } else {
                table_name.clone()
            };

            // A join condition belongs to this JOIN's ON clause iff:
            //   1. it references this variable's alias, AND
            //   2. no variable that appears *later* in tables_seen is also referenced.
            let table_join_conditions: Vec<_> = join_conditions
                .iter()
                .filter(|cond| self.is_condition_for_var(cond, idx, &var_aliases))
                .map(|cond| self.extract_join_condition(cond, idx, &var_aliases))
                .collect::<Result<Vec<_>>>()?;

            query_builder =
                query_builder.join(SqlJoinKind::Inner, &join_source, table_join_conditions);
        }

        // Add WHERE conditions (excluding JOIN conditions)
        if !where_conditions.is_empty() {
            let where_conditions_owned: Vec<SqlExpression> =
                where_conditions.into_iter().cloned().collect();
            let where_expr = self.combine_conditions(&where_conditions_owned);
            query_builder = query_builder.where_clause(where_expr);
        }

        // Add projections
        if !projections.is_empty() {
            query_builder = query_builder.project(projections);
        }

        query_builder.build().map_err(|e| anyhow::anyhow!(e))
    }

    /// Translate a RefDot expression (possibly nested) into the correct SQL.
    ///
    /// For direct table-variable field access (`user.name`) this returns a plain Column.
    /// For nested JSON-path access (`user.permissions.read` or deeper) this builds
    /// `column->'key1'->'key2'->>'lastKey'` using internal `json_extract` (→) and
    /// `json_extract_text` (->>) function names that the codegen renders correctly.
    fn translate_refdot_chain(&self, expr: &Expr) -> Result<SqlExpression> {
        if let Some(path) = Self::extract_input_path(expr)? {
            return self.resolve_input_path(&path);
        }

        // Collect the base column expression and all field names in order.
        let (base, fields) = self.collect_refdot_parts(expr)?;

        if fields.is_empty() {
            // Direct table-var field access already resolved to a column.
            return Ok(base);
        }

        // Build the JSON path chain.
        // All intermediate levels use json_extract  (→  returns JSON/JSONB).
        // The final level uses json_extract_text    (→→ returns TEXT).
        let mut result = base;
        let last_idx = fields.len() - 1;
        for (i, field_name) in fields.iter().enumerate() {
            let func_name = if i == last_idx {
                "json_extract_text"
            } else {
                "json_extract"
            };
            result = SqlExpression::Function {
                name: func_name.to_string(),
                args: vec![
                    result,
                    SqlExpression::Literal(SqlLiteral::String(field_name.clone())),
                ],
            };
        }
        Ok(result)
    }

    /// Recursively decompose a (possibly nested) RefDot into a base SQL expression and
    /// a list of field names that form the JSON path.
    ///
    /// Returns `(base_expr, field_path)` where `base_expr` is either a Column (for a
    /// direct table-variable access) or any other SQL expression, and `field_path` is
    /// the list of JSON keys that still need to be applied.
    fn collect_refdot_parts(&self, expr: &Expr) -> Result<(SqlExpression, Vec<String>)> {
        match expr {
            Expr::RefDot { refr, field, .. } => {
                let field_name = match &field.1 {
                    Value::String(s) => s.to_string(),
                    _ => bail!("Field name must be a string"),
                };

                // Direct table-variable access (innermost refr is a known table var).
                if let Expr::Var { value, .. } = refr.as_ref() {
                    let var_name = value
                        .as_string()
                        .map_err(|_| anyhow::anyhow!("Invalid variable name"))?;
                    let var_str = var_name.as_ref();

                    if self.table_variables.contains(&var_str.to_string()) {
                        // Build the base column expression (with alias for multi-table).
                        let col = if self.tables_seen.len() == 1 {
                            SqlExpression::column(&field_name)
                        } else {
                            let alias = Self::derive_alias(var_str);
                            SqlExpression::column(&format!("{}.{}", alias, field_name))
                        };
                        // No further JSON fields to apply.
                        return Ok((col, vec![]));
                    }
                }

                // Recurse into the inner expression and append this field name.
                let (base, mut path) = self.collect_refdot_parts(refr)?;
                path.push(field_name);
                Ok((base, path))
            }
            other => {
                // Not a RefDot – translate and return with no additional fields.
                let sql_expr = self.translate_expression_to_sql(other)?;
                Ok((sql_expr, vec![]))
            }
        }
    }

    /// Pre-scan an expression to find columns accessed with numeric array indices.
    /// These are later used to map `count(col)` → `ARRAY_LENGTH(col)`.
    fn collect_array_columns_in_expr(expr: &Expr, result: &mut std::collections::HashSet<String>) {
        match expr {
            Expr::RefBrack { refr, index, .. } => {
                if matches!(index.as_ref(), Expr::Number { .. }) {
                    if let Some(col_name) = Self::extract_last_field_name(refr) {
                        result.insert(col_name);
                    }
                }
                Self::collect_array_columns_in_expr(refr, result);
                Self::collect_array_columns_in_expr(index, result);
            }
            Expr::BoolExpr { lhs, rhs, .. }
            | Expr::ArithExpr { lhs, rhs, .. }
            | Expr::BinExpr { lhs, rhs, .. } => {
                Self::collect_array_columns_in_expr(lhs, result);
                Self::collect_array_columns_in_expr(rhs, result);
            }
            Expr::AssignExpr { lhs, rhs, .. } => {
                Self::collect_array_columns_in_expr(lhs, result);
                Self::collect_array_columns_in_expr(rhs, result);
            }
            Expr::Object { fields, .. } => {
                for (_, _, val) in fields {
                    Self::collect_array_columns_in_expr(val, result);
                }
            }
            Expr::Array { items, .. } | Expr::Set { items, .. } => {
                for item in items {
                    Self::collect_array_columns_in_expr(item, result);
                }
            }
            Expr::Call { params, .. } => {
                for param in params {
                    Self::collect_array_columns_in_expr(param, result);
                }
            }
            Expr::RefDot { refr, .. } => {
                Self::collect_array_columns_in_expr(refr, result);
            }
            Expr::UnaryExpr { expr, .. } => {
                Self::collect_array_columns_in_expr(expr, result);
            }
            _ => {}
        }
    }

    /// Extract the last field name from a chain of RefDot/RefBrack expressions.
    /// E.g. `user.tags` → `Some("tags")`, `user.tags[0]` → `Some("tags")`.
    fn extract_last_field_name(expr: &Expr) -> Option<String> {
        match expr {
            Expr::RefDot { field, .. } => match &field.1 {
                Value::String(s) => Some(s.to_string()),
                _ => None,
            },
            Expr::RefBrack { refr, .. } => Self::extract_last_field_name(refr),
            _ => None,
        }
    }

    fn extract_input_path(expr: &Expr) -> Result<Option<Vec<String>>> {
        match expr {
            Expr::Var { value, .. } => {
                let var_name = value
                    .as_string()
                    .map_err(|_| anyhow::anyhow!("Invalid variable name"))?;
                if var_name.as_ref() == "input" {
                    Ok(Some(Vec::new()))
                } else {
                    Ok(None)
                }
            }
            Expr::RefDot { refr, field, .. } => {
                let Some(mut path) = Self::extract_input_path(refr)? else {
                    return Ok(None);
                };
                let field_name = match &field.1 {
                    Value::String(s) => s.to_string(),
                    _ => bail!("Field name must be a string"),
                };
                path.push(field_name);
                Ok(Some(path))
            }
            Expr::RefBrack { refr, index, .. } => {
                let Some(mut path) = Self::extract_input_path(refr)? else {
                    return Ok(None);
                };
                let field_name = match index.as_ref() {
                    Expr::String { value, .. } => value
                        .as_string()
                        .map_err(|_| anyhow::anyhow!("Invalid input field name"))?
                        .as_ref()
                        .to_string(),
                    _ => bail!("input indexing requires a string literal key"),
                };
                path.push(field_name);
                Ok(Some(path))
            }
            _ => Ok(None),
        }
    }

    fn resolve_input_path(&self, path: &[String]) -> Result<SqlExpression> {
        let key = path.join(".");
        let Some(bound_value) = self.input_bindings.get(&key) else {
            if key.is_empty() {
                bail!("global `input` is not supported directly; bind a specific input path")
            } else {
                bail!("missing SQL input binding for `input.{}`", key)
            }
        };

        Ok(match bound_value {
            SqlInputValue::Literal(literal) => SqlExpression::Literal(literal.clone()),
            SqlInputValue::Variable(name) => SqlExpression::InjectedVariable(name.clone()),
        })
    }

    /// Extract a (potentially namespaced) function name from a call's `fcn` expression.
    /// Handles both plain `Var("name")` and dotted `RefDot(Var("ns"), "func")`.
    fn extract_function_name(fcn: &Expr) -> Result<String> {
        match fcn {
            Expr::Var { value, .. } => Ok(value
                .as_string()
                .map_err(|_| anyhow::anyhow!("Invalid function name"))?
                .as_ref()
                .to_string()),
            Expr::RefDot { refr, field, .. } => {
                let namespace = Self::extract_function_name(refr)?;
                let field_name = match &field.1 {
                    Value::String(s) => s.to_string(),
                    _ => bail!("Function field name must be a string"),
                };
                Ok(format!("{}.{}", namespace, field_name))
            }
            _ => bail!("Function name must be a simple identifier"),
        }
    }

    /// Returns true if a SQL expression is already a boolean predicate (no IS NOT NULL wrapping needed).
    fn is_boolean_expression(expr: &SqlExpression) -> bool {
        match expr {
            SqlExpression::Binary { op, .. } => matches!(
                op,
                SqlBinaryOp::Equal
                    | SqlBinaryOp::NotEqual
                    | SqlBinaryOp::LessThan
                    | SqlBinaryOp::LessThanOrEqual
                    | SqlBinaryOp::GreaterThan
                    | SqlBinaryOp::GreaterThanOrEqual
                    | SqlBinaryOp::And
                    | SqlBinaryOp::Or
                    | SqlBinaryOp::Like
                    | SqlBinaryOp::NotLike
                    | SqlBinaryOp::ILike
                    | SqlBinaryOp::NotILike
                    | SqlBinaryOp::In
                    | SqlBinaryOp::NotIn
                    | SqlBinaryOp::IsNull
                    | SqlBinaryOp::IsNotNull
                    | SqlBinaryOp::SimilarTo
                    | SqlBinaryOp::NotSimilarTo
                    | SqlBinaryOp::RegexMatch
            ),
            SqlExpression::Unary { op, .. } => matches!(op, SqlUnaryOp::Not | SqlUnaryOp::Exists),
            SqlExpression::Literal(SqlLiteral::Boolean(_)) => true,
            _ => false,
        }
    }

    /// Derive a short SQL alias from a variable name.
    /// Concatenates the first character of each `_`-separated part:
    ///   `user` → `u`, `role_assignment` → `ra`, `employee` → `e`.
    fn derive_alias(var_name: &str) -> String {
        var_name
            .split('_')
            .filter_map(|part| part.chars().next())
            .collect::<String>()
            .to_lowercase()
    }

    /// Check if a condition is a JOIN condition (equijoin between two table-aliased columns).
    fn is_join_condition(
        &self,
        cond: &SqlExpression,
        all_aliases: &std::collections::HashSet<String>,
    ) -> bool {
        match cond {
            SqlExpression::Binary {
                op: SqlBinaryOp::Equal,
                left,
                right,
            } => match (left.as_ref(), right.as_ref()) {
                (SqlExpression::Column(left_col), SqlExpression::Column(right_col)) => {
                    self.col_has_known_alias(left_col, all_aliases)
                        && self.col_has_known_alias(right_col, all_aliases)
                }
                _ => false,
            },
            _ => false,
        }
    }

    /// Check whether a dotted column reference (e.g. "u.id") has a prefix that is a
    /// known table alias.
    fn col_has_known_alias(
        &self,
        col: &str,
        all_aliases: &std::collections::HashSet<String>,
    ) -> bool {
        col.split('.')
            .next()
            .map_or(false, |prefix| all_aliases.contains(prefix))
    }

    /// Check if a join condition belongs to the ON clause of the variable at `var_idx`
    /// in `tables_seen`.
    ///
    /// Rules:
    /// 1. The condition must reference this variable's alias.
    /// 2. No variable with a *higher* index (appearing later in join order) is also
    ///    referenced — if it were, the condition belongs to that later JOIN.
    fn is_condition_for_var(
        &self,
        cond: &SqlExpression,
        var_idx: usize,
        var_aliases: &std::collections::HashMap<String, String>,
    ) -> bool {
        let (_, var_name) = &self.tables_seen[var_idx];
        let alias = var_aliases.get(var_name).map(|s| s.as_str()).unwrap_or("");
        if alias.is_empty() || !self.expression_contains_table_alias(cond, alias) {
            return false;
        }
        // Ensure no later variable is also referenced.
        !self.tables_seen[var_idx + 1..]
            .iter()
            .any(|(_, later_var)| {
                let later_alias = var_aliases.get(later_var).map(|s| s.as_str()).unwrap_or("");
                !later_alias.is_empty() && self.expression_contains_table_alias(cond, later_alias)
            })
    }

    /// Recursively check if an expression contains a column reference with the given table alias
    fn expression_contains_table_alias(&self, expr: &SqlExpression, alias: &str) -> bool {
        match expr {
            SqlExpression::Column(name) => name.starts_with(&format!("{}.", alias)),
            SqlExpression::Binary { left, right, .. } => {
                self.expression_contains_table_alias(left, alias)
                    || self.expression_contains_table_alias(right, alias)
            }
            SqlExpression::Unary { operand, .. } => {
                self.expression_contains_table_alias(operand, alias)
            }
            SqlExpression::Function { args, .. } => args
                .iter()
                .any(|a| self.expression_contains_table_alias(a, alias)),
            _ => false,
        }
    }

    /// Extract a JOIN condition from a SQL expression, ordering sides so that the
    /// column referencing the *earlier* table (lower index in tables_seen) is on the left.
    fn extract_join_condition(
        &self,
        cond: &SqlExpression,
        var_idx: usize,
        var_aliases: &std::collections::HashMap<String, String>,
    ) -> Result<SqlJoinCondition> {
        match cond {
            SqlExpression::Binary {
                op: SqlBinaryOp::Equal,
                left,
                right,
            } => {
                // If the LEFT side references the current (later) variable, swap so that
                // the earlier-table column ends up on the left.
                let current_alias = var_aliases
                    .get(&self.tables_seen[var_idx].1)
                    .map(|s| s.as_str())
                    .unwrap_or("");
                let left_is_current = self.expression_contains_table_alias(left, current_alias);
                if left_is_current {
                    Ok(SqlJoinCondition {
                        left: right.as_ref().clone(),
                        right: left.as_ref().clone(),
                        operator: SqlBinaryOp::Equal,
                    })
                } else {
                    Ok(SqlJoinCondition {
                        left: left.as_ref().clone(),
                        right: right.as_ref().clone(),
                        operator: SqlBinaryOp::Equal,
                    })
                }
            }
            _ => bail!("Only equality conditions are supported for JOINs"),
        }
    }

    /// Process a single statement
    fn process_statement(
        &mut self,
        stmt: &LiteralStmt,
        _source_table: &mut String,
        projections: &mut Vec<SqlColumn>,
    ) -> Result<()> {
        match &stmt.literal {
            Literal::SomeIn { .. } => {
                // Already handled in pass 1 of translate_rule_spec; nothing to do here.
            }
            Literal::SomeVars { .. } => {
                // Skip variable declarations
            }
            Literal::Every { .. } => {
                bail!("'every' statements are not supported in SQL translation");
            }
            Literal::Expr { expr, .. } => {
                if let Expr::AssignExpr { lhs, rhs, .. } = expr.as_ref() {
                    // Object rhs → extract projections (result := { ... })
                    self.process_assignment_value(rhs, projections)?;

                    // Non-object rhs with a simple Var lhs → intermediate variable binding
                    // e.g. `t := role.age + 10`
                    if !matches!(rhs.as_ref(), Expr::Object { .. }) {
                        if let Expr::Var { value, .. } = lhs.as_ref() {
                            let var_name = value
                                .as_string()
                                .map_err(|_| anyhow::anyhow!("Invalid variable name"))?
                                .as_ref()
                                .to_string();
                            let sql_expr = self.translate_expression_to_sql(rhs)?;
                            self.variable_assignments.insert(var_name, sql_expr);
                        }
                    }
                } else {
                    // Regular expression/condition
                    let sql_expr = self.translate_expression_to_sql(expr)?;
                    // If the expression is not already a boolean predicate (e.g. a standalone
                    // function call like `base64.encode(x)` which is truthy when defined),
                    // wrap it in IS NOT NULL so the SQL is valid.
                    let condition = if Self::is_boolean_expression(&sql_expr) {
                        sql_expr
                    } else {
                        SqlExpression::Binary {
                            op: SqlBinaryOp::IsNotNull,
                            left: Box::new(sql_expr),
                            right: Box::new(SqlExpression::Literal(SqlLiteral::Null)),
                        }
                    };
                    self.conditions.push(condition);
                }
            }
            Literal::NotExpr { expr, .. } => {
                // Process as negated expression
                let inner_expr = self.translate_expression_to_sql(expr)?;
                self.conditions.push(SqlExpression::Unary {
                    op: SqlUnaryOp::Not,
                    operand: Box::new(inner_expr),
                });
            }
        }
        Ok(())
    }

    /// Process assignment values to extract projections
    fn process_assignment_value(
        &mut self,
        rhs: &Expr,
        projections: &mut Vec<SqlColumn>,
    ) -> Result<()> {
        // Handle object literals in projections (result := {"field": table.field, ...})
        if let Expr::Object { fields, .. } = rhs {
            for (_span, key_expr, value_expr) in fields {
                // key_expr is the field name, value_expr is the value expression
                let field_name = match key_expr.as_ref() {
                    Expr::String { value, .. } => {
                        let s = value
                            .as_string()
                            .map_err(|_| anyhow::anyhow!("Invalid field name"))?;
                        s.as_ref().to_string()
                    }
                    _ => bail!("Projection field name must be a string literal"),
                };

                let field_expr = self.translate_expression_to_sql(value_expr.as_ref())?;

                // Set alias only when the unqualified column name differs from the field name.
                // For table-qualified refs like "u.age", compare just "age" against the field name.
                let alias = match &field_expr {
                    SqlExpression::Column(col_name) => {
                        let unqualified = col_name.rsplit('.').next().unwrap_or(col_name.as_str());
                        if unqualified == field_name {
                            None
                        } else {
                            Some(field_name.clone())
                        }
                    }
                    _ => Some(field_name.clone()),
                };

                projections.push(SqlColumn {
                    name: field_name,
                    expression: field_expr,
                    alias,
                });
            }
        }

        Ok(())
    }

    /// Extract variable name from an expression
    fn extract_var_name(&self, expr: &Expr) -> Result<String> {
        match expr {
            Expr::Var { value, .. } => Ok(value
                .as_string()
                .map_err(|_| anyhow::anyhow!("Invalid variable name"))?
                .as_ref()
                .to_string()),
            _ => {
                bail!("Expected variable name, got {:?}", expr)
            }
        }
    }

    /// Extract table name from a collection expression

    /// Extract table name from a collection expression
    fn extract_table_name(&self, expr: &Expr) -> Result<String> {
        match expr {
            Expr::RefDot { refr, field, .. } => {
                // Expecting: data.table_name
                if let Expr::Var { value, .. } = refr.as_ref() {
                    let var_name = value
                        .as_string()
                        .map_err(|_| anyhow::anyhow!("Invalid variable name"))?;
                    if var_name.as_ref() != "data" {
                        bail!("Collection must be of the form 'data.table_name'");
                    }
                }
                let field_value = match &field.1 {
                    Value::String(s) => s.to_string(),
                    _ => bail!("Field name must be a string"),
                };
                Ok(field_value)
            }
            _ => {
                bail!("Collection must be of the form 'data.table_name'");
            }
        }
    }

    /// Translate a Rego expression to SQL expression
    fn translate_expression_to_sql(&self, expr: &Expr) -> Result<SqlExpression> {
        match expr {
            // Membership expressions (x in set)
            Expr::Membership {
                value, collection, ..
            } => {
                let left = self.translate_expression_to_sql(value)?;
                let right = self.translate_expression_to_sql(collection)?;

                // Convert set/array to SQL IN expression
                match right {
                    SqlExpression::Array(items) => Ok(SqlExpression::Binary {
                        op: SqlBinaryOp::In,
                        left: Box::new(left),
                        right: Box::new(SqlExpression::Array(items)),
                    }),
                    _ => {
                        bail!("IN operation requires an array/set on the right side");
                    }
                }
            }

            // Boolean expressions (comparisons)
            Expr::BoolExpr { op, lhs, rhs, .. } => {
                // Handle NULL comparisons specially
                // In SQL, NULL comparisons use IS NULL or IS NOT NULL instead of = NULL or != NULL
                if let Expr::Null { .. } = rhs.as_ref() {
                    let left = self.translate_expression_to_sql(lhs)?;
                    match op {
                        BoolOp::Eq => {
                            return Ok(SqlExpression::Binary {
                                op: SqlBinaryOp::IsNull,
                                left: Box::new(left),
                                right: Box::new(SqlExpression::Literal(SqlLiteral::Null)),
                            });
                        }
                        BoolOp::Ne => {
                            return Ok(SqlExpression::Binary {
                                op: SqlBinaryOp::IsNotNull,
                                left: Box::new(left),
                                right: Box::new(SqlExpression::Literal(SqlLiteral::Null)),
                            });
                        }
                        _ => {
                            // Other operators with NULL are not typically valid, but we'll translate them anyway
                            let right = self.translate_expression_to_sql(rhs)?;
                            let sql_op = self.translate_bool_op(op)?;
                            return Ok(SqlExpression::Binary {
                                op: sql_op,
                                left: Box::new(left),
                                right: Box::new(right),
                            });
                        }
                    }
                }

                // Normal boolean expression
                let left = self.translate_expression_to_sql(lhs)?;

                // If the left side is a JSON text extraction (->>'key'), boolean literals on the
                // right must be compared as strings ('true'/'false'), because PostgreSQL's ->>
                // operator returns TEXT, not BOOLEAN.
                let is_json_text = matches!(&left, SqlExpression::Function { name, .. } if name == "json_extract_text");
                let right = if is_json_text {
                    match rhs.as_ref() {
                        Expr::Bool {
                            value: Value::Bool(b),
                            ..
                        } => SqlExpression::Literal(SqlLiteral::String(
                            if *b { "true" } else { "false" }.to_string(),
                        )),
                        _ => self.translate_expression_to_sql(rhs)?,
                    }
                } else {
                    self.translate_expression_to_sql(rhs)?
                };

                let sql_op = self.translate_bool_op(op)?;
                Ok(SqlExpression::Binary {
                    op: sql_op,
                    left: Box::new(left),
                    right: Box::new(right),
                })
            }

            // Arithmetic expressions
            Expr::ArithExpr { op, lhs, rhs, .. } => {
                let left = self.translate_expression_to_sql(lhs)?;
                let right = self.translate_expression_to_sql(rhs)?;
                let sql_op = self.translate_arith_op(op)?;
                // Preserve operator precedence with explicit parentheses
                let left = Self::parenthesize_if_lower_precedence(left, op, true);
                let right = Self::parenthesize_if_lower_precedence(right, op, false);
                Ok(SqlExpression::Binary {
                    op: sql_op,
                    left: Box::new(left),
                    right: Box::new(right),
                })
            }

            // Binary expressions (set operations)
            Expr::BinExpr { op, lhs, rhs, .. } => {
                let left = self.translate_expression_to_sql(lhs)?;
                let right = self.translate_expression_to_sql(rhs)?;
                let sql_op = self.translate_bin_op(op)?;
                Ok(SqlExpression::Binary {
                    op: sql_op,
                    left: Box::new(left),
                    right: Box::new(right),
                })
            }

            // Variables and field access
            Expr::Var { value, .. } => {
                let var_name = value
                    .as_string()
                    .map_err(|_| anyhow::anyhow!("Invalid variable name"))?;
                if var_name.as_ref() == "input" {
                    return self.resolve_input_path(&[]);
                }
                // Substitute intermediate variable bindings (e.g. `t := role.age + 10`)
                if let Some(assigned) = self.variable_assignments.get(var_name.as_ref()) {
                    return Ok(assigned.clone());
                }
                Ok(SqlExpression::column(var_name.as_ref()))
            }

            Expr::RefDot { .. } => {
                // Use a chain-aware helper so that multi-level JSON access like
                // `user.profile.settings.notifications` generates the correct
                // `profile->'settings'->>'notifications'` chain.
                self.translate_refdot_chain(expr)
            }

            // Literals
            Expr::String { value, .. } => {
                let string_val = value
                    .as_string()
                    .map_err(|_| anyhow::anyhow!("Invalid string value"))?;
                Ok(SqlExpression::Literal(SqlLiteral::String(
                    string_val.as_ref().to_string(),
                )))
            }
            Expr::Number { value, .. } => match value {
                Value::Number(n) => match n {
                    // Preserve float literals even when mathematically whole (e.g. 2.0 ≠ 2).
                    Number::Float(f) => Ok(SqlExpression::Literal(SqlLiteral::Float(*f))),
                    _ => {
                        if n.is_integer() {
                            Ok(SqlExpression::Literal(SqlLiteral::Integer(
                                n.as_i64().unwrap_or(0),
                            )))
                        } else {
                            Ok(SqlExpression::Literal(SqlLiteral::Float(
                                n.as_f64().unwrap_or(0.0),
                            )))
                        }
                    }
                },
                _ => bail!("Invalid number value"),
            },

            // Boolean literals
            Expr::Bool { value, .. } => match value {
                Value::Bool(b) => Ok(SqlExpression::Literal(SqlLiteral::Boolean(*b))),
                _ => bail!("Invalid boolean value"),
            },

            Expr::Null { .. } => Ok(SqlExpression::Literal(SqlLiteral::Null)),

            // Unary minus (-expr)
            Expr::UnaryExpr { expr, .. } => {
                let operand = self.translate_expression_to_sql(expr)?;
                Ok(SqlExpression::Unary {
                    op: SqlUnaryOp::Negate,
                    operand: Box::new(operand),
                })
            }

            // Function calls (handles both plain names and namespaced like array.concat)
            Expr::Call { fcn, params, .. } => {
                let func_name = Self::extract_function_name(fcn)?;

                let sql_args: Result<Vec<SqlExpression>> = params
                    .iter()
                    .map(|arg| self.translate_expression_to_sql(arg))
                    .collect();
                let args = sql_args?;

                match func_name.as_str() {
                    // ── is_string / is_number ──────────────────────────────────────────
                    "is_string" if args.len() == 1 => Ok(SqlExpression::Binary {
                        op: SqlBinaryOp::Equal,
                        left: Box::new(SqlExpression::Function {
                            name: "TYPEOF".to_string(),
                            args: vec![args.into_iter().next().unwrap()],
                        }),
                        right: Box::new(SqlExpression::Literal(SqlLiteral::String(
                            "text".to_string(),
                        ))),
                    }),
                    "is_number" if args.len() == 1 => {
                        let typeof_expr = SqlExpression::Function {
                            name: "TYPEOF".to_string(),
                            args: vec![args.into_iter().next().unwrap()],
                        };
                        Ok(SqlExpression::Binary {
                            op: SqlBinaryOp::Or,
                            left: Box::new(SqlExpression::Binary {
                                op: SqlBinaryOp::Equal,
                                left: Box::new(typeof_expr.clone()),
                                right: Box::new(SqlExpression::Literal(SqlLiteral::String(
                                    "integer".to_string(),
                                ))),
                            }),
                            right: Box::new(SqlExpression::Binary {
                                op: SqlBinaryOp::Equal,
                                left: Box::new(typeof_expr),
                                right: Box::new(SqlExpression::Literal(SqlLiteral::String(
                                    "real".to_string(),
                                ))),
                            }),
                        })
                    }
                    // ── is_null(x) → x IS NULL ────────────────────────────────────────
                    "is_null" if args.len() == 1 => Ok(SqlExpression::Binary {
                        op: SqlBinaryOp::IsNull,
                        left: Box::new(args.into_iter().next().unwrap()),
                        right: Box::new(SqlExpression::Literal(SqlLiteral::Null)),
                    }),
                    // ── count(x) → ARRAY_LENGTH or LENGTH depending on column type ────
                    "count" if args.len() == 1 => {
                        let is_array = match &args[0] {
                            SqlExpression::Column(col_name) => {
                                let unqualified =
                                    col_name.rsplit('.').next().unwrap_or(col_name.as_str());
                                self.array_columns.contains(unqualified)
                            }
                            _ => false,
                        };
                        let fn_name = if is_array { "ARRAY_LENGTH" } else { "LENGTH" };
                        Ok(SqlExpression::Function {
                            name: fn_name.to_string(),
                            args,
                        })
                    }
                    // ── sort(x) → ARRAY_SORT(x) ───────────────────────────────────────
                    "sort" if args.len() == 1 => Ok(SqlExpression::Function {
                        name: "ARRAY_SORT".to_string(),
                        args,
                    }),
                    // ── trim_left(x, cutset) → LTRIM(x)  (cutset ignored) ─────────────
                    "trim_left" if args.len() == 2 => Ok(SqlExpression::Function {
                        name: "LTRIM".to_string(),
                        args: vec![args.into_iter().next().unwrap()],
                    }),
                    "trim_right" if args.len() == 2 => Ok(SqlExpression::Function {
                        name: "RTRIM".to_string(),
                        args: vec![args.into_iter().next().unwrap()],
                    }),
                    // ── to_number(x) → CAST(x AS NUMERIC) ────────────────────────────
                    "to_number" if args.len() == 1 => Ok(SqlExpression::Cast {
                        expression: Box::new(args.into_iter().next().unwrap()),
                        target_type: SqlDataType::Numeric,
                    }),
                    // ── format_int(x, base) → CAST(x AS VARCHAR)  (base ignored) ─────
                    "format_int" if args.len() == 2 => Ok(SqlExpression::Cast {
                        expression: Box::new(args.into_iter().next().unwrap()),
                        target_type: SqlDataType::Varchar(None),
                    }),
                    // ── pow(base, exp) → POWER(base, exp) ────────────────────────────
                    "pow" if args.len() == 2 => Ok(SqlExpression::Function {
                        name: "POWER".to_string(),
                        args,
                    }),
                    // ── round(x) / round(x, n) → ROUND(x) / ROUND(x, n) ─────────────
                    "round" if args.len() == 1 || args.len() == 2 => Ok(SqlExpression::Function {
                        name: "ROUND".to_string(),
                        args,
                    }),
                    // ── sqrt(x) → SQRT(x) ─────────────────────────────────────────────
                    "sqrt" if args.len() == 1 => Ok(SqlExpression::Function {
                        name: "SQRT".to_string(),
                        args,
                    }),
                    // ── sin(x) → SIN(x) ───────────────────────────────────────────────
                    "sin" if args.len() == 1 => Ok(SqlExpression::Function {
                        name: "SIN".to_string(),
                        args,
                    }),
                    "cos" if args.len() == 1 => Ok(SqlExpression::Function {
                        name: "COS".to_string(),
                        args,
                    }),
                    "tan" if args.len() == 1 => Ok(SqlExpression::Function {
                        name: "TAN".to_string(),
                        args,
                    }),
                    // ── array.concat(a, b) → a || b ──────────────────────────────────
                    "array.concat" if args.len() == 2 => {
                        let mut it = args.into_iter();
                        let left = it.next().unwrap();
                        let right = it.next().unwrap();
                        Ok(SqlExpression::Binary {
                            op: SqlBinaryOp::Concat,
                            left: Box::new(left),
                            right: Box::new(right),
                        })
                    }
                    // ── array.reverse(a) → array_reverse(a) ──────────────────────────
                    "array.reverse" if args.len() == 1 => Ok(SqlExpression::Function {
                        name: "array_reverse".to_string(),
                        args,
                    }),
                    // ── array.slice(a, start, end_excl) → ARRAY_SLICE(a, start, end_excl-1) ─
                    "array.slice" if args.len() == 3 => {
                        let mut it = args.into_iter();
                        let arr = it.next().unwrap();
                        let start = it.next().unwrap();
                        let end = it.next().unwrap();
                        let end_inclusive = match &end {
                            SqlExpression::Literal(SqlLiteral::Integer(n)) => {
                                SqlExpression::Literal(SqlLiteral::Integer(n - 1))
                            }
                            _ => SqlExpression::Binary {
                                op: SqlBinaryOp::Subtract,
                                left: Box::new(end),
                                right: Box::new(SqlExpression::Literal(SqlLiteral::Integer(1))),
                            },
                        };
                        Ok(SqlExpression::Function {
                            name: "ARRAY_SLICE".to_string(),
                            args: vec![arr, start, end_inclusive],
                        })
                    }
                    // ── array.length(a) → ARRAY_LENGTH(a) ────────────────────────────
                    "array.length" if args.len() == 1 => Ok(SqlExpression::Function {
                        name: "ARRAY_LENGTH".to_string(),
                        args,
                    }),
                    // ── strings.reverse(a) → REVERSE(a) ──────────────────────────────
                    "strings.reverse" if args.len() == 1 => Ok(SqlExpression::Function {
                        name: "REVERSE".to_string(),
                        args,
                    }),
                    // ── regex.match(pattern, str) → str ~ pattern ─────────────────────
                    "regex.match" if args.len() == 2 => {
                        let mut it = args.into_iter();
                        let pattern = it.next().unwrap();
                        let string = it.next().unwrap();
                        Ok(SqlExpression::Binary {
                            op: SqlBinaryOp::RegexMatch,
                            left: Box::new(string),
                            right: Box::new(pattern),
                        })
                    }
                    // ── base64.encode(x) → ENCODE(x, 'BASE64') ───────────────────────
                    "base64.encode" if args.len() == 1 => Ok(SqlExpression::Function {
                        name: "ENCODE".to_string(),
                        args: vec![
                            args.into_iter().next().unwrap(),
                            SqlExpression::Literal(SqlLiteral::String("BASE64".to_string())),
                        ],
                    }),
                    // ── base64.decode(x) → DECODE(x, 'BASE64') ───────────────────────
                    "base64.decode" if args.len() == 1 => Ok(SqlExpression::Function {
                        name: "DECODE".to_string(),
                        args: vec![
                            args.into_iter().next().unwrap(),
                            SqlExpression::Literal(SqlLiteral::String("BASE64".to_string())),
                        ],
                    }),
                    // ── contains/startswith/endswith → LIKE binary predicates ─────────
                    // Translate these directly to Binary{Like} so is_boolean_expression
                    // recognises them as predicates and doesn't wrap them in IS NOT NULL.
                    "contains" if args.len() == 2 => {
                        let mut it = args.into_iter();
                        let haystack = it.next().unwrap();
                        let needle = it.next().unwrap();
                        let pattern = match &needle {
                            SqlExpression::Literal(SqlLiteral::String(s)) => {
                                SqlExpression::Literal(SqlLiteral::String(format!("%{}%", s)))
                            }
                            _ => SqlExpression::Function {
                                name: "CONCAT".to_string(),
                                args: vec![
                                    SqlExpression::Literal(SqlLiteral::String("%".to_string())),
                                    needle,
                                    SqlExpression::Literal(SqlLiteral::String("%".to_string())),
                                ],
                            },
                        };
                        Ok(SqlExpression::Binary {
                            op: SqlBinaryOp::Like,
                            left: Box::new(haystack),
                            right: Box::new(pattern),
                        })
                    }
                    "startswith" if args.len() == 2 => {
                        let mut it = args.into_iter();
                        let haystack = it.next().unwrap();
                        let needle = it.next().unwrap();
                        let pattern = match &needle {
                            SqlExpression::Literal(SqlLiteral::String(s)) => {
                                SqlExpression::Literal(SqlLiteral::String(format!("{}%", s)))
                            }
                            _ => SqlExpression::Function {
                                name: "CONCAT".to_string(),
                                args: vec![
                                    needle,
                                    SqlExpression::Literal(SqlLiteral::String("%".to_string())),
                                ],
                            },
                        };
                        Ok(SqlExpression::Binary {
                            op: SqlBinaryOp::Like,
                            left: Box::new(haystack),
                            right: Box::new(pattern),
                        })
                    }
                    "endswith" if args.len() == 2 => {
                        let mut it = args.into_iter();
                        let haystack = it.next().unwrap();
                        let needle = it.next().unwrap();
                        let pattern = match &needle {
                            SqlExpression::Literal(SqlLiteral::String(s)) => {
                                SqlExpression::Literal(SqlLiteral::String(format!("%{}", s)))
                            }
                            _ => SqlExpression::Function {
                                name: "CONCAT".to_string(),
                                args: vec![
                                    SqlExpression::Literal(SqlLiteral::String("%".to_string())),
                                    needle,
                                ],
                            },
                        };
                        Ok(SqlExpression::Binary {
                            op: SqlBinaryOp::Like,
                            left: Box::new(haystack),
                            right: Box::new(pattern),
                        })
                    }
                    _ => {
                        // All other functions (lower, upper, abs, floor, ceil, replace, etc.)
                        // are passed through to the codegen.
                        Ok(SqlExpression::Function {
                            name: self.translate_function_name(&func_name)?,
                            args,
                        })
                    }
                }
            }

            // Array subscript: a[0] → a[1] (convert 0-based Rego → 1-based SQL/PostgreSQL)
            Expr::RefBrack { refr, index, .. } => {
                if let Some(path) = Self::extract_input_path(expr)? {
                    return self.resolve_input_path(&path);
                }
                let arr_expr = self.translate_expression_to_sql(refr)?;
                let idx_expr = self.translate_expression_to_sql(index)?;
                // Increment integer literal indices; emit expr+1 for non-literals.
                let sql_index = match &idx_expr {
                    SqlExpression::Literal(SqlLiteral::Integer(n)) => {
                        SqlExpression::Literal(SqlLiteral::Integer(n + 1))
                    }
                    _ => SqlExpression::Binary {
                        op: SqlBinaryOp::Add,
                        left: Box::new(idx_expr),
                        right: Box::new(SqlExpression::Literal(SqlLiteral::Integer(1))),
                    },
                };
                Ok(SqlExpression::ArrayIndex {
                    expr: Box::new(arr_expr),
                    index: Box::new(sql_index),
                })
            }

            // Arrays (for IN operations)
            Expr::Array { items, .. } => {
                let sql_items: Result<Vec<SqlExpression>> = items
                    .iter()
                    .map(|item| self.translate_expression_to_sql(item))
                    .collect();
                Ok(SqlExpression::Array(sql_items?))
            }

            // Sets (treated as arrays for SQL purposes)
            Expr::Set { items, .. } => {
                let sql_items: Result<Vec<SqlExpression>> = items
                    .iter()
                    .map(|item| self.translate_expression_to_sql(item))
                    .collect();
                Ok(SqlExpression::Array(sql_items?))
            }

            // Object literals - for now, we handle these as structure projections
            // In a full implementation, this would generate JSON or structured types
            Expr::Object { fields: _, .. } => {
                // For SQL, object literals typically represent structured data
                // We'll create a column reference that represents the object structure
                bail!("Object literals in expressions are not yet supported for SQL translation");
            }

            _ => {
                bail!("Unsupported expression type: {:?}", expr);
            }
        }
    }

    /// Wrap a SQL expression in parentheses if it has lower arithmetic precedence
    /// than the parent operator, to preserve the semantics of the Rego expression.
    ///
    /// Rules:
    /// 1. Parent is `*`/`/`/`%` and child is `+`/`-` → always parens (different prec).
    /// 2. Right child of any left-associative parent:
    ///    - Parent is `*`/`/`/`%` and right child is any arith binary → parens
    ///      (`a * (b / c)` ≠ `a * b / c` due to left-to-right evaluation)
    ///    - Parent is `-` and right child is `+`/`-` → parens
    ///      (`a - (b + c)` ≠ `a - b + c`)
    fn parenthesize_if_lower_precedence(
        expr: SqlExpression,
        parent_op: &ArithOp,
        is_left: bool,
    ) -> SqlExpression {
        let parent_is_high = matches!(parent_op, ArithOp::Mul | ArithOp::Div | ArithOp::Mod);

        match &expr {
            SqlExpression::Binary {
                op: child_sql_op, ..
            } => {
                let child_is_arith = matches!(
                    child_sql_op,
                    SqlBinaryOp::Add
                        | SqlBinaryOp::Subtract
                        | SqlBinaryOp::Multiply
                        | SqlBinaryOp::Divide
                        | SqlBinaryOp::Modulo
                );
                if !child_is_arith {
                    return expr;
                }
                let child_is_high = matches!(
                    child_sql_op,
                    SqlBinaryOp::Multiply | SqlBinaryOp::Divide | SqlBinaryOp::Modulo
                );

                // Rule 1: parent high-prec, child low-prec → always parens
                if parent_is_high && !child_is_high {
                    return SqlExpression::Parenthesized(Box::new(expr));
                }

                // Rule 2: right-child cases (left-associativity means right subtrees need parens)
                if !is_left {
                    // Parent *, /, % and right child is any arith binary
                    if parent_is_high {
                        return SqlExpression::Parenthesized(Box::new(expr));
                    }
                    // Parent is - and right child is + or -
                    if matches!(parent_op, ArithOp::Sub) && !child_is_high {
                        return SqlExpression::Parenthesized(Box::new(expr));
                    }
                }
                expr
            }
            _ => expr,
        }
    }

    /// Translate a Rego boolean operator to SQL binary operator
    fn translate_bool_op(&self, op: &BoolOp) -> Result<SqlBinaryOp> {
        match op {
            BoolOp::Eq => Ok(SqlBinaryOp::Equal),
            BoolOp::Ne => Ok(SqlBinaryOp::NotEqual),
            BoolOp::Lt => Ok(SqlBinaryOp::LessThan),
            BoolOp::Le => Ok(SqlBinaryOp::LessThanOrEqual),
            BoolOp::Gt => Ok(SqlBinaryOp::GreaterThan),
            BoolOp::Ge => Ok(SqlBinaryOp::GreaterThanOrEqual),
        }
    }

    /// Translate a Rego arithmetic operator to SQL binary operator
    fn translate_arith_op(&self, op: &ArithOp) -> Result<SqlBinaryOp> {
        match op {
            ArithOp::Add => Ok(SqlBinaryOp::Add),
            ArithOp::Sub => Ok(SqlBinaryOp::Subtract),
            ArithOp::Mul => Ok(SqlBinaryOp::Multiply),
            ArithOp::Div => Ok(SqlBinaryOp::Divide),
            ArithOp::Mod => Ok(SqlBinaryOp::Modulo),
        }
    }

    /// Translate a Rego binary operator to SQL binary operator
    fn translate_bin_op(&self, op: &BinOp) -> Result<SqlBinaryOp> {
        match op {
            BinOp::Intersection => Ok(SqlBinaryOp::In),
            BinOp::Union => Ok(SqlBinaryOp::Or),
        }
    }

    /// Translate a Rego function name to SQL function name
    fn translate_function_name(&self, name: &str) -> Result<String> {
        match name {
            "lower" => Ok("LOWER".to_string()),
            "upper" => Ok("UPPER".to_string()),
            "abs" => Ok("ABS".to_string()),
            "floor" => Ok("FLOOR".to_string()),
            "ceil" => Ok("CEIL".to_string()),
            "trim" => Ok("TRIM".to_string()),
            "length" => Ok("LENGTH".to_string()),
            "replace" => Ok("REPLACE".to_string()),
            "concat" => Ok("CONCAT".to_string()),
            "sum" => Ok("SUM".to_string()),
            "avg" => Ok("AVG".to_string()),
            "min" => Ok("MIN".to_string()),
            "max" => Ok("MAX".to_string()),
            _ => Ok(name.to_string()), // Pass through unknown functions
        }
    }

    /// Combine multiple conditions with AND
    fn combine_conditions(&self, conditions: &[SqlExpression]) -> SqlExpression {
        if conditions.is_empty() {
            SqlExpression::Literal(SqlLiteral::Boolean(true))
        } else if conditions.len() == 1 {
            conditions[0].clone()
        } else {
            let mut result = conditions[0].clone();
            for condition in &conditions[1..] {
                result = SqlExpression::Binary {
                    op: SqlBinaryOp::And,
                    left: Box::new(result),
                    right: Box::new(condition.clone()),
                };
            }
            result
        }
    }
}

impl Default for RegoToSqlIrTranslator {
    fn default() -> Self {
        Self::new(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translator_creation() {
        let translator = RegoToSqlIrTranslator::new(Some("users".to_string()));
        assert_eq!(translator.default_table, Some("users".to_string()));
    }
}
