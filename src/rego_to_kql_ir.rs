// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Rego to KQL IR Translator
//!
//! This module translates database-friendly Rego subset to KQL Intermediate Representation.
//! It converts Rego AST nodes to KQL IR structures that can then be compiled to KQL or
//! optimized further.

use crate::ast::*;
use crate::kql_ir::*;
use crate::value::Value;

use crate::alloc::{boxed::Box, format, string::String, string::ToString, vec, vec::Vec};
use anyhow::{bail, Result};
use std::collections::BTreeSet;

#[cfg(feature = "std")]
use std::println;

#[cfg(not(feature = "std"))]
macro_rules! println {
    ($($arg:tt)*) => {
        // No-op for no_std environments
    };
}

/// Information about a table variable and its usage
#[derive(Debug, Clone)]
struct TableVarInfo {
    /// Order in which this var appears in the rule body
    order: usize,
    /// The table name this var iterates over
    table_name: String,
    /// Conditions that only involve this var (no other table vars)
    var_conditions: Vec<KqlExpression>,
    /// Join conditions involving this var and other table vars
    join_conditions: Vec<(String, String, KqlExpression)>, // (left_var, right_var, condition)
    /// Properties of this var that are used in the rego code
    used_properties: BTreeSet<String>,
}

/// Information about an assignment statement
#[derive(Debug, Clone)]
struct AssignmentInfo {
    /// The variable being assigned to
    var_name: String,
    /// The KQL expression for the assignment
    expression: KqlExpression,
    /// Variables this assignment depends on
    dependencies: Vec<String>,
    /// Whether the assignment is to an object literal
    is_object_assignment: bool,
}

/// Translator from Rego to KQL IR
#[derive(Debug)]
pub struct RegoToKqlIrTranslator {
    /// Default table name to use when not specified
    default_table: Option<String>,
    /// Variables in scope for the current translation
    variables: Vec<String>,
    /// Variables that represent table entities (should have their prefixes stripped in property access)
    table_variables: Vec<String>,
    /// Tables we've seen in SomeIn statements - each entry tracks (table_name, var_name)
    tables_seen: Vec<(String, String)>,
    /// Pending join conditions that need to be applied to the most recent join
    pending_join_conditions: Vec<KqlJoinCondition>,
    /// Current join index (to track which join we're building conditions for)
    current_join_index: usize,
    /// Map from table variable to table name for easier lookup
    table_var_to_table: std::collections::HashMap<String, String>,
    /// Track which table variables belong to the base table vs joins
    base_table_vars: std::collections::HashSet<String>,
    /// Conditions that apply to specific table variables (for generating filters in joins)
    table_var_filters: std::collections::HashMap<String, Vec<KqlExpression>>,
    /// Join conditions between tables (defer them until joins are created)
    deferred_join_conditions: Vec<(String, String, KqlExpression)>, // (left_var, right_var, condition)
    /// Cross-table conditions that should be applied after all joins (like employee.id != manager.id)
    deferred_cross_table_conditions: Vec<KqlExpression>,
    /// Deferred object assignments for Set rules
    deferred_object_assignments: Vec<(String, Vec<(String, KqlExpression)>)>, // (var_name, [(key, expr)])
}

impl RegoToKqlIrTranslator {
    pub fn new(default_table: Option<String>) -> Self {
        Self {
            default_table,
            variables: Vec::new(),
            table_variables: Vec::new(),
            tables_seen: Vec::new(),
            pending_join_conditions: Vec::new(),
            current_join_index: 0,
            table_var_to_table: std::collections::HashMap::new(),
            table_var_filters: std::collections::HashMap::new(),
            deferred_join_conditions: Vec::new(),
            deferred_cross_table_conditions: Vec::new(),
            base_table_vars: std::collections::HashSet::new(),
            deferred_object_assignments: Vec::new(),
        }
    }

    pub fn with_default_table(mut self, table: String) -> Self {
        self.default_table = Some(table);
        self
    }

    /// Translate a Rego rule to KQL IR
    pub fn translate_rule(&mut self, rule: &Rule) -> Result<KqlQuery> {
        match rule {
            Rule::Spec { head, bodies, .. } => {
                // Validate rule pattern before translation
                self.validate_rule_pattern(head, bodies)?;
                self.translate_rule_spec(head, bodies)
            }
            Rule::Default { .. } => {
                bail!("Default rules not supported in KQL translation")
            }
        }
    }

    /// Validate that the rule follows the single allowed pattern for database filtering
    fn validate_rule_pattern(&self, head: &RuleHead, bodies: &[RuleBody]) -> Result<()> {
        match head {
            RuleHead::Set { refr, .. } => {
                // Only allow filtering rules of the form: filtered_table contains var if { some var in table }
                self.validate_filtering_rule(refr, bodies)
            }
            _ => {
                bail!("Only 'filtered_table contains var if {{ ... }}' rule patterns are supported")
            }
        }
    }

    /// Validate that filtering rules follow the pattern: filtered_table contains var if { some var in table }
    fn validate_filtering_rule(&self, refr: &Ref<Expr>, bodies: &[RuleBody]) -> Result<()> {
        // For RuleHead::Set, the pattern "rule_name contains var" is represented as:
        // - refr: rule_name (simple Var)
        // - key: var (simple Var)
        // - The "contains" is implicit in the RuleHead::Set structure

        // Check that refr is a simple rule name (Var)
        match refr.as_ref() {
            Expr::Var { .. } => {
                // This is the expected pattern for Set rules
            }
            _ => {
                bail!("Rule head must be a simple rule name for 'contains' patterns");
            }
        }

        // Check that at least one body contains "some var in table"
        let has_some_in = bodies.iter().any(|body| {
            body.query
                .stmts
                .iter()
                .any(|stmt| matches!(stmt.literal, Literal::SomeIn { .. }))
        });

        if !has_some_in {
            bail!("Filtering rules must contain at least one 'some var in table' statement");
        }

        Ok(())
    }

    /// Validate that the variable following 'contains' is actually assigned in the rule body
    fn validate_contains_variable_assignment(
        &self,
        head: &RuleHead,
        assignments: &[AssignmentInfo],
    ) -> Result<()> {
        if let RuleHead::Set { key, .. } = head {
            // Extract the variable name from the key (the variable after "contains")
            if let Some(key_expr) = key {
                if let Some(contains_var_name) =
                    self.extract_variable_name_from_expr_opt(key_expr.as_ref())
                {
                    // Check if this variable is assigned in the rule body
                    let assignment = assignments
                        .iter()
                        .find(|assignment| assignment.var_name == contains_var_name);

                    if let Some(assignment_info) = assignment {
                        // Additional validation: the assignment must be to an object
                        if !assignment_info.is_object_assignment {
                            bail!(
                                "Variable '{}' following 'contains' must be assigned to an object literal. \
                                Example: {} := {{ \"field\": table_var.field, \"other\": table_var.other }}",
                                contains_var_name,
                                contains_var_name
                            );
                        }
                    } else {
                        bail!(
                            "Variable '{}' following 'contains' must be assigned in the rule body using ':=' syntax. \
                            Example: {} := {{ \"field\": table_var.field }}",
                            contains_var_name,
                            contains_var_name
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Extract variable name from expression, returning None if not a simple variable
    fn extract_variable_name_from_expr_opt(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Var { value, .. } => {
                if let Ok(var_name) = value.as_string() {
                    Some(var_name.as_ref().to_string())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Extract variable name from rule reference
    pub fn extract_variable_name_from_ref(&self, refr: &Ref<Expr>) -> Result<String> {
        // Extract the variable name from the reference
        match refr.as_ref() {
            Expr::Var { value, .. } => {
                let name = value
                    .as_string()
                    .map_err(|_| anyhow::anyhow!("Invalid variable name"))?;
                Ok(name.as_ref().to_string())
            }
            _ => bail!("Expected variable reference in rule head"),
        }
    }

    /// Translate a Rego query to KQL IR
    pub fn translate_query(&mut self, query: &Query) -> Result<KqlQuery> {
        let mut builder = KqlQueryBuilder::new();

        // Determine source table
        let table = self.extract_table_from_query(query)?;
        builder = builder.from_table(&table);

        // Process query statements
        for stmt in &query.stmts {
            builder = self.translate_literal_stmt(builder, stmt)?;
        }

        builder.build().map_err(|e| anyhow::anyhow!(e))
    }

    fn translate_rule_spec(&mut self, head: &RuleHead, bodies: &[RuleBody]) -> Result<KqlQuery> {
        // Reset state for each rule
        self.tables_seen.clear();
        self.pending_join_conditions.clear();
        self.current_join_index = 0;
        self.table_var_to_table.clear();
        self.table_var_filters.clear();
        self.deferred_join_conditions.clear();
        self.deferred_cross_table_conditions.clear();
        self.base_table_vars.clear();

        // Step 1: Analyze table variables and their usage
        let mut table_vars = self.analyze_table_variables(bodies)?;
        let var_order: Vec<String> = table_vars
            .iter()
            .enumerate()
            .map(|(_, var_info)| self.table_variables[var_info.order].clone())
            .collect();

        // Step 2: Analyze assignments
        let assignments = self.analyze_assignments(bodies, &mut table_vars, &var_order)?;

        // Step 3: Validate that contains variable is assigned (if applicable)
        self.validate_contains_variable_assignment(head, &assignments)?;

        // Step 4: Emit debugging information
        self.emit_debug_info(&table_vars, &assignments);

        // Step 5: Build KQL query based on analysis
        self.build_kql_from_analysis(head, bodies, &table_vars, &assignments)
    }

    /// Analyze all table variables and their usage patterns
    fn analyze_table_variables(&mut self, bodies: &[RuleBody]) -> Result<Vec<TableVarInfo>> {
        let mut table_vars = Vec::new();
        let mut var_order = Vec::new();

        // Step 1: Find all table variable declarations and their order
        for body in bodies {
            for stmt in &body.query.stmts {
                if let Literal::SomeIn {
                    value, collection, ..
                } = &stmt.literal
                {
                    if let Expr::Var {
                        value: var_value, ..
                    } = value.as_ref()
                    {
                        if let Ok(var_name) = var_value.as_string() {
                            let var_name_str = var_name.as_ref().to_string();
                            if let Some(table_name) =
                                self.extract_table_from_collection_expr(collection)?
                            {
                                var_order.push(var_name_str.clone());
                                table_vars.push(TableVarInfo {
                                    order: var_order.len() - 1,
                                    table_name: table_name.clone(),
                                    var_conditions: Vec::new(),
                                    join_conditions: Vec::new(),
                                    used_properties: BTreeSet::new(),
                                });

                                // Update internal tracking
                                self.table_variables.push(var_name_str.clone());
                                self.table_var_to_table
                                    .insert(var_name_str.clone(), table_name.clone());
                                self.tables_seen.push((table_name, var_name_str.clone()));

                                if table_vars.len() == 1 {
                                    self.base_table_vars.insert(var_name_str);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Step 2: Analyze conditions and categorize them, also extract used properties
        for body in bodies {
            for stmt in &body.query.stmts {
                if let Literal::Expr { expr, .. } = &stmt.literal {
                    self.categorize_condition(expr, &var_order, &mut table_vars)?;

                    // Also check for standalone function calls that should be treated as conditions
                    self.categorize_standalone_function_condition(
                        expr,
                        &var_order,
                        &mut table_vars,
                    )?;

                    // Extract used properties for each table variable
                    for var_info in table_vars.iter_mut() {
                        let var_name = &var_order[var_info.order];
                        self.extract_used_properties_from_expr(
                            expr,
                            var_name,
                            &mut var_info.used_properties,
                        );
                    }
                }
            }
        }

        Ok(table_vars)
    }

    /// Analyze all assignments in the rule bodies
    fn analyze_assignments(
        &mut self,
        bodies: &[RuleBody],
        table_vars: &mut [TableVarInfo],
        var_order: &[String],
    ) -> Result<Vec<AssignmentInfo>> {
        let mut assignments = Vec::new();

        for body in bodies {
            for stmt in &body.query.stmts {
                if let Literal::Expr { expr, .. } = &stmt.literal {
                    if let Expr::AssignExpr { lhs, rhs, .. } = expr.as_ref() {
                        if let Expr::Var {
                            value: var_value, ..
                        } = lhs.as_ref()
                        {
                            if let Ok(var_name) = var_value.as_string() {
                                let var_name_str = var_name.as_ref().to_string();

                                // Find dependencies (variables used in the expression)
                                let dependencies = self.extract_all_variables_from_expr(rhs);

                                // Check if the RHS is an object literal
                                let is_object_assignment =
                                    matches!(rhs.as_ref(), Expr::Object { .. });

                                // Extract used properties for each table variable from the assignment expression
                                for var_info in table_vars.iter_mut() {
                                    let var_name = &var_order[var_info.order];
                                    self.extract_used_properties_from_expr(
                                        rhs,
                                        var_name,
                                        &mut var_info.used_properties,
                                    );
                                }

                                // Store the raw assignment expression for later translation
                                assignments.push(AssignmentInfo {
                                    var_name: var_name_str,
                                    expression: KqlExpression::column("placeholder"), // Placeholder, will be replaced during projection
                                    dependencies,
                                    is_object_assignment,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(assignments)
    }

    /// Extract all variable names from an expression (both table vars and other vars)
    fn extract_all_variables_from_expr(&self, expr: &Expr) -> Vec<String> {
        let mut vars = Vec::new();
        self.collect_variables_from_expr(expr, &mut vars);
        vars.sort();
        vars.dedup();
        vars
    }

    /// Helper to recursively collect variable names from an expression
    fn collect_variables_from_expr(&self, expr: &Expr, vars: &mut Vec<String>) {
        match expr {
            Expr::Var { value, .. } => {
                if let Ok(var_name) = value.as_string() {
                    vars.push(var_name.as_ref().to_string());
                }
            }
            Expr::RefDot { refr, .. } => {
                self.collect_variables_from_expr(refr, vars);
            }
            Expr::RefBrack { refr, index, .. } => {
                self.collect_variables_from_expr(refr, vars);
                self.collect_variables_from_expr(index, vars);
            }
            Expr::BoolExpr { lhs, rhs, .. } => {
                self.collect_variables_from_expr(lhs, vars);
                self.collect_variables_from_expr(rhs, vars);
            }
            Expr::ArithExpr { lhs, rhs, .. } => {
                self.collect_variables_from_expr(lhs, vars);
                self.collect_variables_from_expr(rhs, vars);
            }
            Expr::Array { items, .. } => {
                for item in items {
                    self.collect_variables_from_expr(item, vars);
                }
            }
            Expr::Set { items, .. } => {
                for item in items {
                    self.collect_variables_from_expr(item, vars);
                }
            }
            Expr::Object { fields, .. } => {
                for (_span, key, value) in fields {
                    self.collect_variables_from_expr(key, vars);
                    self.collect_variables_from_expr(value, vars);
                }
            }
            _ => {} // For literals, no variables to collect
        }
    }

    /// Extract used properties for each table variable from an expression
    fn extract_used_properties_from_expr(
        &self,
        expr: &Expr,
        var_name: &str,
        properties: &mut BTreeSet<String>,
    ) {
        match expr {
            Expr::RefDot { refr, field, .. } => {
                if let Expr::Var { value, .. } = refr.as_ref() {
                    if let Ok(ref_var_name) = value.as_string() {
                        if ref_var_name.as_ref() == var_name {
                            properties.insert(field.0.text().to_string());
                        }
                    }
                }
                // Also recurse into the refr in case of nested access
                self.extract_used_properties_from_expr(refr, var_name, properties);
            }
            Expr::BoolExpr { lhs, rhs, .. } => {
                self.extract_used_properties_from_expr(lhs, var_name, properties);
                self.extract_used_properties_from_expr(rhs, var_name, properties);
            }
            Expr::ArithExpr { lhs, rhs, .. } => {
                self.extract_used_properties_from_expr(lhs, var_name, properties);
                self.extract_used_properties_from_expr(rhs, var_name, properties);
            }
            Expr::RefBrack { refr, index, .. } => {
                self.extract_used_properties_from_expr(refr, var_name, properties);
                self.extract_used_properties_from_expr(index, var_name, properties);
            }
            Expr::Call { fcn, params, .. } => {
                self.extract_used_properties_from_expr(fcn, var_name, properties);
                for param in params {
                    self.extract_used_properties_from_expr(param, var_name, properties);
                }
            }
            Expr::Object { fields, .. } => {
                for (_span, key, value) in fields {
                    self.extract_used_properties_from_expr(key, var_name, properties);
                    self.extract_used_properties_from_expr(value, var_name, properties);
                }
            }
            _ => {} // For other expressions, no properties to extract
        }
    }

    /// Categorize a condition as either a var condition or join condition
    fn categorize_condition(
        &mut self,
        expr: &Expr,
        var_order: &[String],
        table_vars: &mut [TableVarInfo],
    ) -> Result<()> {
        if let Expr::BoolExpr { op, lhs, rhs, .. } = expr {
            let lhs_vars = self.extract_table_variables_from_expr(lhs);
            let rhs_vars = self.extract_table_variables_from_expr(rhs);

            if lhs_vars.len() == 1 && rhs_vars.len() == 1 && lhs_vars[0] != rhs_vars[0] {
                // This is a join condition between two different table vars
                match op {
                    BoolOp::Eq => {
                        let kql_expr = self.translate_expr_to_kql_for_join(expr)?;
                        let left_var = &lhs_vars[0];
                        let right_var = &rhs_vars[0];

                        // Add to both variables' join conditions
                        for var_info in table_vars.iter_mut() {
                            let var_name = &var_order[var_info.order];
                            if var_name == left_var || var_name == right_var {
                                var_info.join_conditions.push((
                                    left_var.clone(),
                                    right_var.clone(),
                                    kql_expr.clone(),
                                ));
                            }
                        }
                    }
                    BoolOp::Ne => {
                        // This is a cross-table condition that needs to be applied after join
                        let kql_expr = self.translate_expr_to_kql(expr)?;
                        self.deferred_cross_table_conditions.push(kql_expr);
                    }
                    _ => {
                        // Other comparison operators between different tables
                        let kql_expr = self.translate_expr_to_kql(expr)?;
                        self.deferred_cross_table_conditions.push(kql_expr);
                    }
                }
            } else if lhs_vars.len() == 1 && rhs_vars.is_empty() {
                // This is a var condition (var compared to constant)
                let var_name = &lhs_vars[0];
                let kql_expr = self.translate_expr_to_kql_for_filter(expr)?;

                if let Some(var_info) = table_vars
                    .iter_mut()
                    .find(|v| &var_order[v.order] == var_name)
                {
                    var_info.var_conditions.push(kql_expr);
                }
            } else if lhs_vars.is_empty() && rhs_vars.len() == 1 {
                // This is a var condition (constant compared to var)
                let var_name = &rhs_vars[0];
                let kql_expr = self.translate_expr_to_kql_for_filter(expr)?;

                if let Some(var_info) = table_vars
                    .iter_mut()
                    .find(|v| &var_order[v.order] == var_name)
                {
                    var_info.var_conditions.push(kql_expr);
                }
            } else if lhs_vars.len() == 1 && rhs_vars.len() == 1 && lhs_vars[0] == rhs_vars[0] {
                // This is a self-comparison condition within the same table variable
                // e.g., strings.reverse(text.value) == text.value
                let var_name = &lhs_vars[0];
                let kql_expr = self.translate_expr_to_kql_for_filter(expr)?;

                if let Some(var_info) = table_vars
                    .iter_mut()
                    .find(|v| &var_order[v.order] == var_name)
                {
                    var_info.var_conditions.push(kql_expr);
                }
            }
        } else if let Expr::Membership {
            value, collection, ..
        } = expr
        {
            // Handle membership expressions like "user.role in {"admin", "manager"}"
            let value_vars = self.extract_table_variables_from_expr(value);
            let collection_vars = self.extract_table_variables_from_expr(collection);

            if value_vars.len() == 1 && collection_vars.is_empty() {
                // This is a var membership condition (var in constant set)
                let var_name = &value_vars[0];
                let kql_expr = self.translate_expr_to_kql_for_filter(expr)?;

                if let Some(var_info) = table_vars
                    .iter_mut()
                    .find(|v| &var_order[v.order] == var_name)
                {
                    var_info.var_conditions.push(kql_expr);
                }
            }
        }

        Ok(())
    }

    /// Categorize standalone function calls that should be treated as filter conditions
    fn categorize_standalone_function_condition(
        &mut self,
        expr: &Expr,
        var_order: &[String],
        table_vars: &mut [TableVarInfo],
    ) -> Result<()> {
        if let Expr::Call { fcn, params, .. } = expr {
            // Check if this is a function call that should be treated as a condition
            let func_name = match fcn.as_ref() {
                Expr::Var { value, .. } => value
                    .as_string()
                    .map_err(|_| anyhow::anyhow!("Invalid function name"))?
                    .to_string(),
                Expr::RefDot { refr, field, .. } => {
                    // Handle dotted function names like regex.match, base64.decode, etc.
                    if let Expr::Var { value, .. } = refr.as_ref() {
                        let base = value
                            .as_string()
                            .map_err(|_| anyhow::anyhow!("Invalid function base name"))?;
                        let field_name = field.0.text();
                        format!("{}.{}", base, field_name)
                    } else {
                        return Ok(());
                    }
                }
                _ => return Ok(()),
            };

            // Check if this function should generate a filter condition
            let should_filter = matches!(
                func_name.as_str(),
                "regex.match"
                    | "base64.encode"
                    | "base64.decode"
                    | "sort"
                    | "format_int"
                    | "is_null"
                    | "to_number"
                    | "contains"
                    | "startswith"
                    | "endswith"
                    | "lower"
                    | "upper"
                    | "abs"
                    | "floor"
                    | "ceil"
                    | "is_string"
                    | "is_number"
            );

            if should_filter {
                // Extract variables from the function parameters
                let vars = self.extract_table_variables_from_expr(expr);

                if vars.len() == 1 {
                    // This is a single-table function condition
                    let var_name = &vars[0];

                    // Create a condition that checks the function result is not null
                    let kql_expr = self.translate_function_call(fcn, params)?;
                    let condition = match func_name.as_str() {
                        "regex.match" | "is_null" | "contains" | "startswith" | "endswith"
                        | "is_string" | "is_number" => {
                            // For regex.match, is_null, string functions, and type checks, use the function result directly as boolean
                            kql_expr
                        }
                        _ => {
                            // For other functions, check if result is not null
                            KqlExpression::function("isnotnull", vec![kql_expr])
                        }
                    };

                    if let Some(var_info) = table_vars
                        .iter_mut()
                        .find(|v| &var_order[v.order] == var_name)
                    {
                        var_info.var_conditions.push(condition);
                    }
                }
            }
        }

        Ok(())
    }

    /// Emit debugging information about table variables and their usage
    fn emit_debug_info(&self, table_vars: &[TableVarInfo], assignments: &[AssignmentInfo]) {
        println!("\n=== TABLE VARIABLE ANALYSIS ===");

        for (i, var_info) in table_vars.iter().enumerate() {
            println!("{}. Table Variable Analysis:", i + 1);
            println!("   Order: {}", var_info.order);
            println!("   Table: {}", var_info.table_name);
            println!("   Used Properties ({}):", var_info.used_properties.len());
            let mut properties_vec: Vec<_> = var_info.used_properties.iter().collect();
            properties_vec.sort();
            for (j, property) in properties_vec.iter().enumerate() {
                println!("     {}: {}", j + 1, property);
            }
            println!("   Var Conditions ({}):", var_info.var_conditions.len());
            for (j, condition) in var_info.var_conditions.iter().enumerate() {
                println!("     {}: {:?}", j + 1, condition);
            }
            println!("   Join Conditions ({}):", var_info.join_conditions.len());
            for (j, (left_var, right_var, condition)) in var_info.join_conditions.iter().enumerate()
            {
                println!(
                    "     {}: {} <-> {} : {:?}",
                    j + 1,
                    left_var,
                    right_var,
                    condition
                );
            }
            println!();
        }

        println!("=== ASSIGNMENT ANALYSIS ===");
        for (i, assignment) in assignments.iter().enumerate() {
            println!("{}. Assignment Analysis:", i + 1);
            println!("   Variable: {}", assignment.var_name);
            println!("   Expression: {:?}", assignment.expression);
            println!("   Dependencies: {:?}", assignment.dependencies);
            println!();
        }

        println!("=== KQL GENERATION PLAN ===");
        if !table_vars.is_empty() {
            println!("Base table: {}", table_vars[0].table_name);
            if !table_vars[0].var_conditions.is_empty() {
                println!(
                    "  Base table filters: {} conditions",
                    table_vars[0].var_conditions.len()
                );
            }

            for (i, var_info) in table_vars.iter().skip(1).enumerate() {
                println!("Join with: {}", var_info.table_name);
                if !var_info.var_conditions.is_empty() {
                    println!(
                        "  Join table filters: {} conditions",
                        var_info.var_conditions.len()
                    );
                }

                // Find join conditions that involve this table variable
                let relevant_joins: Vec<_> = var_info
                    .join_conditions
                    .iter()
                    .filter(|(left_var, right_var, _)| {
                        // Check if this join involves the current table and a previous one
                        let current_var_names = self.table_variables.clone();
                        let current_order = i + 1; // +1 because we're skipping the first table

                        // Find which variables map to which tables
                        let left_var_order = current_var_names.iter().position(|v| v == left_var);
                        let right_var_order = current_var_names.iter().position(|v| v == right_var);

                        if let (Some(l_ord), Some(r_ord)) = (left_var_order, right_var_order) {
                            // One variable should be from current table, other from previous
                            (l_ord == current_order && r_ord < current_order)
                                || (r_ord == current_order && l_ord < current_order)
                        } else {
                            false
                        }
                    })
                    .collect();

                println!("  Join conditions: {} relevant", relevant_joins.len());
                for (j, (left_var, right_var, condition)) in relevant_joins.iter().enumerate() {
                    println!(
                        "    {}: {} <-> {} : {:?}",
                        j + 1,
                        left_var,
                        right_var,
                        condition
                    );
                }
            }

            if !assignments.is_empty() {
                println!("Assignments to process: {}", assignments.len());
                for assignment in assignments {
                    println!(
                        "  {} := {:?} (depends on: {:?})",
                        assignment.var_name, assignment.expression, assignment.dependencies
                    );
                }
            }
        }
        println!("=== END ANALYSIS ===\n");
    }

    /// Build KQL query from the analyzed table variables
    fn build_kql_from_analysis(
        &mut self,
        head: &RuleHead,
        bodies: &[RuleBody],
        table_vars: &[TableVarInfo],
        _assignments: &[AssignmentInfo],
    ) -> Result<KqlQuery> {
        if table_vars.is_empty() {
            bail!("No table variables found");
        }

        let mut builder = KqlQueryBuilder::new();

        // Start with base table
        let base_table = &table_vars[0];
        let base_var_name = &self.table_variables[base_table.order];
        builder = builder.from_table(&base_table.table_name);

        // Apply base table conditions
        for condition in &base_table.var_conditions {
            builder = builder.where_clause(condition.clone());
        }

        // Check if there are joins (more than one table)
        let has_joins = table_vars.len() > 1;

        // Add project operation for base table
        if has_joins {
            // With joins: use variable-prefixed column names to avoid conflicts
            let base_project_columns = base_table
                .used_properties
                .iter()
                .map(|prop| KqlColumn {
                    name: prop.clone(),
                    alias: Some(format!("{}_{}", base_var_name, prop)),
                    expression: KqlExpression::Column(prop.clone()),
                })
                .collect();
            builder = builder.project(base_project_columns);
        }
        // No project needed for single table - will be handled by assignment projection if present

        // Add joins for remaining tables
        // Process remaining tables as joins with project clauses
        for var_info in table_vars.iter().skip(1) {
            let var_name = &self.table_variables[var_info.order];

            // Build subquery for this table with its conditions and project clause
            let mut subquery_builder = KqlQueryBuilder::new();
            subquery_builder = subquery_builder.from_table(&var_info.table_name);

            // Apply this table's conditions
            for condition in &var_info.var_conditions {
                subquery_builder = subquery_builder.where_clause(condition.clone());
            }

            // Add project operation with variable-prefixed column names
            let project_columns = var_info
                .used_properties
                .iter()
                .map(|prop| KqlColumn {
                    name: prop.clone(),
                    expression: KqlExpression::Column(prop.clone()),
                    alias: Some(format!("{}_{}", var_name, prop)),
                })
                .collect();
            subquery_builder = subquery_builder.project(project_columns);

            // Find join conditions that connect this table to previous tables
            let mut join_conditions = Vec::new();
            let mut conditions_added = std::collections::HashSet::new();

            // Look through all join conditions to find ones involving this table
            for table_var in table_vars {
                for (left_var, right_var, condition) in &table_var.join_conditions {
                    let left_var_order = self.table_variables.iter().position(|v| v == left_var);
                    let right_var_order = self.table_variables.iter().position(|v| v == right_var);
                    let current_order = var_info.order;

                    if let (Some(l_ord), Some(r_ord)) = (left_var_order, right_var_order) {
                        // One variable should be from current table, other from previous table
                        let is_relevant = (l_ord == current_order && r_ord < current_order)
                            || (r_ord == current_order && l_ord < current_order);

                        if is_relevant {
                            if let KqlExpression::Binary { left, right, op } = condition {
                                // Create a unique key for this condition to avoid duplicates
                                let condition_key = format!(
                                    "{}_{}",
                                    if l_ord < r_ord {
                                        format!("{}_{}", left_var, right_var)
                                    } else {
                                        format!("{}_{}", right_var, left_var)
                                    },
                                    format!("{:?}", condition)
                                );

                                if !conditions_added.contains(&condition_key) {
                                    conditions_added.insert(condition_key);

                                    // Since subqueries use variable-prefixed column names, and there are no conflicts,
                                    // use the variable-prefixed column names directly in join conditions
                                    let (left_expr, right_expr) = if l_ord == current_order {
                                        // left_var belongs to current table (being joined), right_var is from previous table
                                        let right_col = if let KqlExpression::Column(col) = &**right
                                        {
                                            format!("{}_{}", right_var, col)
                                        } else {
                                            format!("{:?}", right)
                                        };
                                        let left_col = if let KqlExpression::Column(col) = &**left {
                                            format!("{}_{}", left_var, col)
                                        } else {
                                            format!("{:?}", left)
                                        };
                                        (
                                            KqlExpression::Column(right_col),
                                            KqlExpression::Column(left_col),
                                        )
                                    } else {
                                        // right_var belongs to current table (being joined), left_var is from previous table
                                        let left_col = if let KqlExpression::Column(col) = &**left {
                                            format!("{}_{}", left_var, col)
                                        } else {
                                            format!("{:?}", left)
                                        };
                                        let right_col = if let KqlExpression::Column(col) = &**right
                                        {
                                            format!("{}_{}", right_var, col)
                                        } else {
                                            format!("{:?}", right)
                                        };
                                        (
                                            KqlExpression::Column(left_col),
                                            KqlExpression::Column(right_col),
                                        )
                                    };

                                    join_conditions.push(KqlJoinCondition {
                                        left: left_expr,
                                        right: right_expr,
                                        operator: op.clone(),
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // Apply join with subquery
            builder = builder.join_subquery(
                KqlJoinKind::Inner,
                subquery_builder.build().map_err(|e| anyhow::anyhow!(e))?,
                join_conditions,
            );
        }

        // Apply any deferred cross-table conditions after all joins but before projections
        // Need to apply variable prefixes to these conditions
        for condition in &self.deferred_cross_table_conditions {
            let prefixed_condition =
                self.apply_variable_prefixes_to_condition(condition.clone(), table_vars);
            builder = builder.where_clause(prefixed_condition);
        }

        // Process assignments by translating them live from the original rule bodies
        if !_assignments.is_empty() {
            builder = self.translate_assignments_live(builder, bodies, table_vars)?;
        } else {
            // Use the existing rule head translation
            builder = self.translate_rule_head(builder, head)?;
        }

        builder.build().map_err(|e| anyhow::anyhow!(e))
    }

    /// Apply variable prefixes to cross-table conditions
    fn apply_variable_prefixes_to_condition(
        &self,
        condition: KqlExpression,
        table_vars: &[TableVarInfo],
    ) -> KqlExpression {
        match condition {
            KqlExpression::Binary { op, left, right } => {
                let prefixed_left = self.apply_variable_prefixes_to_expr(*left, table_vars);
                let prefixed_right = self.apply_variable_prefixes_to_expr(*right, table_vars);
                KqlExpression::Binary {
                    op,
                    left: Box::new(prefixed_left),
                    right: Box::new(prefixed_right),
                }
            }
            other => other, // Pass through other expressions unchanged
        }
    }

    /// Apply variable prefixes to individual expressions
    fn apply_variable_prefixes_to_expr(
        &self,
        expr: KqlExpression,
        table_vars: &[TableVarInfo],
    ) -> KqlExpression {
        match expr {
            KqlExpression::Column(col_name) => {
                // Check if this column name matches any of our variable naming patterns
                // Look for patterns like "id", "id1", etc and map them to proper prefixed names
                for (i, var_info) in table_vars.iter().enumerate() {
                    let var_name = &self.table_variables[var_info.order];

                    // Check if this column matches the pattern for this variable
                    // For self-joins, we might have "id" for first table and "id1" for second table
                    if col_name == "id" && i == 0 {
                        return KqlExpression::Column(format!("{}_id", var_name));
                    } else if col_name == "id1" && i == 1 {
                        return KqlExpression::Column(format!("{}_id", var_name));
                    }

                    // Also check for direct matches with prefixed names
                    for prop in &var_info.used_properties {
                        if col_name == *prop {
                            return KqlExpression::Column(format!("{}_{}", var_name, prop));
                        }
                    }
                }

                // If no match found, return as-is
                KqlExpression::Column(col_name)
            }
            other => other, // Pass through other expressions unchanged
        }
    }

    /// Translate assignments live from the original rule bodies using proper variable prefixes
    fn translate_assignments_live(
        &mut self,
        mut builder: KqlQueryBuilder,
        bodies: &[RuleBody],
        table_vars: &[TableVarInfo],
    ) -> Result<KqlQueryBuilder> {
        // Check if there are joins (more than one table)
        let has_joins = table_vars.len() > 1;

        // Create a mapping from variable names to their order for prefix generation
        let var_to_prefix: std::collections::HashMap<String, String> = if has_joins {
            table_vars
                .iter()
                .map(|tv| {
                    let var_name = &self.tables_seen[tv.order].1;
                    (var_name.clone(), var_name.clone())
                })
                .collect()
        } else {
            // No joins - no prefixes needed
            std::collections::HashMap::new()
        };

        for body in bodies {
            for stmt in &body.query.stmts {
                if let Literal::Expr { expr, .. } = &stmt.literal {
                    if let Expr::AssignExpr { lhs, rhs, .. } = expr.as_ref() {
                        if let Expr::Var {
                            value: var_value, ..
                        } = lhs.as_ref()
                        {
                            if let Ok(var_name) = var_value.as_string() {
                                // Found an assignment, translate it using proper variable prefixes
                                if let Expr::Object { fields, .. } = rhs.as_ref() {
                                    // This is an object assignment, translate to projection
                                    let mut columns = Vec::new();
                                    for (_, key_expr, value_expr) in fields {
                                        if let Expr::String {
                                            value: key_value, ..
                                        } = key_expr.as_ref()
                                        {
                                            let key_name = key_value
                                                .as_string()
                                                .map_err(|_| anyhow::anyhow!("Invalid key"))?;

                                            // Translate the value expression with proper variable prefixes
                                            let column_expr = self.translate_expr_with_prefixes(
                                                value_expr.as_ref(),
                                                &var_to_prefix,
                                            )?;

                                            columns.push(KqlColumn {
                                                name: key_name.as_ref().to_string(),
                                                expression: column_expr,
                                                alias: Some(key_name.as_ref().to_string()),
                                            });
                                        }
                                    }
                                    if !columns.is_empty() {
                                        builder = builder.project(columns);
                                    }
                                } else {
                                    // Regular assignment, translate to extend
                                    let kql_expr = self.translate_expr_with_prefixes(
                                        rhs.as_ref(),
                                        &var_to_prefix,
                                    )?;
                                    let column = KqlColumn {
                                        name: var_name.as_ref().to_string(),
                                        expression: kql_expr,
                                        alias: None,
                                    };
                                    builder = builder.extend(vec![column]);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(builder)
    }

    /// Translate expressions with proper variable prefixes for projection context
    fn translate_expr_with_prefixes(
        &mut self,
        expr: &Expr,
        var_to_prefix: &std::collections::HashMap<String, String>,
    ) -> Result<KqlExpression> {
        match expr {
            Expr::RefDot { refr, field, .. } => {
                // Handle table variable references like vm.id or dep2.id
                if let Expr::Var { value, .. } = refr.as_ref() {
                    let var_name = value
                        .as_string()
                        .map_err(|_| anyhow::anyhow!("Invalid variable"))?;

                    // Check if this is a table variable with a known prefix
                    if let Some(prefix) = var_to_prefix.get(var_name.as_ref()) {
                        let field_name = field.0.text();
                        // After joins with subqueries, columns are available as var_field
                        let prefixed_column = format!("{}_{}", prefix, field_name);
                        return Ok(KqlExpression::column(&prefixed_column));
                    } else if var_to_prefix.is_empty() {
                        // No joins case - use original column names
                        let field_name = field.0.text();
                        return Ok(KqlExpression::column(field_name));
                    }
                }
                // Fallback to regular translation for non-table variables
                self.translate_expr_to_kql(expr)
            }
            Expr::ArithExpr { op, lhs, rhs, .. } => {
                // Handle arithmetic expressions recursively with prefixes
                let mut left_expr =
                    self.translate_expr_with_prefixes(lhs.as_ref(), var_to_prefix)?;
                let mut right_expr =
                    self.translate_expr_with_prefixes(rhs.as_ref(), var_to_prefix)?;

                // Add parentheses if needed based on operator precedence
                if let Expr::ArithExpr { op: child_op, .. } = lhs.as_ref() {
                    if self.needs_parentheses(op, child_op, false) {
                        left_expr = KqlExpression::Parenthesized(Box::new(left_expr));
                    }
                }

                if let Expr::ArithExpr { op: child_op, .. } = rhs.as_ref() {
                    if self.needs_parentheses(op, child_op, true) {
                        right_expr = KqlExpression::Parenthesized(Box::new(right_expr));
                    }
                }

                let kql_op = self.translate_arith_op(op)?;

                Ok(KqlExpression::Binary {
                    op: kql_op,
                    left: Box::new(left_expr),
                    right: Box::new(right_expr),
                })
            }
            Expr::BoolExpr { op, lhs, rhs, .. } => {
                // Handle boolean expressions recursively with prefixes
                let left_expr = self.translate_expr_with_prefixes(lhs.as_ref(), var_to_prefix)?;
                let right_expr = self.translate_expr_with_prefixes(rhs.as_ref(), var_to_prefix)?;

                let kql_op = self.translate_bool_op(op)?;

                Ok(KqlExpression::Binary {
                    op: kql_op,
                    left: Box::new(left_expr),
                    right: Box::new(right_expr),
                })
            }
            _ => {
                // For other expressions, use regular translation
                self.translate_expr_to_kql(expr)
            }
        }
    }

    /// Translate expression to KQL for join conditions (no column suffixes)
    fn translate_expr_to_kql_for_join(&mut self, expr: &Expr) -> Result<KqlExpression> {
        // Use original column names for join conditions
        self.translate_expr_to_kql_no_suffix(expr)
    }

    /// Translate expression to KQL for filters (with column suffixes if needed)
    fn translate_expr_to_kql_for_filter(&mut self, expr: &Expr) -> Result<KqlExpression> {
        // For var conditions (filters), use original column names without suffixes
        self.translate_expr_to_kql_no_suffix(expr)
    }

    /// Translate expression to KQL without adding column suffixes for joined tables
    fn translate_expr_to_kql_no_suffix(&mut self, expr: &Expr) -> Result<KqlExpression> {
        match expr {
            Expr::Var { value, .. } => {
                let name = value
                    .as_string()
                    .map_err(|_| anyhow::anyhow!("Invalid variable"))?;
                Ok(KqlExpression::column(name.as_ref()))
            }

            Expr::String { value, .. } => {
                let s = value
                    .as_string()
                    .map_err(|_| anyhow::anyhow!("Invalid string"))?;
                Ok(KqlExpression::string_literal(s.as_ref()))
            }

            Expr::Number { value, .. } => match value {
                Value::Number(n) => {
                    if n.is_integer() {
                        Ok(KqlExpression::int_literal(n.as_i64().unwrap_or(0)))
                    } else {
                        Ok(KqlExpression::Literal(KqlLiteral::Float(
                            n.as_f64().unwrap_or(0.0),
                        )))
                    }
                }
                _ => bail!("Invalid number value"),
            },

            Expr::Bool { value, .. } => {
                let b = value
                    .as_bool()
                    .map_err(|_| anyhow::anyhow!("Invalid boolean"))?;
                Ok(KqlExpression::bool_literal(*b))
            }

            Expr::Null { .. } => Ok(KqlExpression::null_literal()),

            Expr::RefDot { refr, field, .. } => {
                let object = self.translate_expr_to_kql_no_suffix(refr)?;

                // For join conditions, always use the original field name without suffixes
                if let KqlExpression::Column(name) = &object {
                    if self.table_variables.contains(&name) {
                        // Always use the original field name for join conditions
                        return Ok(KqlExpression::column(field.0.text()));
                    }
                }

                Ok(KqlExpression::property(object, field.0.text()))
            }

            Expr::BoolExpr { op, lhs, rhs, .. } => {
                // Special handling for null comparisons
                match op {
                    BoolOp::Eq => {
                        // Check if this is a comparison with null
                        if matches!(rhs.as_ref(), Expr::Null { .. }) {
                            let left_expr = self.translate_expr_to_kql_no_suffix(lhs)?;
                            return Ok(KqlExpression::function("isnull", vec![left_expr]));
                        } else if matches!(lhs.as_ref(), Expr::Null { .. }) {
                            let right_expr = self.translate_expr_to_kql_no_suffix(rhs)?;
                            return Ok(KqlExpression::function("isnull", vec![right_expr]));
                        }
                    }
                    BoolOp::Ne => {
                        // Check if this is a comparison with null
                        if matches!(rhs.as_ref(), Expr::Null { .. }) {
                            let left_expr = self.translate_expr_to_kql_no_suffix(lhs)?;
                            return Ok(KqlExpression::function("isnotnull", vec![left_expr]));
                        } else if matches!(lhs.as_ref(), Expr::Null { .. }) {
                            let right_expr = self.translate_expr_to_kql_no_suffix(rhs)?;
                            return Ok(KqlExpression::function("isnotnull", vec![right_expr]));
                        }
                    }
                    _ => {}
                }

                let left = self.translate_expr_to_kql_no_suffix(lhs)?;
                let right = self.translate_expr_to_kql_no_suffix(rhs)?;

                let kql_op = match op {
                    BoolOp::Eq => KqlBinaryOp::Equal,
                    BoolOp::Ne => KqlBinaryOp::NotEqual,
                    BoolOp::Lt => KqlBinaryOp::LessThan,
                    BoolOp::Le => KqlBinaryOp::LessThanOrEqual,
                    BoolOp::Gt => KqlBinaryOp::GreaterThan,
                    BoolOp::Ge => KqlBinaryOp::GreaterThanOrEqual,
                };

                Ok(KqlExpression::Binary {
                    left: Box::new(left),
                    right: Box::new(right),
                    op: kql_op,
                })
            }

            // For other expression types, delegate to the main method
            _ => self.translate_expr_to_kql(expr),
        }
    }

    fn extract_table_from_query(&mut self, query: &Query) -> Result<String> {
        // Look for data access patterns in the query
        for stmt in &query.stmts {
            if let Some(table) = self.try_extract_table_from_stmt(stmt)? {
                return Ok(table);
            }
        }

        // Use default table if no table found
        self.default_table
            .clone()
            .ok_or_else(|| anyhow::anyhow!("No table found and no default table specified"))
    }

    fn try_extract_table_from_stmt(&mut self, stmt: &LiteralStmt) -> Result<Option<String>> {
        match &stmt.literal {
            Literal::Expr { expr, .. } => self.try_extract_table_from_expr(expr),
            _ => Ok(None),
        }
    }

    fn try_extract_table_from_expr(&mut self, expr: &Expr) -> Result<Option<String>> {
        match expr {
            Expr::AssignExpr { rhs, .. } => self.try_extract_table_from_expr(rhs),
            Expr::RefBrack { refr, .. } | Expr::RefDot { refr, .. } => {
                self.try_extract_table_from_expr(refr)
            }
            Expr::Var { value, .. } => {
                let var_name = value
                    .as_string()
                    .map_err(|_| anyhow::anyhow!("Invalid variable"))?;
                if var_name.as_ref() == "data" {
                    Ok(None) // Need more context
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    fn translate_literal_stmt(
        &mut self,
        builder: KqlQueryBuilder,
        stmt: &LiteralStmt,
    ) -> Result<KqlQueryBuilder> {
        match &stmt.literal {
            Literal::Expr { expr, .. } => self.translate_expression_stmt(builder, expr),
            Literal::NotExpr { expr, .. } => {
                let kql_expr = self.translate_expr_to_kql(expr)?;
                let not_expr = KqlExpression::Unary {
                    op: KqlUnaryOp::Not,
                    operand: Box::new(kql_expr),
                };
                Ok(builder.where_clause(not_expr))
            }
            Literal::SomeVars { vars, .. } => {
                // Register variables
                for var in vars {
                    self.variables.push(var.text().to_string());
                }
                Ok(builder)
            }
            Literal::SomeIn {
                value, collection, ..
            } => {
                // For database queries, "some user in users" declares that 'user' is a variable
                // representing a row from the 'users' table.
                if let Expr::Var {
                    value: var_value, ..
                } = value.as_ref()
                {
                    if let Ok(var_name) = var_value.as_string() {
                        self.table_variables.push(var_name.as_ref().to_string());
                        self.variables.push(var_name.as_ref().to_string());

                        // Extract the table name from the collection
                        if let Some(table_name) =
                            self.extract_table_from_collection_expr(collection)?
                        {
                            // Track the mapping from variable to table
                            self.table_var_to_table
                                .insert(var_name.as_ref().to_string(), table_name.clone());

                            // Track tables we've seen with their variable names
                            self.tables_seen
                                .push((table_name.clone(), var_name.as_ref().to_string()));

                            // If this is the first occurrence of any table, it's the base table
                            let is_base_table = self.tables_seen.len() == 1;
                            if is_base_table {
                                self.base_table_vars.insert(var_name.as_ref().to_string());
                            }

                            // Don't create joins immediately - defer until we have all filters
                            // The joins will be created in a second pass
                        }
                    }
                }
                // For the base table or if we can't determine the table, just register the variable
                Ok(builder)
            }
            Literal::Every { .. } => {
                bail!("Every statements not supported in KQL translation")
            }
        }
    }

    fn translate_expression_stmt(
        &mut self,
        builder: KqlQueryBuilder,
        expr: &Expr,
    ) -> Result<KqlQueryBuilder> {
        match expr {
            Expr::AssignExpr { lhs, rhs, .. } => {
                // Handle variable assignments
                if let Expr::Var { value, .. } = lhs.as_ref() {
                    let var_name = value
                        .as_string()
                        .map_err(|_| anyhow::anyhow!("Invalid variable"))?;
                    self.variables.push(var_name.as_ref().to_string());

                    // Check if this is a filter condition or a data binding
                    if self.is_data_binding(rhs) {
                        // This is a data source binding, handle in query extraction
                        Ok(builder)
                    } else if let Expr::Object { fields, .. } = rhs.as_ref() {
                        // For object assignments, store them for Set rules to be processed in rule head
                        let mut object_fields = Vec::new();
                        for (_, key_expr, value_expr) in fields {
                            if let Expr::String {
                                value: key_value, ..
                            } = key_expr.as_ref()
                            {
                                let key_name = key_value
                                    .as_string()
                                    .map_err(|_| anyhow::anyhow!("Invalid key"))?;
                                let column_expr =
                                    self.translate_expr_to_kql(value_expr.as_ref())?;
                                object_fields.push((key_name.as_ref().to_string(), column_expr));
                            }
                        }
                        self.deferred_object_assignments
                            .push((var_name.as_ref().to_string(), object_fields));
                        Ok(builder)
                    } else {
                        // This is a computed column
                        let kql_expr = self.translate_expr_to_kql(rhs)?;
                        let column = KqlColumn {
                            name: var_name.as_ref().to_string(),
                            expression: kql_expr,
                            alias: None,
                        };
                        Ok(builder.extend(vec![column]))
                    }
                } else {
                    // This is a filter condition
                    let kql_expr = self.translate_expr_to_kql(expr)?;
                    Ok(builder.where_clause(kql_expr))
                }
            }
            Expr::BoolExpr {
                op: BoolOp::Eq,
                lhs,
                rhs,
                ..
            } => {
                // Check if this is a potential join condition
                let is_join_condition = self.is_potential_join_condition(lhs, rhs);
                let table_var = self.get_table_variable_from_expr(lhs);

                if is_join_condition {
                    // This is a join condition - defer it with variable context for better matching
                    let lhs_vars = self.extract_table_variables_from_expr(lhs);
                    let rhs_vars = self.extract_table_variables_from_expr(rhs);

                    if !lhs_vars.is_empty() && !rhs_vars.is_empty() {
                        // Store the condition with the variable names for better matching
                        let kql_expr = self.translate_expr_to_kql(expr)?;
                        self.deferred_join_conditions.push((
                            lhs_vars[0].clone(),
                            rhs_vars[0].clone(),
                            kql_expr,
                        ));
                    }
                    Ok(builder) // Don't add to WHERE clause yet
                } else if let Some(table_var) = table_var {
                    // Check if this is a table-specific filter
                    if let Some(_table_name) = self.table_var_to_table.get(&table_var).cloned() {
                        // Check if this variable belongs to the base table
                        if self.base_table_vars.contains(&table_var) {
                            // This is a base table filter - apply it directly as WHERE
                            let kql_expr = self.translate_expr_to_kql(expr)?;
                            Ok(builder.where_clause(kql_expr))
                        } else {
                            // This is a join table filter - store it for the table variable
                            let kql_expr = self.translate_expr_to_kql(expr)?;
                            self.table_var_filters
                                .entry(table_var)
                                .or_insert_with(Vec::new)
                                .push(kql_expr);
                            return Ok(builder); // Don't add to main WHERE clause
                        }
                    } else {
                        // Regular filter condition
                        let kql_expr = self.translate_expr_to_kql(expr)?;
                        Ok(builder.where_clause(kql_expr))
                    }
                } else {
                    // Regular filter condition
                    let kql_expr = self.translate_expr_to_kql(expr)?;
                    Ok(builder.where_clause(kql_expr))
                }
            }
            Expr::BoolExpr {
                op: BoolOp::Ne,
                lhs,
                rhs: _,
                ..
            } => {
                // Handle != conditions (like health_id != null)
                let table_var = self.get_table_variable_from_expr(lhs);

                if let Some(table_var) = table_var {
                    // Check if this is a table-specific filter
                    if let Some(_table_name) = self.table_var_to_table.get(&table_var).cloned() {
                        // Check if this variable belongs to the base table
                        if self.base_table_vars.contains(&table_var) {
                            // This is a base table filter - apply it directly as WHERE
                            let kql_expr = self.translate_expr_to_kql(expr)?;
                            Ok(builder.where_clause(kql_expr))
                        } else {
                            // This is a join table filter - store it for the table variable
                            let kql_expr = self.translate_expr_to_kql(expr)?;
                            self.table_var_filters
                                .entry(table_var)
                                .or_insert_with(Vec::new)
                                .push(kql_expr);
                            return Ok(builder); // Don't add to main WHERE clause
                        }
                    } else {
                        // Regular filter condition
                        let kql_expr = self.translate_expr_to_kql(expr)?;
                        Ok(builder.where_clause(kql_expr))
                    }
                } else {
                    // Regular filter condition
                    let kql_expr = self.translate_expr_to_kql(expr)?;
                    Ok(builder.where_clause(kql_expr))
                }
            }
            _ => {
                // This is a filter condition
                let kql_expr = self.translate_expr_to_kql(expr)?;
                Ok(builder.where_clause(kql_expr))
            }
        }
    }

    /// Check if an equality expression could be a join condition
    fn is_potential_join_condition(&self, lhs: &Expr, rhs: &Expr) -> bool {
        // A join condition typically involves fields from different table variables
        let lhs_vars = self.extract_table_variables_from_expr(lhs);
        let rhs_vars = self.extract_table_variables_from_expr(rhs);

        // If both sides reference table variables and they're different, it's likely a join condition
        !lhs_vars.is_empty() && !rhs_vars.is_empty() && lhs_vars != rhs_vars
    }

    /// Extract table variable names referenced in an expression
    fn extract_table_variables_from_expr(&self, expr: &Expr) -> Vec<String> {
        let mut vars = Vec::new();
        self.collect_table_variables_from_expr(expr, &mut vars);
        vars.sort();
        vars.dedup();
        vars
    }

    /// Recursively collect table variable names from an expression
    fn collect_table_variables_from_expr(&self, expr: &Expr, vars: &mut Vec<String>) {
        match expr {
            Expr::Var { value, .. } => {
                if let Ok(var_name) = value.as_string() {
                    if self
                        .table_variables
                        .contains(&var_name.as_ref().to_string())
                    {
                        vars.push(var_name.as_ref().to_string());
                    }
                }
            }
            Expr::RefDot { refr, .. } => {
                self.collect_table_variables_from_expr(refr, vars);
            }
            Expr::RefBrack { refr, .. } => {
                self.collect_table_variables_from_expr(refr, vars);
            }
            Expr::Call { params, .. } => {
                // Recursively extract variables from function arguments
                for param in params {
                    self.collect_table_variables_from_expr(param, vars);
                }
            }
            Expr::BoolExpr { lhs, rhs, .. } => {
                // Recursively extract variables from both sides of boolean expressions
                self.collect_table_variables_from_expr(lhs, vars);
                self.collect_table_variables_from_expr(rhs, vars);
            }
            Expr::ArithExpr { lhs, rhs, .. } => {
                // Recursively extract variables from both sides of arithmetic expressions
                self.collect_table_variables_from_expr(lhs, vars);
                self.collect_table_variables_from_expr(rhs, vars);
            }
            _ => {}
        }
    }

    /// Get the primary table variable from an expression (for detecting table-specific filters)
    fn get_table_variable_from_expr(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::RefDot { refr, .. } => {
                // For expressions like user.role, return "user"
                if let Expr::Var { value, .. } = refr.as_ref() {
                    if let Ok(var_name) = value.as_string() {
                        if self
                            .table_variables
                            .contains(&var_name.as_ref().to_string())
                        {
                            return Some(var_name.as_ref().to_string());
                        }
                    }
                }
                None
            }
            Expr::Var { value, .. } => {
                if let Ok(var_name) = value.as_string() {
                    if self
                        .table_variables
                        .contains(&var_name.as_ref().to_string())
                    {
                        return Some(var_name.as_ref().to_string());
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn is_data_binding(&self, expr: &Expr) -> bool {
        match expr {
            Expr::RefBrack { refr, .. } => self.is_data_binding(refr),
            Expr::RefDot { refr, .. } => self.is_data_binding(refr),
            Expr::Var { value, .. } => {
                if let Ok(name) = value.as_string() {
                    name.as_ref() == "data" || name.as_ref() == "input"
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Extract table name from a collection expression in SomeIn statements
    fn extract_table_from_collection_expr(&self, collection: &Expr) -> Result<Option<String>> {
        match collection {
            Expr::RefDot { refr, field, .. } => {
                // Handle data.TableName pattern
                if let Expr::Var { value, .. } = refr.as_ref() {
                    if let Ok(var_name) = value.as_string() {
                        if var_name.as_ref() == "data" {
                            return Ok(Some(field.0.text().to_string()));
                        }
                    }
                }
                Ok(None)
            }
            Expr::RefBrack { refr, index, .. } => {
                // Handle data["TableName"] pattern
                if let Expr::Var { value, .. } = refr.as_ref() {
                    if let Ok(var_name) = value.as_string() {
                        if var_name.as_ref() == "data" {
                            if let Expr::String {
                                value: table_value, ..
                            } = index.as_ref()
                            {
                                if let Ok(table_name) = table_value.as_string() {
                                    return Ok(Some(table_name.as_ref().to_string()));
                                }
                            }
                        }
                    }
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn translate_rule_head(
        &mut self,
        builder: KqlQueryBuilder,
        head: &RuleHead,
    ) -> Result<KqlQueryBuilder> {
        match head {
            RuleHead::Compr { assign, refr, .. } => {
                if let Some(assign) = assign {
                    // Extract the variable name from the reference
                    let rule_name = self.extract_variable_name_from_ref(refr)?;

                    // Check if this is an object assignment that should become a projection
                    if let Expr::Object { fields, .. } = assign.value.as_ref() {
                        // Convert object fields to projection columns
                        let mut projection_columns = Vec::new();
                        for (_, key_expr, value_expr) in fields {
                            if let Expr::String {
                                value: key_value, ..
                            } = key_expr.as_ref()
                            {
                                let key_name = key_value
                                    .as_string()
                                    .map_err(|_| anyhow::anyhow!("Invalid key"))?;
                                let column_expr =
                                    self.translate_expr_to_kql(value_expr.as_ref())?;
                                projection_columns.push(KqlColumn {
                                    name: key_name.as_ref().to_string(),
                                    expression: column_expr,
                                    alias: Some(key_name.as_ref().to_string()),
                                });
                            }
                        }
                        return Ok(builder.project(projection_columns));
                    } else {
                        // For assignments (like arithmetic expressions), generate extend operations
                        let kql_expr = self.translate_expr_to_kql(&assign.value)?;
                        let column = KqlColumn {
                            name: rule_name.clone(),
                            expression: kql_expr,
                            alias: None,
                        };
                        return Ok(builder.extend(vec![column]));
                    }
                } else {
                    Ok(builder)
                }
            }
            RuleHead::Set { key, .. } => {
                // Check if we have deferred object assignments that should become projections
                if !self.deferred_object_assignments.is_empty() {
                    // Process deferred object assignments as projections
                    let mut projection_columns = Vec::new();
                    for (_var_name, object_fields) in self.deferred_object_assignments.drain(..) {
                        for (key_name, column_expr) in object_fields {
                            projection_columns.push(KqlColumn {
                                name: key_name.clone(),
                                expression: column_expr,
                                alias: Some(key_name),
                            });
                        }
                    }
                    if !projection_columns.is_empty() {
                        return Ok(builder.project(projection_columns));
                    }
                }

                // For filtering rules (contains patterns), we don't want to project anything
                // We want to return the full filtered records
                if let Some(_key) = key {
                    // Don't project the key for filtering rules - just return the builder as-is
                    // This allows the full records to be returned after filtering
                    Ok(builder)
                } else {
                    Ok(builder)
                }
            }
            RuleHead::Func { .. } => {
                bail!("Function rules not supported")
            }
        }
    }

    fn translate_expr_to_kql(&mut self, expr: &Expr) -> Result<KqlExpression> {
        match expr {
            Expr::Var { value, .. } => {
                let name = value
                    .as_string()
                    .map_err(|_| anyhow::anyhow!("Invalid variable"))?;
                Ok(KqlExpression::column(name.as_ref()))
            }

            Expr::String { value, .. } => {
                let s = value
                    .as_string()
                    .map_err(|_| anyhow::anyhow!("Invalid string"))?;
                Ok(KqlExpression::string_literal(s.as_ref()))
            }

            Expr::Number { value, .. } => match value {
                Value::Number(n) => {
                    if n.is_integer() {
                        Ok(KqlExpression::int_literal(n.as_i64().unwrap_or(0)))
                    } else {
                        Ok(KqlExpression::Literal(KqlLiteral::Float(
                            n.as_f64().unwrap_or(0.0),
                        )))
                    }
                }
                _ => bail!("Invalid number value"),
            },

            Expr::Bool { value, .. } => {
                let b = value
                    .as_bool()
                    .map_err(|_| anyhow::anyhow!("Invalid boolean"))?;
                Ok(KqlExpression::bool_literal(*b))
            }

            Expr::Null { .. } => Ok(KqlExpression::null_literal()),

            Expr::Array { items, .. } => {
                let mut kql_items = Vec::new();
                for item in items {
                    kql_items.push(self.translate_expr_to_kql(item)?);
                }
                Ok(KqlExpression::Array(kql_items))
            }

            Expr::Set { items, .. } => {
                // Sets in Rego translate to arrays in KQL (with distinct if needed)
                let mut kql_items = Vec::new();
                for item in items {
                    kql_items.push(self.translate_expr_to_kql(item)?);
                }
                Ok(KqlExpression::Array(kql_items))
            }

            Expr::RefDot { refr, field, .. } => {
                let object = self.translate_expr_to_kql(refr)?;

                // Check if the object is a column reference that represents a table variable
                // If so, we can use just the field name instead of table_var.field
                if let KqlExpression::Column(name) = &object {
                    // Check if this is a table variable declared with "some var in table"
                    if self.table_variables.contains(&name) {
                        // For joined tables, we need to account for KQL's automatic column renaming
                        // When tables are joined and have columns with the same name, KQL renames them:
                        // first table: column_name, second table: column_name1, third: column_name2, etc.

                        let field_name = field.0.text();

                        // Find which table this variable belongs to
                        if let Some(_table_name) = self.table_var_to_table.get(name) {
                            // Find the index of this table in the join order
                            let table_index = self
                                .tables_seen
                                .iter()
                                .position(|(_, v)| v == name)
                                .unwrap_or(0);

                            // If this is the base table (index 0), use the original column name
                            // For joined tables, check if we need to add a suffix
                            if table_index == 0 {
                                return Ok(KqlExpression::column(field_name));
                            } else {
                                // For joined tables, we need to determine if there's a naming conflict
                                // and add the appropriate suffix (1, 2, etc.)
                                // For now, we'll use a simple heuristic: joined tables get suffixed with their index
                                let column_name = format!("{}{}", field_name, table_index);
                                return Ok(KqlExpression::column(&column_name));
                            }
                        } else {
                            // Fallback to original field name
                            return Ok(KqlExpression::column(field_name));
                        }
                    }
                }

                Ok(KqlExpression::property(object, field.0.text()))
            }

            Expr::RefBrack { refr, index, .. } => {
                let array = self.translate_expr_to_kql(refr)?;
                let index_expr = self.translate_expr_to_kql(index)?;
                Ok(KqlExpression::Index {
                    array: Box::new(array),
                    index: Box::new(index_expr),
                })
            }

            Expr::BoolExpr { op, lhs, rhs, .. } => {
                // Special handling for null comparisons
                match op {
                    BoolOp::Eq => {
                        // Check if this is a comparison with null
                        if matches!(rhs.as_ref(), Expr::Null { .. }) {
                            // x == null -> isnull(x)
                            let left_expr = self.translate_expr_to_kql(lhs)?;
                            return Ok(KqlExpression::function("isnull", vec![left_expr]));
                        } else if matches!(lhs.as_ref(), Expr::Null { .. }) {
                            // null == x -> isnull(x)
                            let right_expr = self.translate_expr_to_kql(rhs)?;
                            return Ok(KqlExpression::function("isnull", vec![right_expr]));
                        }
                    }
                    BoolOp::Ne => {
                        // Check if this is a comparison with null
                        if matches!(rhs.as_ref(), Expr::Null { .. }) {
                            // x != null -> isnotnull(x)
                            let left_expr = self.translate_expr_to_kql(lhs)?;
                            return Ok(KqlExpression::function("isnotnull", vec![left_expr]));
                        } else if matches!(lhs.as_ref(), Expr::Null { .. }) {
                            // null != x -> isnotnull(x)
                            let right_expr = self.translate_expr_to_kql(rhs)?;
                            return Ok(KqlExpression::function("isnotnull", vec![right_expr]));
                        }
                    }
                    _ => {} // For other operators, proceed with normal handling
                }

                // Normal boolean expression handling
                let left = self.translate_expr_to_kql(lhs)?;
                let right = self.translate_expr_to_kql(rhs)?;
                let kql_op = self.translate_bool_op(op)?;
                Ok(KqlExpression::Binary {
                    op: kql_op,
                    left: Box::new(left),
                    right: Box::new(right),
                })
            }

            Expr::ArithExpr { op, lhs, rhs, .. } => {
                let mut left = self.translate_expr_to_kql(lhs)?;
                let mut right = self.translate_expr_to_kql(rhs)?;

                // Add parentheses if needed based on operator precedence
                if let Expr::ArithExpr { op: child_op, .. } = lhs.as_ref() {
                    if self.needs_parentheses(op, child_op, false) {
                        left = KqlExpression::Parenthesized(Box::new(left));
                    }
                }

                if let Expr::ArithExpr { op: child_op, .. } = rhs.as_ref() {
                    if self.needs_parentheses(op, child_op, true) {
                        right = KqlExpression::Parenthesized(Box::new(right));
                    }
                }

                let kql_op = self.translate_arith_op(op)?;
                Ok(KqlExpression::Binary {
                    op: kql_op,
                    left: Box::new(left),
                    right: Box::new(right),
                })
            }

            Expr::BinExpr { op, lhs, rhs, .. } => {
                let left = self.translate_expr_to_kql(lhs)?;
                let right = self.translate_expr_to_kql(rhs)?;
                let kql_op = match op {
                    BinOp::Union => KqlBinaryOp::Union,
                    BinOp::Intersection => KqlBinaryOp::Intersect,
                };
                Ok(KqlExpression::Binary {
                    op: kql_op,
                    left: Box::new(left),
                    right: Box::new(right),
                })
            }

            Expr::Membership {
                value, collection, ..
            } => {
                let value_expr = self.translate_expr_to_kql(value)?;
                let collection_expr = self.translate_expr_to_kql(collection)?;
                Ok(KqlExpression::Binary {
                    op: KqlBinaryOp::In,
                    left: Box::new(value_expr),
                    right: Box::new(collection_expr),
                })
            }

            Expr::Call { fcn, params, .. } => self.translate_function_call(fcn, params),

            Expr::Object { fields, .. } => {
                // Object constructor: { "vm_id": vm.id, "health_id": health.health_id }
                // Convert to a KQL object-like representation using a function call
                // This creates a dynamic object that can be used in expressions
                let mut object_args = Vec::new();
                for (_, key_expr, value_expr) in fields {
                    if let Expr::String {
                        value: key_value, ..
                    } = key_expr.as_ref()
                    {
                        let key_name = key_value
                            .as_string()
                            .map_err(|_| anyhow::anyhow!("Invalid key"))?;
                        let value_kql = self.translate_expr_to_kql(value_expr.as_ref())?;
                        // Add key-value pairs as alternating arguments to pack function
                        object_args.push(KqlExpression::string_literal(key_name.as_ref()));
                        object_args.push(value_kql);
                    }
                }
                // Use KQL pack() function to create an object
                Ok(KqlExpression::function("pack", object_args))
            }

            Expr::UnaryExpr { expr, .. } => {
                // Handle unary minus
                let operand = self.translate_expr_to_kql(expr)?;
                Ok(KqlExpression::Unary {
                    op: KqlUnaryOp::Negate,
                    operand: Box::new(operand),
                })
            }

            _ => {
                bail!("Unsupported expression type: {:?}", expr)
            }
        }
    }

    fn translate_bool_op(&self, op: &BoolOp) -> Result<KqlBinaryOp> {
        match op {
            BoolOp::Eq => Ok(KqlBinaryOp::Equal),
            BoolOp::Ne => Ok(KqlBinaryOp::NotEqual),
            BoolOp::Lt => Ok(KqlBinaryOp::LessThan),
            BoolOp::Le => Ok(KqlBinaryOp::LessThanOrEqual),
            BoolOp::Gt => Ok(KqlBinaryOp::GreaterThan),
            BoolOp::Ge => Ok(KqlBinaryOp::GreaterThanOrEqual),
        }
    }

    fn translate_arith_op(&self, op: &ArithOp) -> Result<KqlBinaryOp> {
        match op {
            ArithOp::Add => Ok(KqlBinaryOp::Add),
            ArithOp::Sub => Ok(KqlBinaryOp::Subtract),
            ArithOp::Mul => Ok(KqlBinaryOp::Multiply),
            ArithOp::Div => Ok(KqlBinaryOp::Divide),
            ArithOp::Mod => Ok(KqlBinaryOp::Modulo),
        }
    }

    /// Get the precedence level of an arithmetic operator (higher number = higher precedence)
    fn get_arith_op_precedence(&self, op: &ArithOp) -> i32 {
        match op {
            ArithOp::Add | ArithOp::Sub => 1,
            ArithOp::Mul | ArithOp::Div | ArithOp::Mod => 2,
        }
    }

    /// Check if parentheses are needed when an expression with child_op is used
    /// as an operand in an expression with parent_op
    fn needs_parentheses(
        &self,
        parent_op: &ArithOp,
        child_op: &ArithOp,
        is_right_operand: bool,
    ) -> bool {
        let parent_prec = self.get_arith_op_precedence(parent_op);
        let child_prec = self.get_arith_op_precedence(child_op);

        // If child has lower precedence, it needs parentheses
        if child_prec < parent_prec {
            return true;
        }

        // For same precedence, we need parentheses in certain cases to preserve grouping
        if child_prec == parent_prec && is_right_operand {
            match (parent_op, child_op) {
                // Right associativity issues: (a - (b - c)) != (a - b - c)
                (ArithOp::Sub, ArithOp::Sub) | (ArithOp::Sub, ArithOp::Add) => true,
                (ArithOp::Div, ArithOp::Div) | (ArithOp::Div, ArithOp::Mul) => true,
                (ArithOp::Mod, ArithOp::Mod)
                | (ArithOp::Mod, ArithOp::Mul)
                | (ArithOp::Mod, ArithOp::Div) => true,
                // Mixed multiplication/division: a * (b / c) needs parentheses
                (ArithOp::Mul, ArithOp::Div) => true,
                _ => false,
            }
        } else {
            false
        }
    }

    fn translate_function_call(
        &mut self,
        fcn: &Expr,
        params: &[Ref<Expr>],
    ) -> Result<KqlExpression> {
        // Get the function name
        let func_name = match fcn {
            Expr::Var { value, .. } => value
                .as_string()
                .map_err(|_| anyhow::anyhow!("Invalid function name"))?
                .to_string(),
            Expr::RefDot { refr, field, .. } => {
                // Handle dotted function names like array.concat, strings.reverse, etc.
                if let Expr::Var { value, .. } = refr.as_ref() {
                    let base = value
                        .as_string()
                        .map_err(|_| anyhow::anyhow!("Invalid function base name"))?;
                    let field_name = field.0.text();
                    format!("{}.{}", base, field_name)
                } else {
                    bail!("Complex function expressions not supported")
                }
            }
            _ => bail!("Complex function expressions not supported"),
        };

        // Translate parameters
        let mut kql_args = Vec::new();
        for param in params {
            kql_args.push(self.translate_expr_to_kql(param)?);
        }

        // Map Rego builtin functions to KQL equivalents
        self.map_builtin_function(&func_name, kql_args)
    }

    fn map_builtin_function(
        &self,
        func_name: &str,
        args: Vec<KqlExpression>,
    ) -> Result<KqlExpression> {
        match func_name {
            // Perfect matches - same name and behavior
            "contains" => {
                if args.len() != 2 {
                    bail!("contains() expects 2 arguments");
                }
                Ok(KqlExpression::function("contains", args))
            }
            "endswith" => {
                if args.len() != 2 {
                    bail!("endswith() expects 2 arguments");
                }
                Ok(KqlExpression::function("endswith", args))
            }
            "startswith" => {
                if args.len() != 2 {
                    bail!("startswith() expects 2 arguments");
                }
                Ok(KqlExpression::function("startswith", args))
            }
            "split" => {
                if args.len() != 2 {
                    bail!("split() expects 2 arguments");
                }
                Ok(KqlExpression::function("split", args))
            }
            "substring" => {
                if args.len() != 3 {
                    bail!("substring() expects 3 arguments");
                }
                Ok(KqlExpression::function("substring", args))
            }
            "indexof" => {
                if args.len() != 2 {
                    bail!("indexof() expects 2 arguments");
                }
                Ok(KqlExpression::function("indexof", args))
            }
            "abs" => {
                if args.len() != 1 {
                    bail!("abs() expects 1 argument");
                }
                Ok(KqlExpression::function("abs", args))
            }
            "floor" => {
                if args.len() != 1 {
                    bail!("floor() expects 1 argument");
                }
                Ok(KqlExpression::function("floor", args))
            }
            "round" => {
                if args.len() == 1 {
                    Ok(KqlExpression::function("round", args))
                } else if args.len() == 2 {
                    // KQL round with precision
                    Ok(KqlExpression::function("round", args))
                } else {
                    bail!("round() expects 1 or 2 arguments");
                }
            }

            // Close equivalents - different names
            "concat" => {
                if args.len() != 2 {
                    bail!("concat() expects 2 arguments (delimiter, array)");
                }
                // Rego: concat(delimiter, array) -> KQL: strcat_delim(delimiter, ...)
                // Need to handle the array expansion
                Ok(KqlExpression::function("strcat_delim", args))
            }
            "lower" => {
                if args.len() != 1 {
                    bail!("lower() expects 1 argument");
                }
                Ok(KqlExpression::function("tolower", args))
            }
            "upper" => {
                if args.len() != 1 {
                    bail!("upper() expects 1 argument");
                }
                Ok(KqlExpression::function("toupper", args))
            }
            "replace" => {
                if args.len() != 3 {
                    bail!("replace() expects 3 arguments");
                }
                Ok(KqlExpression::function("replace_string", args))
            }
            "trim_space" => {
                if args.len() != 1 {
                    bail!("trim_space() expects 1 argument");
                }
                // KQL trim with space regex
                let mut trim_args = args;
                trim_args.push(KqlExpression::string_literal(" "));
                Ok(KqlExpression::function("trim", trim_args))
            }
            "ceil" => {
                if args.len() != 1 {
                    bail!("ceil() expects 1 argument");
                }
                Ok(KqlExpression::function("ceiling", args))
            }

            // Array/collection functions
            "count" => {
                if args.len() != 1 {
                    bail!("count() expects 1 argument");
                }
                // In most contexts, this will be used in aggregation
                // For now, treat as a scalar function
                Ok(KqlExpression::function("array_length", args))
            }

            // Type checking functions
            "is_string" => {
                if args.len() != 1 {
                    bail!("is_string() expects 1 argument");
                }
                Ok(KqlExpression::Binary {
                    op: KqlBinaryOp::Equal,
                    left: Box::new(KqlExpression::function("gettype", args)),
                    right: Box::new(KqlExpression::string_literal("string")),
                })
            }
            "is_number" => {
                if args.len() != 1 {
                    bail!("is_number() expects 1 argument");
                }
                let gettype_call = KqlExpression::function("gettype", args);
                // Check for both int and real types
                Ok(KqlExpression::Binary {
                    op: KqlBinaryOp::Or,
                    left: Box::new(KqlExpression::Binary {
                        op: KqlBinaryOp::Equal,
                        left: Box::new(gettype_call.clone()),
                        right: Box::new(KqlExpression::string_literal("int")),
                    }),
                    right: Box::new(KqlExpression::Binary {
                        op: KqlBinaryOp::Equal,
                        left: Box::new(gettype_call),
                        right: Box::new(KqlExpression::string_literal("real")),
                    }),
                })
            }
            "is_boolean" => {
                if args.len() != 1 {
                    bail!("is_boolean() expects 1 argument");
                }
                Ok(KqlExpression::Binary {
                    op: KqlBinaryOp::Equal,
                    left: Box::new(KqlExpression::function("gettype", args)),
                    right: Box::new(KqlExpression::string_literal("bool")),
                })
            }
            "is_array" => {
                if args.len() != 1 {
                    bail!("is_array() expects 1 argument");
                }
                Ok(KqlExpression::Binary {
                    op: KqlBinaryOp::Equal,
                    left: Box::new(KqlExpression::function("gettype", args)),
                    right: Box::new(KqlExpression::string_literal("array")),
                })
            }
            "is_object" => {
                if args.len() != 1 {
                    bail!("is_object() expects 1 argument");
                }
                Ok(KqlExpression::Binary {
                    op: KqlBinaryOp::Equal,
                    left: Box::new(KqlExpression::function("gettype", args)),
                    right: Box::new(KqlExpression::string_literal("object")),
                })
            }

            // JSON functions
            "json.marshal" => {
                if args.len() != 1 {
                    bail!("json.marshal() expects 1 argument");
                }
                Ok(KqlExpression::function("tostring", args))
            }
            "json.unmarshal" => {
                if args.len() != 1 {
                    bail!("json.unmarshal() expects 1 argument");
                }
                Ok(KqlExpression::function("parse_json", args))
            }

            // Additional commonly used functions
            "sprintf" => {
                if args.len() < 1 {
                    bail!("sprintf() expects at least 1 argument");
                }
                // KQL uses strcat for string concatenation or strcat_delim
                Ok(KqlExpression::function("strcat", args))
            }
            "to_number" => {
                if args.len() != 1 {
                    bail!("to_number() expects 1 argument");
                }
                Ok(KqlExpression::function("todouble", args))
            }
            "array.slice" => {
                if args.len() != 3 {
                    bail!("array.slice() expects 3 arguments");
                }
                // Rego uses exclusive end index, KQL uses inclusive end index
                // So we need to subtract 1 from the end parameter
                let mut kql_args = args;
                if let KqlExpression::Literal(KqlLiteral::Integer(num)) = &kql_args[2] {
                    kql_args[2] = KqlExpression::int_literal(num - 1);
                } else {
                    // For non-literal values, create a binary expression to subtract 1
                    kql_args[2] = KqlExpression::Binary {
                        op: KqlBinaryOp::Subtract,
                        left: Box::new(kql_args[2].clone()),
                        right: Box::new(KqlExpression::int_literal(1)),
                    };
                }
                Ok(KqlExpression::function("array_slice", kql_args))
            }
            "array.concat" => {
                if args.len() != 2 {
                    bail!("array.concat() expects 2 arguments");
                }
                Ok(KqlExpression::function("array_concat", args))
            }
            "array.reverse" => {
                if args.len() != 1 {
                    bail!("array.reverse() expects 1 argument");
                }
                Ok(KqlExpression::function("array_reverse", args))
            }
            "array.length" => {
                if args.len() != 1 {
                    bail!("array.length() expects 1 argument");
                }
                Ok(KqlExpression::function("array_length", args))
            }
            "strings.reverse" => {
                if args.len() != 1 {
                    bail!("strings.reverse() expects 1 argument");
                }
                Ok(KqlExpression::function("reverse", args))
            }
            "sort" => {
                if args.len() != 1 {
                    bail!("sort() expects 1 argument");
                }
                Ok(KqlExpression::function("array_sort_asc", args))
            }
            "trim_left" => {
                if args.len() != 2 {
                    bail!("trim_left() expects 2 arguments");
                }
                Ok(KqlExpression::function("trim_start", args))
            }
            "regex.match" => {
                if args.len() != 2 {
                    bail!("regex.match() expects 2 arguments");
                }
                // KQL regex match syntax: string matches regex "pattern"
                // args[0] is the pattern, args[1] is the string
                Ok(KqlExpression::Binary {
                    op: KqlBinaryOp::Matches,
                    left: Box::new(args[1].clone()),  // string
                    right: Box::new(args[0].clone()), // pattern directly
                })
            }
            "format_int" => {
                if args.len() != 2 {
                    bail!("format_int() expects 2 arguments");
                }
                // Just convert to string, ignore the base for now
                Ok(KqlExpression::function("tostring", vec![args[0].clone()]))
            }
            "is_null" => {
                if args.len() != 1 {
                    bail!("is_null() expects 1 argument");
                }
                Ok(KqlExpression::function("isnull", args))
            }
            "base64.encode" => {
                if args.len() != 1 {
                    bail!("base64.encode() expects 1 argument");
                }
                Ok(KqlExpression::function("base64_encode_tostring", args))
            }
            "base64.decode" => {
                if args.len() != 1 {
                    bail!("base64.decode() expects 1 argument");
                }
                Ok(KqlExpression::function("base64_decode_tostring", args))
            }
            "strings.replace_n" => {
                if args.len() != 4 {
                    bail!("strings.replace_n() expects 4 arguments");
                }
                // Use the first 3 args for replace_string, ignore the count for now
                let replace_args = args[0..3].to_vec();
                Ok(KqlExpression::function("replace_string", replace_args))
            }

            // Math functions
            "pow" => {
                if args.len() != 2 {
                    bail!("pow() expects 2 arguments");
                }
                Ok(KqlExpression::function("pow", args))
            }
            "sqrt" => {
                if args.len() != 1 {
                    bail!("sqrt() expects 1 argument");
                }
                Ok(KqlExpression::function("sqrt", args))
            }
            "sin" => {
                if args.len() != 1 {
                    bail!("sin() expects 1 argument");
                }
                Ok(KqlExpression::function("sin", args))
            }

            _ => {
                bail!("Unsupported builtin function: {}", func_name)
            }
        }
    }

    /// Translate a Rego array comprehension to KQL
    pub fn translate_comprehension(&mut self, term: &Expr, query: &Query) -> Result<KqlQuery> {
        // Extract the main table from the comprehension query
        let table = self.extract_table_from_query(query)?;
        let mut builder = KqlQueryBuilder::new().from_table(&table);

        // Process comprehension query (variable bindings and filters)
        for stmt in &query.stmts {
            builder = self.translate_literal_stmt(builder, stmt)?;
        }

        // Add the projection for the term
        let term_expr = self.translate_expr_to_kql(term)?;
        let column = KqlColumn {
            name: "value".to_string(),
            expression: term_expr,
            alias: None,
        };
        builder = builder.project(vec![column]);

        builder.build().map_err(|e| anyhow::anyhow!(e))
    }
}

impl Default for RegoToKqlIrTranslator {
    fn default() -> Self {
        Self::new(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{unstable::DatabaseParser, Source};

    #[test]
    fn test_simple_filter_rule() {
        let input = r#"
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

        let source = Source::from_contents("test.rego".to_string(), input.to_string()).unwrap();
        let mut parser = DatabaseParser::new(&source).unwrap();
        let module = parser.parse_database_module().unwrap();
        let rule = &module.policy[0];

        let mut translator =
            RegoToKqlIrTranslator::new(None).with_default_table("users".to_string());
        let kql_query = translator.translate_rule(rule).unwrap();

        assert_eq!(kql_query.source, "users");
        assert!(!kql_query.pipeline.is_empty());
    }

    #[test]
    fn test_membership_rule() {
        let input = r#"
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

        let source = Source::from_contents("test.rego".to_string(), input.to_string()).unwrap();
        let mut parser = DatabaseParser::new(&source).unwrap();
        let module = parser.parse_database_module().unwrap();
        let rule = &module.policy[0];

        let mut translator =
            RegoToKqlIrTranslator::new(None).with_default_table("users".to_string());
        let kql_query = translator.translate_rule(rule).unwrap();

        assert_eq!(kql_query.source, "users");
        assert!(!kql_query.pipeline.is_empty());

        // Check for membership operation
        if let KqlOperation::Where(expr) = &kql_query.pipeline[0] {
            if let KqlExpression::Binary { op, .. } = expr {
                assert_eq!(*op, KqlBinaryOp::In);
            }
        }
    }

    #[test]
    fn test_binary_serialization() {
        let input = r#"
            package test
            
            import rego.v1
            
            allowed_users contains result if {
                some user in data.users
                user.role == "admin"
                result := {
                    "name": user.name,
                    "role": user.role
                }
            }
        "#;

        let source = Source::from_contents("test.rego".to_string(), input.to_string()).unwrap();
        let mut parser = DatabaseParser::new(&source).unwrap();
        let module = parser.parse_database_module().unwrap();
        let rule = &module.policy[0];

        let mut translator =
            RegoToKqlIrTranslator::new(None).with_default_table("users".to_string());
        let kql_query = translator.translate_rule(rule).unwrap();

        // Test binary serialization
        let binary_data = kql_query.to_binary().unwrap();
        let deserialized = KqlQuery::from_binary(&binary_data).unwrap();

        assert_eq!(kql_query, deserialized);
    }
}
