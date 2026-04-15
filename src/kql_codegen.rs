// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! KQL IR to KQL Compiler
//!
//! This module compiles KQL Intermediate Representation to actual KQL query strings.
//! It handles query optimization and proper KQL syntax generation.

use crate::kql_ir::*;
use alloc::{boxed::Box, format, string::String, string::ToString as _, vec::Vec};

/// KQL Code Generator
#[derive(Debug)]
pub struct KqlCodeGenerator {
    /// Whether to generate pretty-printed KQL
    pretty_print: bool,
}

impl KqlCodeGenerator {
    pub const fn new() -> Self {
        Self { pretty_print: true }
    }

    pub const fn with_pretty_print(mut self, pretty: bool) -> Self {
        self.pretty_print = pretty;
        self
    }

    /// Generate KQL from IR
    pub fn generate(&mut self, query: &KqlQuery) -> String {
        let mut kql = String::new();

        // Generate let statements first
        for let_stmt in &query.let_statements {
            kql.push_str(&format!(
                "let {} = {};",
                let_stmt.name,
                self.generate_expression(&let_stmt.value)
            ));
            if self.pretty_print {
                kql.push('\n');
            } else {
                kql.push(' ');
            }
        }

        // Start with the source table
        kql.push_str(&query.source);

        // Add pipeline operations
        for operation in &query.pipeline {
            if self.pretty_print {
                kql.push('\n');
                kql.push_str("| ");
            } else {
                kql.push_str(" | ");
            }
            kql.push_str(&self.generate_operation(operation));
        }

        kql
    }

    fn generate_operation(&mut self, operation: &KqlOperation) -> String {
        match *operation {
            KqlOperation::Where(ref expr) => {
                format!("where {}", self.generate_expression(expr))
            }
            KqlOperation::Project(ref columns) => {
                let cols = columns
                    .iter()
                    .map(|col| self.generate_column(col))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("project {}", cols)
            }
            KqlOperation::Extend(ref columns) => {
                let cols = columns
                    .iter()
                    .map(|col| self.generate_column(col))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("extend {}", cols)
            }
            KqlOperation::Take(ref count) => {
                format!("take {}", count)
            }
            KqlOperation::Order(ref order_by) => {
                let orders = order_by
                    .iter()
                    .map(|o| self.generate_order_by(o))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("order by {}", orders)
            }
            KqlOperation::Summarize {
                ref group_by,
                ref aggregates,
            } => {
                let mut parts = Vec::new();

                if !aggregates.is_empty() {
                    let aggs = aggregates
                        .iter()
                        .map(|agg| self.generate_aggregate(agg))
                        .collect::<Vec<_>>()
                        .join(", ");
                    parts.push(aggs);
                }

                if !group_by.is_empty() {
                    let groups = group_by
                        .iter()
                        .map(|expr| self.generate_expression(expr))
                        .collect::<Vec<_>>()
                        .join(", ");
                    parts.push(format!("by {}", groups));
                }

                format!("summarize {}", parts.join(" "))
            }
            KqlOperation::Join {
                ref kind,
                ref source,
                ref on,
            } => {
                let join_type = Self::generate_join_kind(kind);
                let table_repr = match *source {
                    KqlJoinSource::Table(ref t) => t.clone(),
                    KqlJoinSource::Filtered {
                        ref table,
                        ref filters,
                    } => {
                        if filters.is_empty() {
                            table.clone()
                        } else {
                            let filter_strs: Vec<String> = filters
                                .iter()
                                .map(|f| format!("where {}", self.generate_expression(f)))
                                .collect();
                            if self.pretty_print {
                                format!("({}\n    | {})", table, filter_strs.join("\n    | "))
                            } else {
                                format!("({} | {})", table, filter_strs.join(" | "))
                            }
                        }
                    }
                    KqlJoinSource::Subquery(ref subquery) => {
                        if self.pretty_print {
                            let subquery_str = self.generate_subquery_pretty(subquery);
                            format!("(\n{}\n  )", subquery_str)
                        } else {
                            format!("({})", self.generate(subquery))
                        }
                    }
                };
                let conditions = on
                    .iter()
                    .map(|cond| self.generate_join_condition(cond))
                    .collect::<Vec<_>>()
                    .join(" and ");

                if self.pretty_print {
                    format!("{} {}\n  on {}", join_type, table_repr, conditions)
                } else {
                    format!("{} {} on {}", join_type, table_repr, conditions)
                }
            }
            KqlOperation::Union(ref query) => {
                format!("union ({})", self.generate(query))
            }
            KqlOperation::Distinct(ref expressions) => {
                if expressions.is_empty() {
                    "distinct *".to_string()
                } else {
                    let exprs = expressions
                        .iter()
                        .map(|expr| self.generate_expression(expr))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("distinct {}", exprs)
                }
            }
        }
    }

    fn generate_expression(&mut self, expr: &KqlExpression) -> String {
        match *expr {
            KqlExpression::Column(ref name) => name.clone(),
            KqlExpression::Literal(ref literal) => Self::generate_literal(literal),
            KqlExpression::Binary {
                ref op,
                ref left,
                ref right,
            } => {
                let left_str = self.generate_expression(left);
                let right_str = self.generate_expression(right);
                let op_str = Self::generate_binary_op(op);

                // Handle special cases for KQL syntax
                match *op {
                    KqlBinaryOp::In => format!("{} in ({})", left_str, right_str),
                    KqlBinaryOp::HasAny => format!("{} has_any ({})", left_str, right_str),
                    KqlBinaryOp::HasAll => format!("{} has_all ({})", left_str, right_str),
                    KqlBinaryOp::Contains => format!("{} contains {}", left_str, right_str),
                    KqlBinaryOp::StartsWith => format!("{} startswith {}", left_str, right_str),
                    KqlBinaryOp::EndsWith => format!("{} endswith {}", left_str, right_str),
                    KqlBinaryOp::Matches => format!("{} matches regex {}", left_str, right_str),
                    KqlBinaryOp::Or => {
                        // Add parentheses around OR operations to ensure proper precedence
                        format!("({} {} {})", left_str, op_str, right_str)
                    }
                    _ => format!("{} {} {}", left_str, op_str, right_str),
                }
            }
            KqlExpression::Unary {
                ref op,
                ref operand,
            } => {
                let operand_str = self.generate_expression(operand);
                match *op {
                    KqlUnaryOp::Not => format!("not({})", operand_str),
                    KqlUnaryOp::Negate => format!("-{}", operand_str),
                    KqlUnaryOp::IsNull => format!("isnull({})", operand_str),
                    KqlUnaryOp::IsNotNull => format!("isnotnull({})", operand_str),
                    KqlUnaryOp::IsEmpty => format!("isempty({})", operand_str),
                    KqlUnaryOp::IsNotEmpty => format!("isnotempty({})", operand_str),
                }
            }
            KqlExpression::Function { ref name, ref args } => {
                // Handle special string functions that use infix notation in KQL
                match name.as_str() {
                    "contains" | "startswith" | "endswith" if args.len() == 2 => {
                        // Safety: guard ensures args has exactly 2 elements
                        if let (Some(arg0), Some(arg1)) = (args.first(), args.get(1)) {
                            let left_str = self.generate_expression(arg0);
                            let right_str = self.generate_expression(arg1);
                            format!("{} {} {}", left_str, name, right_str)
                        } else {
                            // Unreachable due to guard, but provide fallback
                            let arg_strs = args
                                .iter()
                                .map(|a| self.generate_expression(a))
                                .collect::<Vec<_>>()
                                .join(", ");
                            format!("{}({})", name, arg_strs)
                        }
                    }
                    _ => {
                        let arg_strs = args
                            .iter()
                            .map(|arg| self.generate_expression(arg))
                            .collect::<Vec<_>>()
                            .join(", ");
                        format!("{}({})", name, arg_strs)
                    }
                }
            }
            KqlExpression::Array(ref items) => {
                let item_strs = items
                    .iter()
                    .map(|item| self.generate_expression(item))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("pack_array({})", item_strs)
            }
            KqlExpression::Property {
                ref object,
                ref property,
            } => {
                let object_str = self.generate_expression(object);
                format!("{}.{}", object_str, property)
            }
            KqlExpression::Index {
                ref array,
                ref index,
            } => {
                let array_str = self.generate_expression(array);
                let index_str = self.generate_expression(index);
                format!("{}[{}]", array_str, index_str)
            }
            KqlExpression::Case {
                ref conditions,
                ref default,
            } => {
                let mut case_str = String::from("case(");

                for (i, pair) in conditions.iter().enumerate() {
                    if i > 0 {
                        case_str.push_str(", ");
                    }
                    case_str.push_str(&format!(
                        "{}, {}",
                        self.generate_expression(&pair.0),
                        self.generate_expression(&pair.1)
                    ));
                }

                default.as_ref().map_or_else(
                    || (),
                    |default_expr| {
                        case_str.push_str(", ");
                        case_str.push_str(&self.generate_expression(default_expr));
                    },
                );

                case_str.push(')');
                case_str
            }
            KqlExpression::Parenthesized(ref expr) => {
                // Generate expression with parentheses to preserve precedence
                format!("({})", self.generate_expression(expr))
            }
            KqlExpression::Subquery(ref query) => {
                // Generate subquery in parentheses
                format!("({})", self.generate(query))
            }
        }
    }

    fn generate_literal(literal: &KqlLiteral) -> String {
        match *literal {
            KqlLiteral::String(ref s) => {
                // Escape backslashes and quotes for KQL string literals
                let escaped = s.replace('\\', "\\\\").replace('\"', "\\\"");
                format!("\"{}\"", escaped)
            }
            KqlLiteral::Integer(i) => i.to_string(),
            KqlLiteral::Float(f) => f.to_string(),
            KqlLiteral::Boolean(b) => {
                if b {
                    "true".to_string()
                } else {
                    "false".to_string()
                }
            }
            KqlLiteral::Null => "null".to_string(),
            KqlLiteral::DateTime(ref dt) => format!("datetime({})", dt),
            KqlLiteral::TimeSpan(ref ts) => format!("timespan({})", ts),
            KqlLiteral::Guid(ref guid) => format!("guid({})", guid),
        }
    }

    const fn generate_binary_op(op: &KqlBinaryOp) -> &'static str {
        match *op {
            KqlBinaryOp::Equal => "==",
            KqlBinaryOp::NotEqual => "!=",
            KqlBinaryOp::LessThan => "<",
            KqlBinaryOp::LessThanOrEqual => "<=",
            KqlBinaryOp::GreaterThan => ">",
            KqlBinaryOp::GreaterThanOrEqual => ">=",
            KqlBinaryOp::Add => "+",
            KqlBinaryOp::Subtract => "-",
            KqlBinaryOp::Multiply => "*",
            KqlBinaryOp::Divide => "/",
            KqlBinaryOp::Modulo => "%",
            KqlBinaryOp::And => "and",
            KqlBinaryOp::Or => "or",
            KqlBinaryOp::Contains => "contains",
            KqlBinaryOp::StartsWith => "startswith",
            KqlBinaryOp::EndsWith => "endswith",
            KqlBinaryOp::Matches => "matches",
            KqlBinaryOp::In => "in",
            KqlBinaryOp::HasAny => "has_any",
            KqlBinaryOp::HasAll => "has_all",
            KqlBinaryOp::Union => "union",
            KqlBinaryOp::Intersect => "intersect",
        }
    }

    fn generate_column(&mut self, column: &KqlColumn) -> String {
        let expr_str = self.generate_expression(&column.expression);
        column.alias.as_ref().map_or_else(
            || format!("{} = {}", column.name, expr_str),
            |alias| {
                // If the alias is the same as the expression, just output the expression
                if alias == &expr_str {
                    expr_str.clone()
                } else {
                    format!("{} = {}", alias, expr_str)
                }
            },
        )
    }

    fn generate_order_by(&mut self, order: &KqlOrderBy) -> String {
        let expr_str = self.generate_expression(&order.expression);
        let dir = &order.direction;
        match *dir {
            KqlSortDirection::Ascending => format!("{} asc", expr_str),
            KqlSortDirection::Descending => format!("{} desc", expr_str),
        }
    }

    fn generate_aggregate(&mut self, aggregate: &KqlAggregate) -> String {
        let agg_fn = &aggregate.function;
        let func_str = match *agg_fn {
            KqlAggregateFunction::Count => "count()".to_string(),
            KqlAggregateFunction::CountIf => aggregate.expression.as_ref().map_or_else(
                || "count()".to_string(),
                |expr| format!("countif({})", self.generate_expression(expr)),
            ),
            KqlAggregateFunction::Sum => aggregate.expression.as_ref().map_or_else(
                || "sum()".to_string(),
                |expr| format!("sum({})", self.generate_expression(expr)),
            ),
            KqlAggregateFunction::Avg => aggregate.expression.as_ref().map_or_else(
                || "avg()".to_string(),
                |expr| format!("avg({})", self.generate_expression(expr)),
            ),
            KqlAggregateFunction::Min => aggregate.expression.as_ref().map_or_else(
                || "min()".to_string(),
                |expr| format!("min({})", self.generate_expression(expr)),
            ),
            KqlAggregateFunction::Max => aggregate.expression.as_ref().map_or_else(
                || "max()".to_string(),
                |expr| format!("max({})", self.generate_expression(expr)),
            ),
            KqlAggregateFunction::Any => aggregate.expression.as_ref().map_or_else(
                || "any()".to_string(),
                |expr| format!("any({})", self.generate_expression(expr)),
            ),
            KqlAggregateFunction::StdDev => aggregate.expression.as_ref().map_or_else(
                || "stdev()".to_string(),
                |expr| format!("stdev({})", self.generate_expression(expr)),
            ),
            KqlAggregateFunction::Variance => aggregate.expression.as_ref().map_or_else(
                || "variance()".to_string(),
                |expr| format!("variance({})", self.generate_expression(expr)),
            ),
            KqlAggregateFunction::Percentile(ref p) => aggregate.expression.as_ref().map_or_else(
                || format!("percentile({}, {})", "*", p),
                |expr| format!("percentile({}, {})", self.generate_expression(expr), p),
            ),
            KqlAggregateFunction::MakeList => aggregate.expression.as_ref().map_or_else(
                || "make_list()".to_string(),
                |expr| format!("make_list({})", self.generate_expression(expr)),
            ),
            KqlAggregateFunction::MakeSet => aggregate.expression.as_ref().map_or_else(
                || "make_set()".to_string(),
                |expr| format!("make_set({})", self.generate_expression(expr)),
            ),
            KqlAggregateFunction::ArraySort => aggregate.expression.as_ref().map_or_else(
                || "array_sort_asc(make_list())".to_string(),
                |expr| {
                    format!(
                        "array_sort_asc(make_list({}))",
                        self.generate_expression(expr)
                    )
                },
            ),
        };

        format!("{} = {}", aggregate.alias, func_str)
    }

    const fn generate_join_kind(kind: &KqlJoinKind) -> &'static str {
        match *kind {
            KqlJoinKind::Inner => "join kind=inner",
            KqlJoinKind::LeftOuter => "join kind=leftouter",
            KqlJoinKind::RightOuter => "join kind=rightouter",
            KqlJoinKind::FullOuter => "join kind=fullouter",
            KqlJoinKind::LeftAnti => "join kind=leftanti",
            KqlJoinKind::RightAnti => "join kind=rightanti",
            KqlJoinKind::LeftSemi => "join kind=leftsemi",
            KqlJoinKind::RightSemi => "join kind=rightsemi",
        }
    }

    fn generate_join_condition(&mut self, condition: &KqlJoinCondition) -> String {
        let left_str = self.generate_join_expression(&condition.left, "$left");
        let right_str = self.generate_join_expression(&condition.right, "$right");
        let op_str = Self::generate_binary_op(&condition.operator);
        format!("{} {} {}", left_str, op_str, right_str)
    }

    fn generate_join_expression(&mut self, expr: &KqlExpression, table_prefix: &str) -> String {
        match *expr {
            KqlExpression::Column(ref name) => format!("{}.{}", table_prefix, name),
            _ => self.generate_expression(expr), // For non-column expressions, generate normally
        }
    }

    fn generate_subquery_pretty(&mut self, query: &KqlQuery) -> String {
        let mut kql = String::new();
        let indent = "    "; // 4 spaces for subquery indentation

        // Generate let statements first
        for let_stmt in &query.let_statements {
            kql.push_str(&format!(
                "{}let {} = {};",
                indent,
                let_stmt.name,
                self.generate_expression(&let_stmt.value)
            ));
            kql.push('\n');
        }

        // Start with the source table
        kql.push_str(indent);
        kql.push_str(&query.source);

        // Add pipeline operations with proper indentation
        for operation in &query.pipeline {
            kql.push('\n');
            kql.push_str(indent);
            kql.push_str("| ");
            kql.push_str(&self.generate_operation(operation));
        }

        kql
    }
}

impl Default for KqlCodeGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Query optimizer for KQL IR
#[derive(Debug)]
pub struct KqlOptimizer;

impl KqlOptimizer {
    pub const fn new() -> Self {
        Self
    }

    /// Optimize a KQL query
    pub fn optimize(&self, query: &KqlQuery) -> KqlQuery {
        let mut optimized = query.clone();

        // Apply optimization passes
        optimized = Self::push_down_filters(optimized);
        optimized = Self::combine_filters(optimized);
        optimized = Self::eliminate_redundant_operations(optimized);

        optimized
    }

    /// Push filter operations down in the pipeline
    const fn push_down_filters(query: KqlQuery) -> KqlQuery {
        // Don't push down filters - this breaks cross-table conditions that need to be applied after joins
        // TODO: Implement smarter filter pushdown that respects join dependencies
        query
    }

    /// Combine multiple filter operations into a single one
    fn combine_filters(mut query: KqlQuery) -> KqlQuery {
        let mut combined_pipeline = Vec::new();
        let mut current_filter: Option<KqlExpression> = None;

        for op in query.pipeline {
            match op {
                KqlOperation::Where(expr) => match current_filter {
                    None => current_filter = Some(expr),
                    Some(existing) => {
                        current_filter = Some(KqlExpression::Binary {
                            op: KqlBinaryOp::And,
                            left: Box::new(existing),
                            right: Box::new(expr),
                        });
                    }
                },
                _ => {
                    if let Some(filter) = current_filter.take() {
                        combined_pipeline.push(KqlOperation::Where(filter));
                    }
                    combined_pipeline.push(op);
                }
            }
        }

        if let Some(filter) = current_filter {
            combined_pipeline.push(KqlOperation::Where(filter));
        }

        query.pipeline = combined_pipeline;
        query
    }

    /// Eliminate redundant operations
    fn eliminate_redundant_operations(mut query: KqlQuery) -> KqlQuery {
        // Remove consecutive project operations (keep only the last one)
        let mut filtered_pipeline = Vec::new();
        let mut last_project: Option<KqlOperation> = None;

        for op in query.pipeline {
            match op {
                KqlOperation::Project(_) => {
                    if let Some(prev_project) = last_project.take() {
                        // Skip the previous project operation
                        let _ = prev_project;
                    }
                    last_project = Some(op);
                }
                _ => {
                    if let Some(project) = last_project.take() {
                        filtered_pipeline.push(project);
                    }
                    filtered_pipeline.push(op);
                }
            }
        }

        if let Some(project) = last_project {
            filtered_pipeline.push(project);
        }

        query.pipeline = filtered_pipeline;
        query
    }
}

impl Default for KqlOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vec;

    #[test]
    fn test_simple_query_generation() -> anyhow::Result<()> {
        let query = KqlQueryBuilder::new()
            .from_table("users")
            .where_clause(KqlExpression::equals(
                KqlExpression::column("role"),
                KqlExpression::string_literal("admin"),
            ))
            .take(10)
            .build()
            .map_err(|e| anyhow::anyhow!(e))?;

        let mut generator = KqlCodeGenerator::new().with_pretty_print(false);
        let kql = generator.generate(&query);

        anyhow::ensure!(kql.contains("users"), "expected 'users' in KQL");
        anyhow::ensure!(kql.contains("where"), "expected 'where' in KQL");
        anyhow::ensure!(
            kql.contains("role == \"admin\""),
            "expected role filter in KQL"
        );
        anyhow::ensure!(kql.contains("take 10"), "expected 'take 10' in KQL");
        Ok(())
    }

    #[test]
    fn test_aggregation_query() -> anyhow::Result<()> {
        let query = KqlQueryBuilder::new()
            .from_table("events")
            .summarize(
                vec![KqlExpression::column("category")],
                vec![KqlAggregate {
                    function: KqlAggregateFunction::Count,
                    expression: None,
                    alias: "event_count".to_string(),
                }],
            )
            .build()
            .map_err(|e| anyhow::anyhow!(e))?;

        let mut generator = KqlCodeGenerator::new().with_pretty_print(false);
        let kql = generator.generate(&query);

        anyhow::ensure!(kql.contains("events"), "expected 'events' in KQL");
        anyhow::ensure!(kql.contains("summarize"), "expected 'summarize' in KQL");
        anyhow::ensure!(
            kql.contains("event_count = count()"),
            "expected aggregate in KQL"
        );
        anyhow::ensure!(kql.contains("by category"), "expected 'by category' in KQL");
        Ok(())
    }

    #[test]
    fn test_query_optimization() -> anyhow::Result<()> {
        let mut query = KqlQueryBuilder::new()
            .from_table("logs")
            .where_clause(KqlExpression::equals(
                KqlExpression::column("level"),
                KqlExpression::string_literal("error"),
            ))
            .where_clause(KqlExpression::equals(
                KqlExpression::column("service"),
                KqlExpression::string_literal("web"),
            ))
            .build()
            .map_err(|e| anyhow::anyhow!(e))?;

        // Add operations manually to test optimization
        query
            .pipeline
            .push(KqlOperation::Where(KqlExpression::equals(
                KqlExpression::column("timestamp"),
                KqlExpression::string_literal("today"),
            )));

        let optimizer = KqlOptimizer::new();
        let result_query = optimizer.optimize(&query);

        // Should have combined filters
        let where_count = result_query
            .pipeline
            .iter()
            .filter(|op| matches!(*op, KqlOperation::Where(_)))
            .count();

        anyhow::ensure!(
            where_count == 1,
            "all filters should be combined, got {}",
            where_count
        ); // All filters should be combined
        Ok(())
    }

    #[test]
    fn test_complex_expression() {
        let expr = KqlExpression::Binary {
            op: KqlBinaryOp::And,
            left: Box::new(KqlExpression::equals(
                KqlExpression::column("status"),
                KqlExpression::string_literal("active"),
            )),
            right: Box::new(KqlExpression::Binary {
                op: KqlBinaryOp::GreaterThan,
                left: Box::new(KqlExpression::column("age")),
                right: Box::new(KqlExpression::int_literal(18)),
            }),
        };

        let mut generator = KqlCodeGenerator::new();
        let kql_expr = generator.generate_expression(&expr);

        assert!(kql_expr.contains("status == \"active\""));
        assert!(kql_expr.contains("age > 18"));
        assert!(kql_expr.contains("and"));
    }
}
