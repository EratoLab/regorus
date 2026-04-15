// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SQL IR to SQL Compiler
//!
//! This module compiles SQL Intermediate Representation to actual SQL query strings.
//! It handles query optimization and proper SQL syntax generation.

use crate::sql_ir::*;
use alloc::{boxed::Box, format, string::String, string::ToString as _, vec::Vec};

/// SQL Code Generator
#[derive(Debug)]
pub struct SqlCodeGenerator {
    /// Whether to generate pretty-printed SQL
    pretty_print: bool,
    /// SQL dialect (for dialect-specific syntax)
    dialect: SqlDialect,
}

/// Supported SQL dialects
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SqlDialect {
    /// Standard SQL (ANSI SQL)
    Standard,
    /// PostgreSQL
    PostgreSQL,
    /// MySQL/MariaDB
    MySQL,
    /// SQLite
    SQLite,
    /// Microsoft SQL Server
    TSQL,
}

impl SqlCodeGenerator {
    pub const fn new() -> Self {
        Self {
            pretty_print: true,
            dialect: SqlDialect::Standard,
        }
    }

    pub const fn with_pretty_print(mut self, pretty: bool) -> Self {
        self.pretty_print = pretty;
        self
    }

    pub const fn with_dialect(mut self, dialect: SqlDialect) -> Self {
        self.dialect = dialect;
        self
    }

    /// Generate SQL from IR
    pub fn generate(&mut self, query: &SqlQuery) -> String {
        let mut sql = String::new();

        // Generate CTEs (WITH clauses)
        if !query.ctes.is_empty() {
            sql.push_str("WITH ");
            let cte_strs: Vec<String> = query
                .ctes
                .iter()
                .enumerate()
                .map(|(i, cte)| {
                    let cte_sql = if self.pretty_print {
                        format!(
                            "{} AS (\n{}\n)",
                            cte.name,
                            self.generate_subquery_pretty(&cte.query)
                        )
                    } else {
                        format!("{} AS ({})", cte.name, self.generate(&cte.query))
                    };

                    if i > 0 {
                        format!(",\n{}", cte_sql)
                    } else {
                        cte_sql
                    }
                })
                .collect();

            sql.push_str(&cte_strs.join(""));
            if self.pretty_print {
                sql.push('\n');
            }
        }

        // Start with SELECT
        sql.push_str("SELECT ");

        // Handle DISTINCT if present
        let distinct = query
            .pipeline
            .iter()
            .any(|op| matches!(*op, SqlOperation::Distinct(_)));
        if distinct {
            sql.push_str("DISTINCT ");
        }

        // Generate projection
        let projection = self.generate_projection(query);
        sql.push_str(&projection);

        // Add FROM clause
        if self.pretty_print {
            sql.push_str("\nFROM ");
        } else {
            sql.push_str(" FROM ");
        }
        sql.push_str(&query.source);

        // Add pipeline operations
        for operation in &query.pipeline {
            // Skip DISTINCT as it's already handled in SELECT
            if matches!(*operation, SqlOperation::Distinct(_)) {
                continue;
            }

            self.generate_operation(&mut sql, operation);
        }

        sql
    }

    fn generate_operation(&mut self, sql: &mut String, operation: &SqlOperation) {
        match *operation {
            SqlOperation::Where(ref expr) => {
                if self.pretty_print {
                    sql.push_str("\nWHERE ");
                } else {
                    sql.push_str(" WHERE ");
                }
                sql.push_str(&self.generate_expression(expr));
            }
            SqlOperation::Project(ref _columns) => {
                // Project is handled in the SELECT clause
                // This operation is mainly for internal use
            }
            SqlOperation::Extend(ref _columns) => {
                // Extend is handled by modifying the projection
                // This operation is mainly for internal use
            }
            SqlOperation::Limit(ref count) => {
                if self.pretty_print {
                    sql.push_str(&format!("\nLIMIT {}", count));
                } else {
                    sql.push_str(&format!(" LIMIT {}", count));
                }
            }
            SqlOperation::Order(ref order_by) => {
                if self.pretty_print {
                    sql.push_str("\nORDER BY ");
                } else {
                    sql.push_str(" ORDER BY ");
                }
                let orders = order_by
                    .iter()
                    .map(|o| self.generate_order_by(o))
                    .collect::<Vec<_>>()
                    .join(", ");
                sql.push_str(&orders);
            }
            SqlOperation::Aggregate {
                ref group_by,
                aggregates: _,
                ref having,
            } => {
                if !group_by.is_empty() {
                    if self.pretty_print {
                        sql.push_str("\nGROUP BY ");
                    } else {
                        sql.push_str(" GROUP BY ");
                    }
                    let groups = group_by
                        .iter()
                        .map(|expr| self.generate_expression(expr))
                        .collect::<Vec<_>>()
                        .join(", ");
                    sql.push_str(&groups);
                }

                if let Some(having_expr) = having {
                    if self.pretty_print {
                        sql.push_str("\nHAVING ");
                    } else {
                        sql.push_str(" HAVING ");
                    }
                    sql.push_str(&self.generate_expression(having_expr));
                }
            }
            SqlOperation::Join {
                ref kind,
                ref source,
                ref on,
            } => {
                let join_type = SqlCodeGenerator::generate_join_kind(kind);
                let table_repr = match *source {
                    SqlJoinSource::Table(ref t) => t.clone(),
                    SqlJoinSource::Filtered {
                        ref table,
                        ref filters,
                    } => {
                        if filters.is_empty() {
                            table.clone()
                        } else {
                            let filter_str = filters
                                .iter()
                                .map(|f| self.generate_expression(f))
                                .collect::<Vec<_>>()
                                .join(" AND ");
                            format!("({} WHERE {})", table, filter_str)
                        }
                    }
                    SqlJoinSource::Subquery(ref subquery) => {
                        if self.pretty_print {
                            format!("(\n{}\n)", self.generate_subquery_pretty(subquery))
                        } else {
                            format!("({})", self.generate(subquery))
                        }
                    }
                };

                if self.pretty_print {
                    sql.push_str(&format!("\n{} {}", join_type, table_repr));
                } else {
                    sql.push_str(&format!(" {} {}", join_type, table_repr));
                }

                if !on.is_empty() {
                    if self.pretty_print {
                        sql.push_str("\n  ON ");
                    } else {
                        sql.push_str(" ON ");
                    }
                    let conditions = on
                        .iter()
                        .map(|cond| self.generate_join_condition(cond))
                        .collect::<Vec<_>>()
                        .join(" AND ");
                    sql.push_str(&conditions);
                }
            }
            SqlOperation::Union(ref query) => {
                if self.pretty_print {
                    sql.push_str(&format!("\nUNION\n{}", self.generate(query)));
                } else {
                    sql.push_str(&format!(" UNION {}", self.generate(query)));
                }
            }
            SqlOperation::Distinct(_) => {
                // DISTINCT is handled in the SELECT clause
            }
        }
    }

    fn generate_projection(&mut self, query: &SqlQuery) -> String {
        // Check if there's a projection operation in the pipeline
        for operation in &query.pipeline {
            if let SqlOperation::Project(columns) = operation {
                let cols = columns
                    .iter()
                    .map(|col| self.generate_column(col))
                    .collect::<Vec<_>>()
                    .join(", ");
                return cols;
            }
        }

        // Check if there's an aggregate operation and include aggregates in SELECT
        for operation in &query.pipeline {
            if let SqlOperation::Aggregate {
                aggregates,
                group_by,
                ..
            } = operation
            {
                let mut select_parts = Vec::new();

                // Add GROUP BY columns
                for col in group_by {
                    select_parts.push(self.generate_expression(col));
                }

                // Add aggregate functions
                for agg in aggregates {
                    select_parts.push(self.generate_aggregate(agg));
                }

                return select_parts.join(", ");
            }
        }

        // Default to SELECT *
        "*".to_string()
    }

    fn generate_expression(&mut self, expr: &SqlExpression) -> String {
        match *expr {
            SqlExpression::Column(ref name) => {
                // Quote column names if they contain special characters or are SQL keywords
                if self.needs_quoting(name) {
                    self.quote_identifier(name)
                } else {
                    name.clone()
                }
            }
            SqlExpression::Literal(ref literal) => self.generate_literal(literal),
            SqlExpression::InjectedVariable(ref name) => name.clone(),
            SqlExpression::Binary {
                ref op,
                ref left,
                ref right,
            } => {
                let left_str = self.generate_expression(left);
                let op_str = Self::generate_binary_op(op);

                // Handle IN/NOT IN specially: when right side is an Array, generate items
                // directly as comma-separated list inside parens (avoid double-wrapping).
                match *op {
                    SqlBinaryOp::In | SqlBinaryOp::NotIn => {
                        let items_str = match right.as_ref() {
                            SqlExpression::Array(items) => items
                                .iter()
                                .map(|i| self.generate_expression(i))
                                .collect::<Vec<_>>()
                                .join(", "),
                            _ => self.generate_expression(right),
                        };
                        return if matches!(*op, SqlBinaryOp::In) {
                            format!("{} IN ({})", left_str, items_str)
                        } else {
                            format!("{} NOT IN ({})", left_str, items_str)
                        };
                    }
                    _ => {}
                }

                let right_str = self.generate_expression(right);

                // Handle special cases for SQL syntax
                match *op {
                    SqlBinaryOp::In => format!("{} IN ({})", left_str, right_str),
                    SqlBinaryOp::NotIn => format!("{} NOT IN ({})", left_str, right_str),
                    SqlBinaryOp::Like => format!("{} LIKE {}", left_str, right_str),
                    SqlBinaryOp::NotLike => format!("{} NOT LIKE {}", left_str, right_str),
                    SqlBinaryOp::ILike => {
                        if matches!(self.dialect, SqlDialect::PostgreSQL) {
                            format!("{} ILIKE {}", left_str, right_str)
                        } else {
                            // For other dialects, use LOWER() for case-insensitive comparison
                            format!("LOWER({}) LIKE LOWER({})", left_str, right_str)
                        }
                    }
                    SqlBinaryOp::NotILike => {
                        if matches!(self.dialect, SqlDialect::PostgreSQL) {
                            format!("{} NOT ILIKE {}", left_str, right_str)
                        } else {
                            format!("LOWER({}) NOT LIKE LOWER({})", left_str, right_str)
                        }
                    }
                    SqlBinaryOp::IsNull => format!("{} IS NULL", left_str),
                    SqlBinaryOp::IsNotNull => format!("{} IS NOT NULL", left_str),
                    SqlBinaryOp::Or => {
                        // Add parentheses around OR operations to ensure proper precedence
                        format!("({} {} {})", left_str, op_str, right_str)
                    }
                    _ => format!("{} {} {}", left_str, op_str, right_str),
                }
            }
            SqlExpression::Unary {
                ref op,
                ref operand,
            } => {
                let operand_str = self.generate_expression(operand);
                match *op {
                    SqlUnaryOp::Not => format!("NOT ({})", operand_str),
                    SqlUnaryOp::Negate => format!("-{}", operand_str),
                    SqlUnaryOp::Exists => format!("EXISTS ({})", operand_str),
                }
            }
            SqlExpression::Function { ref name, ref args } => {
                // Handle special string functions
                match name.as_str() {
                    "json_extract" if args.len() == 2 => {
                        // Intermediate JSON object access: col->'key'
                        let col_str = self.generate_expression(&args[0]);
                        let key_str = self.generate_expression(&args[1]);
                        return format!("{}->{}", col_str, key_str);
                    }
                    "json_extract_text" if args.len() == 2 => {
                        // Final JSON text access: col->>'key'
                        let col_str = self.generate_expression(&args[0]);
                        let key_str = self.generate_expression(&args[1]);
                        return format!("{}->>{}", col_str, key_str);
                    }
                    "contains" | "startswith" | "endswith" if args.len() == 2 => {
                        // These are not standard SQL functions, convert to LIKE
                        if let (Some(arg0), Some(arg1)) = (args.first(), args.get(1)) {
                            let left_str = self.generate_expression(arg0);
                            let right_str = self.generate_expression(arg1);

                            match name.as_str() {
                                "contains" => {
                                    format!(
                                        "{} LIKE '%{}%'",
                                        left_str,
                                        right_str.trim_matches('\'')
                                    )
                                }
                                "startswith" => {
                                    format!("{} LIKE '{}%'", left_str, right_str.trim_matches('\''))
                                }
                                "endswith" => {
                                    format!("{} LIKE '%{}'", left_str, right_str.trim_matches('\''))
                                }
                                _ => {
                                    let arg_strs = args
                                        .iter()
                                        .map(|a| self.generate_expression(a))
                                        .collect::<Vec<_>>()
                                        .join(", ");
                                    format!("{}({})", name, arg_strs)
                                }
                            }
                        } else {
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
            SqlExpression::Array(ref items) => {
                let item_strs = items
                    .iter()
                    .map(|item| self.generate_expression(item))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("[{}]", item_strs)
            }
            SqlExpression::Case {
                ref conditions,
                ref default,
            } => {
                let mut case_str = String::from("CASE");

                for pair in conditions.iter() {
                    case_str.push_str(&format!(
                        " WHEN {} THEN {}",
                        self.generate_expression(&pair.0),
                        self.generate_expression(&pair.1)
                    ));
                }

                if let Some(default_expr) = default {
                    case_str.push_str(&format!(" ELSE {}", self.generate_expression(default_expr)));
                }

                case_str.push_str(" END");
                case_str
            }
            SqlExpression::Parenthesized(ref expr) => {
                format!("({})", self.generate_expression(expr))
            }
            SqlExpression::Subquery(ref query) => {
                format!("({})", self.generate(query))
            }
            SqlExpression::Cast {
                ref expression,
                ref target_type,
            } => {
                let expr_str = self.generate_expression(expression);
                let type_str = self.generate_data_type(target_type);
                match self.dialect {
                    SqlDialect::PostgreSQL | SqlDialect::Standard => {
                        format!("CAST({} AS {})", expr_str, type_str)
                    }
                    SqlDialect::MySQL => format!("CAST({} AS {})", expr_str, type_str),
                    SqlDialect::TSQL => format!("CAST({} AS {})", expr_str, type_str),
                    SqlDialect::SQLite => format!("CAST({} AS {})", expr_str, type_str),
                }
            }
            SqlExpression::ArrayIndex {
                ref expr,
                ref index,
            } => {
                let expr_str = self.generate_expression(expr);
                let index_str = self.generate_expression(index);
                format!("{}[{}]", expr_str, index_str)
            }
            SqlExpression::Between {
                ref expression,
                ref lower,
                ref upper,
                not,
            } => {
                let expr_str = self.generate_expression(expression);
                let lower_str = self.generate_expression(lower);
                let upper_str = self.generate_expression(upper);
                if not {
                    format!("{} NOT BETWEEN {} AND {}", expr_str, lower_str, upper_str)
                } else {
                    format!("{} BETWEEN {} AND {}", expr_str, lower_str, upper_str)
                }
            }
        }
    }

    fn generate_literal(&self, literal: &SqlLiteral) -> String {
        match *literal {
            SqlLiteral::String(ref s) => {
                // Escape single quotes for SQL string literals
                let escaped = s.replace('\'', "''");
                format!("'{}'", escaped)
            }
            SqlLiteral::Integer(i) => i.to_string(),
            SqlLiteral::Float(f) => {
                let s = f.to_string();
                // Ensure float literals always have a decimal point (e.g. "2" → "2.0")
                if s.contains('.') || s.contains('e') {
                    s
                } else {
                    format!("{}.0", s)
                }
            }
            SqlLiteral::Boolean(b) => {
                if b {
                    match self.dialect {
                        SqlDialect::PostgreSQL | SqlDialect::Standard | SqlDialect::SQLite => {
                            "TRUE".to_string()
                        }
                        SqlDialect::MySQL | SqlDialect::TSQL => "1".to_string(),
                    }
                } else {
                    match self.dialect {
                        SqlDialect::PostgreSQL | SqlDialect::Standard | SqlDialect::SQLite => {
                            "FALSE".to_string()
                        }
                        SqlDialect::MySQL | SqlDialect::TSQL => "0".to_string(),
                    }
                }
            }
            SqlLiteral::Null => "NULL".to_string(),
            SqlLiteral::DateTime(ref dt) => match self.dialect {
                SqlDialect::PostgreSQL => format!("'{}'::timestamp", dt),
                SqlDialect::MySQL => format!("CAST('{}' AS DATETIME)", dt),
                SqlDialect::SQLite => format!("datetime('{}')", dt),
                SqlDialect::TSQL => format!("CAST('{}' AS DATETIME)", dt),
                SqlDialect::Standard => format!("CAST('{}' AS TIMESTAMP)", dt),
            },
            SqlLiteral::Interval(ref ts) => {
                match self.dialect {
                    SqlDialect::PostgreSQL => format!("INTERVAL '{}'", ts),
                    SqlDialect::Standard => format!("INTERVAL '{}'", ts),
                    _ => format!("'{}'", ts), // Fallback for other dialects
                }
            }
        }
    }

    const fn generate_binary_op(op: &SqlBinaryOp) -> &'static str {
        match *op {
            SqlBinaryOp::Equal => "=",
            SqlBinaryOp::NotEqual => "!=",
            SqlBinaryOp::LessThan => "<",
            SqlBinaryOp::LessThanOrEqual => "<=",
            SqlBinaryOp::GreaterThan => ">",
            SqlBinaryOp::GreaterThanOrEqual => ">=",
            SqlBinaryOp::Add => "+",
            SqlBinaryOp::Subtract => "-",
            SqlBinaryOp::Multiply => "*",
            SqlBinaryOp::Divide => "/",
            SqlBinaryOp::Modulo => "%",
            SqlBinaryOp::And => "AND",
            SqlBinaryOp::Or => "OR",
            SqlBinaryOp::Like => "LIKE",
            SqlBinaryOp::NotLike => "NOT LIKE",
            SqlBinaryOp::ILike => "ILIKE",
            SqlBinaryOp::NotILike => "NOT ILIKE",
            SqlBinaryOp::In => "IN",
            SqlBinaryOp::NotIn => "NOT IN",
            SqlBinaryOp::IsNull => "IS NULL",
            SqlBinaryOp::IsNotNull => "IS NOT NULL",
            SqlBinaryOp::SimilarTo => "SIMILAR TO",
            SqlBinaryOp::NotSimilarTo => "NOT SIMILAR TO",
            SqlBinaryOp::Concat => "||",
            SqlBinaryOp::RegexMatch => "~",
        }
    }

    fn generate_column(&mut self, column: &SqlColumn) -> String {
        let expr_str = self.generate_expression(&column.expression);
        column.alias.as_ref().map_or_else(
            || expr_str.clone(),
            |alias| {
                // If the alias is the same as the expression, just output the expression
                if alias == &expr_str {
                    expr_str.clone()
                } else if self.needs_quoting(alias) {
                    format!("{} AS {}", expr_str, self.quote_identifier(alias))
                } else {
                    format!("{} AS {}", expr_str, alias)
                }
            },
        )
    }

    fn generate_order_by(&mut self, order: &SqlOrderBy) -> String {
        let expr_str = self.generate_expression(&order.expression);
        let dir = match order.direction {
            SqlSortDirection::Ascending => "ASC",
            SqlSortDirection::Descending => "DESC",
        };

        let null_order = match order.null_order {
            Some(SqlNullOrder::NullsFirst) => " NULLS FIRST",
            Some(SqlNullOrder::NullsLast) => " NULLS LAST",
            None => "",
        };

        format!("{} {}{}", expr_str, dir, null_order)
    }

    #[allow(dead_code)]
    fn generate_aggregate(&mut self, aggregate: &SqlAggregate) -> String {
        let agg_fn = &aggregate.function;
        let func_str = match *agg_fn {
            SqlAggregateFunction::Count => {
                if aggregate.distinct {
                    aggregate.expression.as_ref().map_or_else(
                        || "COUNT(*)".to_string(),
                        |expr| format!("COUNT(DISTINCT {})", self.generate_expression(expr)),
                    )
                } else {
                    aggregate.expression.as_ref().map_or_else(
                        || "COUNT(*)".to_string(),
                        |expr| format!("COUNT({})", self.generate_expression(expr)),
                    )
                }
            }
            SqlAggregateFunction::Sum => aggregate.expression.as_ref().map_or_else(
                || "SUM(*)".to_string(),
                |expr| {
                    if aggregate.distinct {
                        format!("SUM(DISTINCT {})", self.generate_expression(expr))
                    } else {
                        format!("SUM({})", self.generate_expression(expr))
                    }
                },
            ),
            SqlAggregateFunction::Avg => aggregate.expression.as_ref().map_or_else(
                || "AVG(*)".to_string(),
                |expr| {
                    if aggregate.distinct {
                        format!("AVG(DISTINCT {})", self.generate_expression(expr))
                    } else {
                        format!("AVG({})", self.generate_expression(expr))
                    }
                },
            ),
            SqlAggregateFunction::Min => aggregate.expression.as_ref().map_or_else(
                || "MIN(*)".to_string(),
                |expr| format!("MIN({})", self.generate_expression(expr)),
            ),
            SqlAggregateFunction::Max => aggregate.expression.as_ref().map_or_else(
                || "MAX(*)".to_string(),
                |expr| format!("MAX({})", self.generate_expression(expr)),
            ),
            SqlAggregateFunction::StdDev => aggregate.expression.as_ref().map_or_else(
                || "STDEV(*)".to_string(),
                |expr| match self.dialect {
                    SqlDialect::PostgreSQL => format!("STDDEV({})", self.generate_expression(expr)),
                    SqlDialect::MySQL => format!("STDDEV({})", self.generate_expression(expr)),
                    _ => format!("STDEV({})", self.generate_expression(expr)),
                },
            ),
            SqlAggregateFunction::Variance => aggregate.expression.as_ref().map_or_else(
                || "VARIANCE(*)".to_string(),
                |expr| match self.dialect {
                    SqlDialect::PostgreSQL => {
                        format!("VARIANCE({})", self.generate_expression(expr))
                    }
                    SqlDialect::MySQL => format!("VARIANCE({})", self.generate_expression(expr)),
                    _ => format!("VAR({})", self.generate_expression(expr)),
                },
            ),
            SqlAggregateFunction::Percentile(ref p) => aggregate.expression.as_ref().map_or_else(
                || format!("PERCENTILE_CONT({}) WITHIN GROUP (ORDER BY *)", p),
                |expr| match self.dialect {
                    SqlDialect::PostgreSQL => format!(
                        "PERCENTILE_CONT({}) WITHIN GROUP (ORDER BY {})",
                        p,
                        self.generate_expression(expr)
                    ),
                    _ => format!("PERCENTILE({}, {})", self.generate_expression(expr), p),
                },
            ),
            SqlAggregateFunction::ArrayAgg => aggregate.expression.as_ref().map_or_else(
                || "ARRAY_AGG(*)".to_string(),
                |expr| format!("ARRAY_AGG({})", self.generate_expression(expr)),
            ),
            SqlAggregateFunction::StringAgg => aggregate.expression.as_ref().map_or_else(
                || "STRING_AGG(*)".to_string(),
                |expr| match self.dialect {
                    SqlDialect::PostgreSQL => {
                        format!("STRING_AGG({}, ',')", self.generate_expression(expr))
                    }
                    SqlDialect::MySQL => {
                        format!("GROUP_CONCAT({})", self.generate_expression(expr))
                    }
                    _ => format!("STRING_AGG({}, ',')", self.generate_expression(expr)),
                },
            ),
        };

        format!(
            "{} AS {}",
            func_str,
            self.quote_identifier(&aggregate.alias)
        )
    }

    const fn generate_join_kind(kind: &SqlJoinKind) -> &'static str {
        match *kind {
            SqlJoinKind::Inner => "INNER JOIN",
            SqlJoinKind::LeftOuter => "LEFT OUTER JOIN",
            SqlJoinKind::RightOuter => "RIGHT OUTER JOIN",
            SqlJoinKind::FullOuter => "FULL OUTER JOIN",
            SqlJoinKind::Cross => "CROSS JOIN",
            SqlJoinKind::LeftAnti => "LEFT JOIN", // Will need additional WHERE clause
            SqlJoinKind::RightAnti => "RIGHT JOIN", // Will need additional WHERE clause
            SqlJoinKind::LeftSemi => "INNER JOIN", // Will need special handling
            SqlJoinKind::RightSemi => "INNER JOIN", // Will need special handling
        }
    }

    fn generate_join_condition(&mut self, condition: &SqlJoinCondition) -> String {
        let left_str = self.generate_expression(&condition.left);
        let right_str = self.generate_expression(&condition.right);
        let op_str = Self::generate_binary_op(&condition.operator);
        format!("{} {} {}", left_str, op_str, right_str)
    }

    fn generate_data_type(&self, data_type: &SqlDataType) -> String {
        match data_type {
            SqlDataType::Integer => "INTEGER".to_string(),
            SqlDataType::BigInt => "BIGINT".to_string(),
            SqlDataType::SmallInt => "SMALLINT".to_string(),
            SqlDataType::Decimal => "DECIMAL".to_string(),
            SqlDataType::Real => "REAL".to_string(),
            SqlDataType::DoublePrecision => "DOUBLE PRECISION".to_string(),
            SqlDataType::Varchar(len) => {
                if let Some(length) = len {
                    format!("VARCHAR({})", length)
                } else {
                    "VARCHAR".to_string()
                }
            }
            SqlDataType::Text => "TEXT".to_string(),
            SqlDataType::Boolean => match self.dialect {
                SqlDialect::MySQL => "TINYINT(1)".to_string(),
                SqlDialect::TSQL => "BIT".to_string(),
                _ => "BOOLEAN".to_string(),
            },
            SqlDataType::Date => "DATE".to_string(),
            SqlDataType::Time => "TIME".to_string(),
            SqlDataType::Timestamp => "TIMESTAMP".to_string(),
            SqlDataType::Timestamptz => "TIMESTAMP WITH TIME ZONE".to_string(),
            SqlDataType::Interval => "INTERVAL".to_string(),
            SqlDataType::Json => "JSON".to_string(),
            SqlDataType::Jsonb => match self.dialect {
                SqlDialect::PostgreSQL => "JSONB".to_string(),
                _ => "JSON".to_string(),
            },
            SqlDataType::Array(inner_type) => format!("{}[]", self.generate_data_type(inner_type)),
            SqlDataType::Numeric => "NUMERIC".to_string(),
        }
    }

    fn generate_subquery_pretty(&mut self, query: &SqlQuery) -> String {
        let mut sql = String::new();
        let indent = "    "; // 4 spaces for subquery indentation

        // Start with SELECT
        sql.push_str(indent);
        sql.push_str("SELECT ");

        // Handle DISTINCT if present
        let distinct = query
            .pipeline
            .iter()
            .any(|op| matches!(*op, SqlOperation::Distinct(_)));
        if distinct {
            sql.push_str("DISTINCT ");
        }

        // Generate projection
        let projection = self.generate_projection(query);
        sql.push_str(&projection);

        // Add FROM clause
        sql.push_str(&format!("\n{}FROM {}", indent, query.source));

        // Add pipeline operations with proper indentation
        for operation in &query.pipeline {
            // Skip DISTINCT and Project as they're already handled
            if matches!(
                *operation,
                SqlOperation::Distinct(_) | SqlOperation::Project(_)
            ) {
                continue;
            }

            self.generate_operation(&mut sql, operation);
        }

        sql
    }

    fn quote_identifier(&self, identifier: &str) -> String {
        match self.dialect {
            SqlDialect::PostgreSQL => format!("\"{}\"", identifier),
            SqlDialect::MySQL => format!("`{}`", identifier),
            SqlDialect::TSQL => format!("[{}]", identifier),
            SqlDialect::SQLite => format!("\"{}\"", identifier),
            SqlDialect::Standard => format!("\"{}\"", identifier),
        }
    }

    fn needs_quoting(&self, identifier: &str) -> bool {
        // SQL keywords that need quoting
        let keywords = [
            "SELECT",
            "FROM",
            "WHERE",
            "JOIN",
            "INNER",
            "OUTER",
            "LEFT",
            "RIGHT",
            "FULL",
            "CROSS",
            "UNION",
            "INTERSECT",
            "EXCEPT",
            "GROUP",
            "BY",
            "HAVING",
            "ORDER",
            "LIMIT",
            "OFFSET",
            "AND",
            "OR",
            "NOT",
            "NULL",
            "TRUE",
            "FALSE",
            "IS",
            "BETWEEN",
            "LIKE",
            "IN",
            "EXISTS",
            "DISTINCT",
            "AS",
            "ON",
            "ASC",
            "DESC",
            "CASE",
            "WHEN",
            "THEN",
            "ELSE",
            "END",
            "CAST",
            "WITH",
            "RECURSIVE",
        ];

        let upper = identifier.to_uppercase();
        keywords.contains(&upper.as_str()) || identifier.contains(' ') || identifier.contains('-')
    }
}

impl Default for SqlCodeGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Query optimizer for SQL IR
#[derive(Debug)]
pub struct SqlOptimizer;

impl SqlOptimizer {
    pub const fn new() -> Self {
        Self
    }

    /// Optimize a SQL query
    pub fn optimize(&self, query: &SqlQuery) -> SqlQuery {
        let mut optimized = query.clone();

        // Apply optimization passes
        optimized = Self::combine_filters(optimized);
        optimized = Self::eliminate_redundant_operations(optimized);

        optimized
    }

    /// Combine multiple filter operations into a single one
    fn combine_filters(mut query: SqlQuery) -> SqlQuery {
        let mut combined_pipeline = Vec::new();
        let mut current_filter: Option<SqlExpression> = None;

        for op in query.pipeline {
            match op {
                SqlOperation::Where(expr) => match current_filter {
                    None => current_filter = Some(expr),
                    Some(existing) => {
                        current_filter = Some(SqlExpression::Binary {
                            op: SqlBinaryOp::And,
                            left: Box::new(existing),
                            right: Box::new(expr),
                        });
                    }
                },
                _ => {
                    if let Some(filter) = current_filter.take() {
                        combined_pipeline.push(SqlOperation::Where(filter));
                    }
                    combined_pipeline.push(op);
                }
            }
        }

        if let Some(filter) = current_filter {
            combined_pipeline.push(SqlOperation::Where(filter));
        }

        query.pipeline = combined_pipeline;
        query
    }

    /// Eliminate redundant operations
    fn eliminate_redundant_operations(mut query: SqlQuery) -> SqlQuery {
        // Remove consecutive project operations (keep only the last one)
        let mut filtered_pipeline = Vec::new();
        let mut last_project: Option<SqlOperation> = None;

        for op in query.pipeline {
            match op {
                SqlOperation::Project(_) => {
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

impl Default for SqlOptimizer {
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
        let query = SqlQueryBuilder::new()
            .from_table("users")
            .where_clause(SqlExpression::equals(
                SqlExpression::column("role"),
                SqlExpression::string_literal("admin"),
            ))
            .limit(10)
            .build()
            .map_err(|e| anyhow::anyhow!(e))?;

        let mut generator = SqlCodeGenerator::new().with_pretty_print(false);
        let sql = generator.generate(&query);

        anyhow::ensure!(sql.contains("SELECT"), "expected 'SELECT' in SQL");
        anyhow::ensure!(sql.contains("users"), "expected 'users' in SQL");
        anyhow::ensure!(sql.contains("WHERE"), "expected 'WHERE' in SQL");
        anyhow::ensure!(
            sql.contains("role = 'admin'"),
            "expected role filter in SQL"
        );
        anyhow::ensure!(sql.contains("LIMIT 10"), "expected 'LIMIT 10' in SQL");
        Ok(())
    }

    #[test]
    fn test_aggregation_query() -> anyhow::Result<()> {
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
            .map_err(|e| anyhow::anyhow!(e))?;

        let mut generator = SqlCodeGenerator::new().with_pretty_print(false);
        let sql = generator.generate(&query);

        anyhow::ensure!(sql.contains("SELECT"), "expected 'SELECT' in SQL");
        anyhow::ensure!(sql.contains("events"), "expected 'events' in SQL");
        anyhow::ensure!(sql.contains("GROUP BY"), "expected 'GROUP BY' in SQL");
        anyhow::ensure!(sql.contains("COUNT(*)"), "expected COUNT in SQL");
        Ok(())
    }

    #[test]
    fn test_query_optimization() -> anyhow::Result<()> {
        let mut query = SqlQueryBuilder::new()
            .from_table("logs")
            .where_clause(SqlExpression::equals(
                SqlExpression::column("level"),
                SqlExpression::string_literal("error"),
            ))
            .where_clause(SqlExpression::equals(
                SqlExpression::column("service"),
                SqlExpression::string_literal("web"),
            ))
            .build()
            .map_err(|e| anyhow::anyhow!(e))?;

        // Add operations manually to test optimization
        query
            .pipeline
            .push(SqlOperation::Where(SqlExpression::equals(
                SqlExpression::column("timestamp"),
                SqlExpression::string_literal("today"),
            )));

        let optimizer = SqlOptimizer::new();
        let result_query = optimizer.optimize(&query);

        // Should have combined filters
        let where_count = result_query
            .pipeline
            .iter()
            .filter(|op| matches!(*op, SqlOperation::Where(_)))
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
        let expr = SqlExpression::and(
            SqlExpression::equals(
                SqlExpression::column("status"),
                SqlExpression::string_literal("active"),
            ),
            SqlExpression::Binary {
                op: SqlBinaryOp::GreaterThan,
                left: Box::new(SqlExpression::column("age")),
                right: Box::new(SqlExpression::int_literal(18)),
            },
        );

        let mut generator = SqlCodeGenerator::new();
        let sql_expr = generator.generate_expression(&expr);

        assert!(sql_expr.contains("status = 'active'"));
        assert!(sql_expr.contains("age > 18"));
        assert!(sql_expr.contains("AND"));
    }

    #[test]
    fn test_cast_expression() {
        let expr = SqlExpression::cast(SqlExpression::column("age"), SqlDataType::Integer);

        let mut generator = SqlCodeGenerator::new();
        let sql_expr = generator.generate_expression(&expr);

        assert!(sql_expr.contains("CAST"));
        assert!(sql_expr.contains("INTEGER"));
    }

    #[test]
    fn test_between_expression() {
        let expr = SqlExpression::between(
            SqlExpression::column("age"),
            SqlExpression::int_literal(18),
            SqlExpression::int_literal(65),
        );

        let mut generator = SqlCodeGenerator::new();
        let sql_expr = generator.generate_expression(&expr);

        assert!(sql_expr.contains("BETWEEN"));
        assert!(sql_expr.contains("AND"));
    }

    #[test]
    fn test_case_expression() {
        let expr = SqlExpression::Case {
            conditions: vec![
                (
                    SqlExpression::equals(
                        SqlExpression::column("status"),
                        SqlExpression::string_literal("active"),
                    ),
                    SqlExpression::int_literal(1),
                ),
                (
                    SqlExpression::equals(
                        SqlExpression::column("status"),
                        SqlExpression::string_literal("inactive"),
                    ),
                    SqlExpression::int_literal(0),
                ),
            ],
            default: Some(Box::new(SqlExpression::int_literal(-1))),
        };

        let mut generator = SqlCodeGenerator::new();
        let sql_expr = generator.generate_expression(&expr);

        assert!(sql_expr.contains("CASE"));
        assert!(sql_expr.contains("WHEN"));
        assert!(sql_expr.contains("THEN"));
        assert!(sql_expr.contains("ELSE"));
        assert!(sql_expr.contains("END"));
    }
}
