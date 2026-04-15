// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SQL Intermediate Representation (IR)
//!
//! This module defines an intermediate representation that closely mirrors SQL structure
//! but is serializable in binary format. This allows for:
//! 1. Separation of Rego parsing from SQL generation
//! 2. Query optimization at the IR level
//! 3. Caching of compiled queries
//! 4. Cross-language interoperability

use alloc::{boxed::Box, format, string::String, string::ToString as _, vec::Vec};
use serde::{Deserialize, Serialize};

/// SQL Query Intermediate Representation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SqlQuery {
    /// Common Table Expressions (WITH clauses)
    pub ctes: Vec<SqlCte>,
    /// The main data source (table name)
    pub source: String,
    /// Pipeline of operations to apply
    pub pipeline: Vec<SqlOperation>,
    /// Optional result projection
    pub projection: Option<SqlProjection>,
}

/// SQL Common Table Expression (CTE)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SqlCte {
    pub name: String,
    pub query: Box<SqlQuery>,
}

/// SQL Operation in the query pipeline
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SqlOperation {
    /// Where clause filtering
    Where(SqlExpression),
    /// Project specific columns (SELECT)
    Project(Vec<SqlColumn>),
    /// Extend with computed columns (not directly in SQL, handled in projection)
    Extend(Vec<SqlColumn>),
    /// Limit clause (LIMIT)
    Limit(i64),
    /// Order by columns
    Order(Vec<SqlOrderBy>),
    /// Group by and aggregate (GROUP BY + HAVING)
    Aggregate {
        group_by: Vec<SqlExpression>,
        aggregates: Vec<SqlAggregate>,
        having: Option<SqlExpression>, // HAVING clause
    },
    /// Join with another table
    Join {
        kind: SqlJoinKind,
        source: SqlJoinSource,
        on: Vec<SqlJoinCondition>,
    },
    /// Union with another query
    Union(Box<SqlQuery>),
    /// Distinct values
    Distinct(Vec<SqlExpression>),
}

/// SQL Expression
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SqlExpression {
    /// Column reference
    Column(String),
    /// Literal value
    Literal(SqlLiteral),
    /// Binary operation
    Binary {
        op: SqlBinaryOp,
        left: Box<SqlExpression>,
        right: Box<SqlExpression>,
    },
    /// Unary operation
    Unary {
        op: SqlUnaryOp,
        operand: Box<SqlExpression>,
    },
    /// Function call
    Function {
        name: String,
        args: Vec<SqlExpression>,
    },
    /// Array/list literal (ARRAY constructor in SQL)
    Array(Vec<SqlExpression>),
    /// Case expression (CASE WHEN)
    Case {
        conditions: Vec<(SqlExpression, SqlExpression)>,
        default: Option<Box<SqlExpression>>,
    },
    /// Parenthesized expression (preserves precedence)
    Parenthesized(Box<SqlExpression>),
    /// Subquery (nested query)
    Subquery(Box<SqlQuery>),
    /// Cast expression
    Cast {
        expression: Box<SqlExpression>,
        target_type: SqlDataType,
    },
    /// Between expression
    Between {
        expression: Box<SqlExpression>,
        lower: Box<SqlExpression>,
        upper: Box<SqlExpression>,
        not: bool,
    },
    /// Array subscript expression (e.g. `arr[1]`)
    ArrayIndex {
        expr: Box<SqlExpression>,
        index: Box<SqlExpression>,
    },
}

/// SQL Literal values
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SqlLiteral {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Null,
    /// Date/Time/Timestamp value (ISO 8601 format)
    DateTime(String),
    /// Interval value
    Interval(String),
}

/// SQL Binary operators
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SqlBinaryOp {
    // Comparison
    Equal,
    NotEqual,
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,

    // Arithmetic
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,

    // Logical
    And,
    Or,

    // String operations
    Like,
    NotLike,
    ILike, // Case-insensitive LIKE (PostgreSQL)
    NotILike,

    // Collection operations
    In,
    NotIn,

    // Null checks
    IsNull,
    IsNotNull,

    // Pattern matching
    SimilarTo, // PostgreSQL SIMILAR TO
    NotSimilarTo,

    // Concatenation (||)
    Concat,

    // Regex match (~)
    RegexMatch,
}

/// SQL Unary operators
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SqlUnaryOp {
    Not,
    Negate, // Unary minus
    Exists, // EXISTS subquery
}

/// Column definition for projections
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SqlColumn {
    pub name: String,
    pub expression: SqlExpression,
    pub alias: Option<String>,
}

/// Projection specification
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SqlProjection {
    /// Project all columns (SELECT *)
    All,
    /// Project specific columns
    Columns(Vec<String>),
    /// Project with expressions
    Expressions(Vec<SqlColumn>),
}

/// Order by specification
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SqlOrderBy {
    pub expression: SqlExpression,
    pub direction: SqlSortDirection,
    /// Null ordering (NULLS FIRST or NULLS LAST)
    pub null_order: Option<SqlNullOrder>,
}

/// Sort direction
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SqlSortDirection {
    Ascending,
    Descending,
}

/// Null ordering for ORDER BY
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SqlNullOrder {
    NullsFirst,
    NullsLast,
}

/// Aggregate function
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SqlAggregate {
    pub function: SqlAggregateFunction,
    pub expression: Option<SqlExpression>,
    pub alias: String,
    /// DISTINCT modifier (e.g., COUNT(DISTINCT column))
    pub distinct: bool,
}

/// Aggregate functions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SqlAggregateFunction {
    Count,
    Sum,
    Avg,
    Min,
    Max,
    StdDev,
    Variance,
    Percentile(f64), // With specific percentile value
    ArrayAgg,        // PostgreSQL array aggregation
    StringAgg,       // PostgreSQL string aggregation
}

/// SQL data types for CAST expressions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SqlDataType {
    Integer,
    BigInt,
    SmallInt,
    Decimal,
    Real,
    DoublePrecision,
    Varchar(Option<usize>),
    Text,
    Boolean,
    Date,
    Time,
    Timestamp,
    Timestamptz,
    Interval,
    Json,
    Jsonb,
    Array(Box<SqlDataType>),
    Numeric,
}

/// Join types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SqlJoinKind {
    Inner,
    LeftOuter,
    RightOuter,
    FullOuter,
    Cross,
    // SQL doesn't have anti/semi joins like KQL, but they can be emulated
    LeftAnti,  // Emulated with LEFT JOIN ... WHERE right.key IS NULL
    RightAnti, // Emulated with RIGHT JOIN ... WHERE left.key IS NULL
    LeftSemi,  // Emulated with WHERE EXISTS
    RightSemi, // Emulated with WHERE EXISTS
}

/// Join source specification
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SqlJoinSource {
    Table(String),
    Filtered {
        table: String,
        filters: Vec<SqlExpression>,
    },
    Subquery(SqlQuery),
}

/// Join condition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SqlJoinCondition {
    pub left: SqlExpression,
    pub right: SqlExpression,
    pub operator: SqlBinaryOp,
}

/// Query builder for constructing SQL IR
#[derive(Debug)]
pub struct SqlQueryBuilder {
    ctes: Vec<SqlCte>,
    source: Option<String>,
    operations: Vec<SqlOperation>,
    projection: Option<SqlProjection>,
}

impl SqlQueryBuilder {
    pub const fn new() -> Self {
        Self {
            ctes: Vec::new(),
            source: None,
            operations: Vec::new(),
            projection: None,
        }
    }

    pub fn from_table(mut self, table: &str) -> Self {
        self.source = Some(table.to_string());
        self
    }

    pub fn where_clause(mut self, condition: SqlExpression) -> Self {
        self.operations.push(SqlOperation::Where(condition));
        self
    }

    pub fn project(mut self, columns: Vec<SqlColumn>) -> Self {
        self.operations.push(SqlOperation::Project(columns));
        self
    }

    pub fn extend(mut self, columns: Vec<SqlColumn>) -> Self {
        self.operations.push(SqlOperation::Extend(columns));
        self
    }

    pub fn limit(mut self, count: i64) -> Self {
        self.operations.push(SqlOperation::Limit(count));
        self
    }

    pub fn order_by(mut self, order: Vec<SqlOrderBy>) -> Self {
        self.operations.push(SqlOperation::Order(order));
        self
    }

    pub fn aggregate(
        mut self,
        group_by: Vec<SqlExpression>,
        aggregates: Vec<SqlAggregate>,
        having: Option<SqlExpression>,
    ) -> Self {
        self.operations.push(SqlOperation::Aggregate {
            group_by,
            aggregates,
            having,
        });
        self
    }

    /// Add a JOIN operation
    pub fn join(
        mut self,
        kind: SqlJoinKind,
        table: &str,
        conditions: Vec<SqlJoinCondition>,
    ) -> Self {
        self.operations.push(SqlOperation::Join {
            kind,
            source: SqlJoinSource::Table(table.to_string()),
            on: conditions,
        });
        self
    }

    pub fn join_filtered(
        mut self,
        kind: SqlJoinKind,
        table: &str,
        filters: Vec<SqlExpression>,
        conditions: Vec<SqlJoinCondition>,
    ) -> Self {
        self.operations.push(SqlOperation::Join {
            kind,
            source: SqlJoinSource::Filtered {
                table: table.to_string(),
                filters,
            },
            on: conditions,
        });
        self
    }

    /// Add a JOIN operation with a subquery
    pub fn join_subquery(
        mut self,
        kind: SqlJoinKind,
        subquery: SqlQuery,
        conditions: Vec<SqlJoinCondition>,
    ) -> Self {
        self.operations.push(SqlOperation::Join {
            kind,
            source: SqlJoinSource::Subquery(subquery),
            on: conditions,
        });
        self
    }

    pub fn build(self) -> Result<SqlQuery, String> {
        let source = self.source.ok_or("Source table not specified")?;
        Ok(SqlQuery {
            ctes: self.ctes,
            source,
            pipeline: self.operations,
            projection: self.projection,
        })
    }
}

impl Default for SqlQueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper functions for creating common expressions
impl SqlExpression {
    pub fn column(name: &str) -> Self {
        SqlExpression::Column(name.to_string())
    }

    pub fn string_literal(value: &str) -> Self {
        SqlExpression::Literal(SqlLiteral::String(value.to_string()))
    }

    pub const fn int_literal(value: i64) -> Self {
        SqlExpression::Literal(SqlLiteral::Integer(value))
    }

    pub const fn float_literal(value: f64) -> Self {
        SqlExpression::Literal(SqlLiteral::Float(value))
    }

    pub const fn bool_literal(value: bool) -> Self {
        SqlExpression::Literal(SqlLiteral::Boolean(value))
    }

    pub const fn null_literal() -> Self {
        SqlExpression::Literal(SqlLiteral::Null)
    }

    pub fn equals(left: SqlExpression, right: SqlExpression) -> Self {
        SqlExpression::Binary {
            op: SqlBinaryOp::Equal,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    pub fn and(left: SqlExpression, right: SqlExpression) -> Self {
        SqlExpression::Binary {
            op: SqlBinaryOp::And,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    pub fn or(left: SqlExpression, right: SqlExpression) -> Self {
        SqlExpression::Binary {
            op: SqlBinaryOp::Or,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    pub fn function(name: &str, args: Vec<SqlExpression>) -> Self {
        SqlExpression::Function {
            name: name.to_string(),
            args,
        }
    }

    pub fn cast(expression: SqlExpression, target_type: SqlDataType) -> Self {
        SqlExpression::Cast {
            expression: Box::new(expression),
            target_type,
        }
    }

    pub fn between(expression: SqlExpression, lower: SqlExpression, upper: SqlExpression) -> Self {
        SqlExpression::Between {
            expression: Box::new(expression),
            lower: Box::new(lower),
            upper: Box::new(upper),
            not: false,
        }
    }
}

/// Binary serialization/deserialization using bincode
impl SqlQuery {
    /// Serialize the query to binary format
    pub fn to_binary(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|e| format!("Serialization error: {}", e))
    }

    /// Deserialize the query from binary format
    pub fn from_binary(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data).map_err(|e| format!("Deserialization error: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vec;

    #[test]
    fn test_query_builder() -> anyhow::Result<()> {
        let query = SqlQueryBuilder::new()
            .from_table("users")
            .where_clause(SqlExpression::equals(
                SqlExpression::column("role"),
                SqlExpression::string_literal("admin"),
            ))
            .limit(100)
            .build()
            .map_err(|e| anyhow::anyhow!(e))?;

        anyhow::ensure!(query.source == "users", "wrong source table");
        anyhow::ensure!(query.pipeline.len() == 2, "expected 2 pipeline operations");

        let first_op = query
            .pipeline
            .first()
            .ok_or_else(|| anyhow::anyhow!("expected pipeline operation"))?
            .clone();
        match first_op {
            SqlOperation::Where(expr) => match expr {
                SqlExpression::Binary { op, .. } => {
                    anyhow::ensure!(op == SqlBinaryOp::Equal, "expected Equal op");
                }
                _ => anyhow::bail!("Expected binary expression"),
            },
            _ => anyhow::bail!("Expected where operation"),
        }
        Ok(())
    }

    #[test]
    fn test_binary_serialization() -> anyhow::Result<()> {
        let query = SqlQueryBuilder::new()
            .from_table("logs")
            .where_clause(SqlExpression::equals(
                SqlExpression::column("level"),
                SqlExpression::string_literal("error"),
            ))
            .build()
            .map_err(|e| anyhow::anyhow!(e))?;

        let binary_data = query.to_binary().map_err(|e| anyhow::anyhow!(e))?;
        anyhow::ensure!(!binary_data.is_empty(), "binary data should not be empty");

        let deserialized = SqlQuery::from_binary(&binary_data).map_err(|e| anyhow::anyhow!(e))?;
        anyhow::ensure!(
            query == deserialized,
            "deserialized query should match original"
        );
        Ok(())
    }

    #[test]
    fn test_complex_expression() -> anyhow::Result<()> {
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

        match expr {
            SqlExpression::Binary { op, .. } => {
                anyhow::ensure!(op == SqlBinaryOp::And, "expected And op");
            }
            _ => anyhow::bail!("Expected binary expression"),
        }
        Ok(())
    }

    #[test]
    fn test_aggregate_query() -> anyhow::Result<()> {
        let query = SqlQueryBuilder::new()
            .from_table("events")
            .aggregate(
                vec![SqlExpression::column("category")],
                vec![SqlAggregate {
                    function: SqlAggregateFunction::Count,
                    expression: None,
                    alias: "count".to_string(),
                    distinct: false,
                }],
                None,
            )
            .build()
            .map_err(|e| anyhow::anyhow!(e))?;

        anyhow::ensure!(query.pipeline.len() == 1, "expected 1 pipeline operation");
        let first_op = query
            .pipeline
            .first()
            .ok_or_else(|| anyhow::anyhow!("expected pipeline operation"))?
            .clone();
        match first_op {
            SqlOperation::Aggregate {
                group_by,
                aggregates,
                ..
            } => {
                anyhow::ensure!(group_by.len() == 1, "expected 1 group by");
                anyhow::ensure!(aggregates.len() == 1, "expected 1 aggregate");
            }
            _ => anyhow::bail!("Expected aggregate operation"),
        }
        Ok(())
    }

    #[test]
    fn test_cast_expression() {
        let expr = SqlExpression::cast(SqlExpression::column("age"), SqlDataType::Integer);

        match expr {
            SqlExpression::Cast { target_type, .. } => {
                assert!(matches!(target_type, SqlDataType::Integer));
            }
            _ => panic!("Expected cast expression"),
        }
    }

    #[test]
    fn test_between_expression() {
        let expr = SqlExpression::between(
            SqlExpression::column("age"),
            SqlExpression::int_literal(18),
            SqlExpression::int_literal(65),
        );

        match expr {
            SqlExpression::Between { not, .. } => {
                assert!(!not);
            }
            _ => panic!("Expected between expression"),
        }
    }
}
