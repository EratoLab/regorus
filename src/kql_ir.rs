// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! KQL Intermediate Representation (IR)
//!
//! This module defines an intermediate representation that closely mirrors KQL structure
//! but is serializable in binary format. This allows for:
//! 1. Separation of Rego parsing from KQL generation
//! 2. Query optimization at the IR level
//! 3. Caching of compiled queries
//! 4. Cross-language interoperability

use alloc::{boxed::Box, format, string::String, string::ToString as _, vec::Vec};
use serde::{Deserialize, Serialize};

/// KQL Query Intermediate Representation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KqlQuery {
    /// Let statements that come before the query
    pub let_statements: Vec<KqlLetStatement>,
    /// The main data source (table name)
    pub source: String,
    /// Pipeline of operations to apply
    pub pipeline: Vec<KqlOperation>,
    /// Optional result projection
    pub projection: Option<KqlProjection>,
}

/// KQL Let Statement
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KqlLetStatement {
    pub name: String,
    pub value: KqlExpression,
}

/// KQL Operation in the query pipeline
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KqlOperation {
    /// Where clause filtering
    Where(KqlExpression),
    /// Project specific columns
    Project(Vec<KqlColumn>),
    /// Extend with computed columns
    Extend(Vec<KqlColumn>),
    /// Take first N rows
    Take(i64),
    /// Order by columns
    Order(Vec<KqlOrderBy>),
    /// Group by and aggregate
    Summarize {
        group_by: Vec<KqlExpression>,
        aggregates: Vec<KqlAggregate>,
    },
    /// Join with another table
    Join {
        kind: KqlJoinKind,
        source: KqlJoinSource,
        on: Vec<KqlJoinCondition>,
    },
    /// Union with another query
    Union(Box<KqlQuery>),
    /// Distinct values
    Distinct(Vec<KqlExpression>),
}

/// KQL Expression
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KqlExpression {
    /// Column reference
    Column(String),
    /// Literal value
    Literal(KqlLiteral),
    /// Binary operation
    Binary {
        op: KqlBinaryOp,
        left: Box<KqlExpression>,
        right: Box<KqlExpression>,
    },
    /// Unary operation
    Unary {
        op: KqlUnaryOp,
        operand: Box<KqlExpression>,
    },
    /// Function call
    Function {
        name: String,
        args: Vec<KqlExpression>,
    },
    /// Array/list literal
    Array(Vec<KqlExpression>),
    /// Object/record access
    Property {
        object: Box<KqlExpression>,
        property: String,
    },
    /// Array indexing
    Index {
        array: Box<KqlExpression>,
        index: Box<KqlExpression>,
    },
    /// Case expression
    Case {
        conditions: Vec<(KqlExpression, KqlExpression)>,
        default: Option<Box<KqlExpression>>,
    },
    /// Parenthesized expression (preserves precedence)
    Parenthesized(Box<KqlExpression>),
    /// Subquery (nested query)
    Subquery(Box<KqlQuery>),
}

/// KQL Literal values
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KqlLiteral {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Null,
    DateTime(String), // ISO 8601 format
    TimeSpan(String), // KQL timespan format
    Guid(String),
}

/// KQL Binary operators
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KqlBinaryOp {
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
    Contains,
    StartsWith,
    EndsWith,
    Matches, // Regex match

    // Collection operations
    In,
    HasAny,
    HasAll,

    // Set operations
    Union,
    Intersect,
}

/// KQL Unary operators
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KqlUnaryOp {
    Not,
    Negate, // Unary minus
    IsNull,
    IsNotNull,
    IsEmpty,
    IsNotEmpty,
}

/// Column definition for projections and extensions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KqlColumn {
    pub name: String,
    pub expression: KqlExpression,
    pub alias: Option<String>,
}

/// Projection specification
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KqlProjection {
    /// Project all columns
    All,
    /// Project specific columns
    Columns(Vec<String>),
    /// Project with expressions
    Expressions(Vec<KqlColumn>),
}

/// Order by specification
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KqlOrderBy {
    pub expression: KqlExpression,
    pub direction: KqlSortDirection,
}

/// Sort direction
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KqlSortDirection {
    Ascending,
    Descending,
}

/// Aggregate function
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KqlAggregate {
    pub function: KqlAggregateFunction,
    pub expression: Option<KqlExpression>,
    pub alias: String,
}

/// Aggregate functions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KqlAggregateFunction {
    Count,
    CountIf,
    Sum,
    Avg,
    Min,
    Max,
    Any,
    StdDev,
    Variance,
    Percentile(f64),
    MakeList,
    MakeSet,
    ArraySort,
}

/// Join types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KqlJoinKind {
    Inner,
    LeftOuter,
    RightOuter,
    FullOuter,
    LeftAnti,
    RightAnti,
    LeftSemi,
    RightSemi,
}

/// Join source specification
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KqlJoinSource {
    Table(String),
    Filtered {
        table: String,
        filters: Vec<KqlExpression>,
    },
    Subquery(KqlQuery),
}

/// Join condition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KqlJoinCondition {
    pub left: KqlExpression,
    pub right: KqlExpression,
    pub operator: KqlBinaryOp,
}

/// Query builder for constructing KQL IR
#[derive(Debug)]
pub struct KqlQueryBuilder {
    let_statements: Vec<KqlLetStatement>,
    source: Option<String>,
    operations: Vec<KqlOperation>,
    projection: Option<KqlProjection>,
}

impl KqlQueryBuilder {
    pub const fn new() -> Self {
        Self {
            let_statements: Vec::new(),
            source: None,
            operations: Vec::new(),
            projection: None,
        }
    }

    pub fn from_table(mut self, table: &str) -> Self {
        self.source = Some(table.to_string());
        self
    }

    pub fn where_clause(mut self, condition: KqlExpression) -> Self {
        self.operations.push(KqlOperation::Where(condition));
        self
    }

    pub fn project(mut self, columns: Vec<KqlColumn>) -> Self {
        self.operations.push(KqlOperation::Project(columns));
        self
    }

    pub fn extend(mut self, columns: Vec<KqlColumn>) -> Self {
        self.operations.push(KqlOperation::Extend(columns));
        self
    }

    pub fn let_statement(mut self, name: String, value: KqlExpression) -> Self {
        self.let_statements.push(KqlLetStatement { name, value });
        self
    }

    pub fn take(mut self, count: i64) -> Self {
        self.operations.push(KqlOperation::Take(count));
        self
    }

    pub fn order_by(mut self, order: Vec<KqlOrderBy>) -> Self {
        self.operations.push(KqlOperation::Order(order));
        self
    }

    pub fn summarize(
        mut self,
        group_by: Vec<KqlExpression>,
        aggregates: Vec<KqlAggregate>,
    ) -> Self {
        self.operations.push(KqlOperation::Summarize {
            group_by,
            aggregates,
        });
        self
    }

    /// Add a JOIN operation
    pub fn join(
        mut self,
        kind: KqlJoinKind,
        table: &str,
        conditions: Vec<KqlJoinCondition>,
    ) -> Self {
        self.operations.push(KqlOperation::Join {
            kind,
            source: KqlJoinSource::Table(table.to_string()),
            on: conditions,
        });
        self
    }

    pub fn join_filtered(
        mut self,
        kind: KqlJoinKind,
        table: &str,
        filters: Vec<KqlExpression>,
        conditions: Vec<KqlJoinCondition>,
    ) -> Self {
        self.operations.push(KqlOperation::Join {
            kind,
            source: KqlJoinSource::Filtered {
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
        kind: KqlJoinKind,
        subquery: KqlQuery,
        conditions: Vec<KqlJoinCondition>,
    ) -> Self {
        self.operations.push(KqlOperation::Join {
            kind,
            source: KqlJoinSource::Subquery(subquery),
            on: conditions,
        });
        self
    }

    pub fn build(self) -> Result<KqlQuery, String> {
        let source = self.source.ok_or("Source table not specified")?;
        Ok(KqlQuery {
            let_statements: self.let_statements,
            source,
            pipeline: self.operations,
            projection: self.projection,
        })
    }
}

impl Default for KqlQueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper functions for creating common expressions
impl KqlExpression {
    pub fn column(name: &str) -> Self {
        KqlExpression::Column(name.to_string())
    }

    pub fn string_literal(value: &str) -> Self {
        KqlExpression::Literal(KqlLiteral::String(value.to_string()))
    }

    pub const fn int_literal(value: i64) -> Self {
        KqlExpression::Literal(KqlLiteral::Integer(value))
    }

    pub const fn bool_literal(value: bool) -> Self {
        KqlExpression::Literal(KqlLiteral::Boolean(value))
    }

    pub const fn null_literal() -> Self {
        KqlExpression::Literal(KqlLiteral::Null)
    }

    pub fn equals(left: KqlExpression, right: KqlExpression) -> Self {
        KqlExpression::Binary {
            op: KqlBinaryOp::Equal,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    pub fn and(left: KqlExpression, right: KqlExpression) -> Self {
        KqlExpression::Binary {
            op: KqlBinaryOp::And,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    pub fn or(left: KqlExpression, right: KqlExpression) -> Self {
        KqlExpression::Binary {
            op: KqlBinaryOp::Or,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    pub fn property(object: KqlExpression, property: &str) -> Self {
        KqlExpression::Property {
            object: Box::new(object),
            property: property.to_string(),
        }
    }

    pub fn function(name: &str, args: Vec<KqlExpression>) -> Self {
        KqlExpression::Function {
            name: name.to_string(),
            args,
        }
    }
}

/// Binary serialization/deserialization using bincode
impl KqlQuery {
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
        let query = KqlQueryBuilder::new()
            .from_table("users")
            .where_clause(KqlExpression::equals(
                KqlExpression::column("role"),
                KqlExpression::string_literal("admin"),
            ))
            .take(100)
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
            KqlOperation::Where(expr) => match expr {
                KqlExpression::Binary { op, .. } => {
                    anyhow::ensure!(op == KqlBinaryOp::Equal, "expected Equal op");
                }
                _ => anyhow::bail!("Expected binary expression"),
            },
            _ => anyhow::bail!("Expected where operation"),
        }
        Ok(())
    }

    #[test]
    fn test_binary_serialization() -> anyhow::Result<()> {
        let query = KqlQueryBuilder::new()
            .from_table("logs")
            .where_clause(KqlExpression::equals(
                KqlExpression::column("level"),
                KqlExpression::string_literal("error"),
            ))
            .build()
            .map_err(|e| anyhow::anyhow!(e))?;

        let binary_data = query.to_binary().map_err(|e| anyhow::anyhow!(e))?;
        anyhow::ensure!(!binary_data.is_empty(), "binary data should not be empty");

        let deserialized = KqlQuery::from_binary(&binary_data).map_err(|e| anyhow::anyhow!(e))?;
        anyhow::ensure!(
            query == deserialized,
            "deserialized query should match original"
        );
        Ok(())
    }

    #[test]
    fn test_complex_expression() -> anyhow::Result<()> {
        let expr = KqlExpression::and(
            KqlExpression::equals(
                KqlExpression::column("status"),
                KqlExpression::string_literal("active"),
            ),
            KqlExpression::Binary {
                op: KqlBinaryOp::GreaterThan,
                left: Box::new(KqlExpression::column("age")),
                right: Box::new(KqlExpression::int_literal(18)),
            },
        );

        match expr {
            KqlExpression::Binary { op, .. } => {
                anyhow::ensure!(op == KqlBinaryOp::And, "expected And op");
            }
            _ => anyhow::bail!("Expected binary expression"),
        }
        Ok(())
    }

    #[test]
    fn test_aggregate_query() -> anyhow::Result<()> {
        let query = KqlQueryBuilder::new()
            .from_table("events")
            .summarize(
                vec![KqlExpression::column("category")],
                vec![KqlAggregate {
                    function: KqlAggregateFunction::Count,
                    expression: None,
                    alias: "count".to_string(),
                }],
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
            KqlOperation::Summarize {
                group_by,
                aggregates,
            } => {
                anyhow::ensure!(group_by.len() == 1, "expected 1 group by");
                anyhow::ensure!(aggregates.len() == 1, "expected 1 aggregate");
            }
            _ => anyhow::bail!("Expected summarize operation"),
        }
        Ok(())
    }
}
