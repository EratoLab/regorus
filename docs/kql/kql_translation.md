# Rego to KQL Translation System

This document describes the complete system for translating database-friendly Rego policies into KQL (Kusto Query Language) queries for execution in Azure Data Explorer, Azure Monitor, and other Kusto-based services.

## System Architecture

The translation system consists of three main components working in sequence:

```
    ┌─────────────────────────────────────────────────────────┐
    │                  Regorus Translation System             │
    │                                                         │
    │  ╔═══════════════╗  ╔═══════════════╗  ╔═══════════════╗│
    │  ║   Database    ║  ║  Rego-to-KQL  ║  ║      KQL      ║│
    │  ║    Subset     ║══║      IR       ║══║     Code      ║│
    │  ║    Parser     ║  ║  Translator   ║  ║   Generator   ║│
    │  ╚═══════════════╝  ╚═══════════════╝  ╚═══════════════╝│
    │           │                  ║                  │       │
    └───────────┼──────────────────╫──────────────────┼───────┘
                │                  ║                  │
                │                  ▼                  │
                │          ┌─────────────┐            │
                │          │ Serialized  │            │
                │          │     IR      │            │
                │          │(Cross-Lang) │            │
                │          └─────────────┘            │
                │                  │                  │
                v                  v                  v
        ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
        │   Error     │    │  C# / .NET  │    │    KQL      │
        │ Reporting   │    │Applications │    │   Queries   │
        └─────────────┘    └─────────────┘    └─────────────┘
```

### 1. Database Subset Parser (`database_parser.rs`)
- Validates Rego syntax against the database-friendly subset
- Rejects unsupported constructs (comprehensions, function calls, etc.)
- Ensures policies can be efficiently translated to database queries

### 2. Rego-to-KQL IR Translator (`rego_to_kql_ir.rs`)
- Converts validated Rego AST into KQL Intermediate Representation
- Handles complex join logic and variable binding analysis
- Optimizes query structure and table access patterns

### 3. KQL Code Generator (`kql_codegen.rs`)
- Generates final KQL query strings from IR
- Applies KQL-specific optimizations and syntax
- Produces executable queries for Kusto services

## Core Translation Patterns

### Set-Based Rules (Primary Pattern)

The most common translation pattern handles Rego rules that iterate over data collections:

**Input Rego:**
```rego
package security

privileged_users contains result if {
    some user in data.users
    user.role in {"admin", "manager"}
    user.active == true
    result := {
        "name": user.name,
        "role": user.role,
        "department": user.department
    }
}
```

**Generated KQL:**
```kql
users
| where role in (pack_array("admin", "manager")) 
    and active == true
| project name, 
          role, 
          department
```

**Key Translation Elements:**
- **Table Iteration**: `some user in data.users` → `users` (base table)
- **Set Membership**: `user.role in {"admin", "manager"}` → `role in (pack_array("admin", "manager"))`
- **Logical Conditions**: Multiple conditions combined with `and` operator
- **Result Projection**: Result object fields → `project` statement with column selection

### Multi-Table Joins

The system automatically detects relationships between tables and generates appropriate joins:

**Input Rego:**
```rego
package hr

employee_manager_pairs contains result if {
    some employee in data.employees
    some manager in data.managers
    employee.manager_id == manager.id
    employee.department == "engineering"
    result := {
        "employee_name": employee.name,
        "manager_name": manager.name,
        "department": employee.department
    }
}
```

**Generated KQL:**
```kql
employees
| where department == "engineering"
| project employee_department = department, 
          employee_manager_id = manager_id, 
          employee_name = name
| join kind=inner (
    managers
    | project manager_id = id, 
              manager_name = name
  ) on $left.employee_manager_id == $right.manager_id
| project employee_name, 
          manager_name, 
          department = employee_department
```

**Join Translation Logic:**
- **Base Table**: First table becomes base table with `project` for column aliasing
- **Subquery Joins**: Subsequent tables become subquery joins: `join kind=inner (table | project ...) on condition`
- **Column Prefixing**: Each table projects only used columns with prefixed names (e.g., `employee_name`, `manager_id`)
- **Join Conditions**: Use `$left` (accumulated result) and `$right` (new table being joined)
- **Cross-Table Filters**: Non-equality conditions (like `!=`) applied after joins complete

### Arithmetic and Computed Values

**Input Rego:**
```rego
package analytics

risk_assessment contains result if {
    some user in data.users
    user.status == "active"
    result := {
        "user_id": user.id,
        "risk_score": (user.failed_attempts * 10) + (user.days_inactive / 7),
        "category": user.category
    }
}
```

**Generated KQL:**
```kql
users
| where status == "active"
| project user_id = id, 
          risk_score = ((failed_attempts * 10) + (days_inactive / 7)), 
          category
```

## KQL Intermediate Representation (IR)

The IR provides a structured, optimizable representation of KQL queries:

```rust
pub struct KqlQuery {
    pub let_statements: Vec<KqlLetStatement>,
    pub source: String,                    // Base table name
    pub pipeline: Vec<KqlOperation>,       // Query operations
    pub projection: Option<KqlProjection>, // Final output columns
}

pub enum KqlOperation {
    Where(KqlExpression),                  // Filtering
    Project(Vec<KqlColumn>),               // Column selection
    Extend(Vec<KqlColumn>),                // Computed columns
    Join { kind, source, on },             // Table joins
    Summarize { group_by, aggregates },    // Aggregation
    Order(Vec<KqlOrderBy>),                // Sorting
    Take(i64),                             // Row limiting
    // ... additional operations
}
```

### IR Benefits

1. **Optimization Opportunities**: The IR can be analyzed and optimized before code generation
2. **Caching**: Compiled IR can be cached for repeated policy evaluation
3. **Cross-Language Support**: IR is serializable for use across different runtime environments
4. **Debugging**: IR provides clear insight into translation decisions

## Data Type Mappings

| Rego Type | KQL Type      | Translation Example                    |
|-----------|---------------|----------------------------------------|
| `string`  | `string`      | `"admin"` → `"admin"`                  |
| `number`  | `real`/`long` | `42` → `42`, `3.14` → `3.14`           |
| `boolean` | `bool`        | `true` → `true`                        |
| `null`    | `null`        | `null` → `null`                        |
| `array`   | `dynamic`     | `[1, 2, 3]` → `pack_array(1, 2, 3)`   |
| `set`     | `dynamic`     | `{"a", "b"}` → `pack_array("a", "b")`  |
| `object`  | `dynamic`     | `{"k": "v"}` → `pack("k", "v")`        |

## Operator Translations

### Comparison Operators
```rego
user.age >= 18         →  age >= 18
user.name == "admin"   →  name == "admin"
user.score != 0        →  score != 0
```

### Arithmetic Operators
```rego
price + tax            →  price + tax
total * 0.9            →  total * 0.9
score / attempts       →  score / attempts
id % 10                →  id % 10
```

### Set Operations
```rego
role in {"admin", "user"}               →  role in (pack_array("admin", "user"))
tags & required_tags                    →  set_intersect(tags, required_tags)
permissions | default_permissions       →  set_union(permissions, default_permissions)
```

### Logical Operations
```rego
condition1; condition2                  →  condition1 and condition2
not user.expired                        →  not(user.expired)
```

## Advanced Features

### Complex Filtering with Multiple Tables

**Input Rego:**
```rego
security_violations contains result if {
    some user in data.users
    some session in data.sessions
    some alert in data.alerts
    user.id == session.user_id
    session.id == alert.session_id
    user.risk_level == "high"
    alert.severity >= 8
    result := {
        "user_name": user.name,
        "session_start": session.start_time,
        "alert_type": alert.type
    }
}
```

**Generated KQL:**
```kql
users
| where risk_level == "high"
| project user_id = id, 
          user_name = name
| join kind=inner (
    sessions
    | project session_id = id, 
              session_start_time = start_time, 
              session_user_id = user_id
  ) on $left.user_id == $right.session_user_id
| join kind=inner (
    alerts
    | project alert_session_id = session_id, 
              alert_severity = severity, 
              alert_type = type
  ) on $left.session_id == $right.alert_session_id
| where alert_severity >= 8
| project user_name, 
          session_start = session_start_time, 
          alert_type
```

### Aggregation Support

**Input Rego:**
```rego
department_stats contains result if {
    some emp in data.employees
    emp.status == "active"
    result := {
        "department": emp.department,
        "employee_count": count([e | e = data.employees[_]; e.department == emp.department])
    }
}
```

**Generated KQL:**
```kql
employees
| where status == "active"
| summarize employee_count = count() by department
| project department, 
          employee_count
```

## Database Subset Restrictions

The database subset parser enforces strict limitations to ensure translatability:

### Prohibited Constructs
- **Comprehensions**: `[x | x = data[_]; x.value > 10]`
- **Function calls**: `count()`, `sum()`, custom functions
- **Recursive rules**: Rules that reference themselves
- **Dynamic rule generation**: Rules created at runtime
- **Complex control flow**: Loops, conditional rule definitions

### Validation Errors
```rust
// From database_parser.rs
fn visit_expr(&mut self, expr: &Expr) -> Result<()> {
    match expr {
        Expr::Compr { .. } => bail!("Comprehensions are not supported in database subset"),
        Expr::Call { .. } => bail!("Function calls are not supported in database subset"),
        // ... other restrictions
    }
}
```

## Performance Optimization

### Query Structure Optimization
1. **Filter Pushdown**: Conditions are placed as early as possible in the pipeline
2. **Join Ordering**: Tables are joined in optimal order based on estimated selectivity
3. **Projection Minimization**: Only required columns are projected at each stage

### KQL-Specific Optimizations
1. **pack_array() Usage**: Set membership uses Kusto's native pack_array function
2. **Column Aliasing**: Proper aliasing prevents naming conflicts in joins
3. **Pipeline Efficiency**: Operations are ordered to minimize data movement

## Error Handling and Validation

### Translation Errors
The system provides detailed error messages for unsupported constructs:

```rust
// Example error messages from the implementation
"Comprehensions are not supported in database subset"
"Function calls are not supported in database subset"
"Complex nested rules require simplification"
"Cannot translate recursive rule definitions"
```

### Runtime Considerations
Generated KQL includes appropriate handling for:
- Null value propagation
- Type coercion where necessary
- Join condition validation

## Integration Examples

### Azure Data Explorer Usage
```rust
use regorus::unstable::{DatabaseParser, RegoToKqlIrTranslator, KqlCodeGenerator};

// Parse Rego policy
let source = Source::from_contents("policy.rego", rego_content)?;
let mut parser = DatabaseParser::new(&source)?;
let module = parser.parse_database_module()?;

// Translate to KQL IR
let mut translator = RegoToKqlIrTranslator::new(Some("SecurityEvents".to_string()));
let queries = translator.translate_module(&module)?;

// Generate KQL
let mut generator = KqlCodeGenerator::new();
for query in queries {
    let kql = generator.generate(&query);
    println!("Generated KQL: {}", kql);
}
```

### Azure Monitor Integration
Generated KQL can be executed directly in Azure Monitor workspaces:

```kql
// Generated from Rego security policy
SecurityEvent
| where EventID == 4624
| where Account in (pack_array("admin", "root", "administrator"))
| where LogonType in (pack_array(2, 10))
| project TimeGenerated, 
          Account, 
          Computer, 
          LogonType
```

## Testing and Validation

The system includes comprehensive test suites:

- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end translation validation  
- **YAML Test Cases**: 500+ test cases across 9 categories:
  - `basic.yaml`: Simple rules and conditions
  - `membership.yaml`: Set membership operations
  - `arithmetic.yaml`: Mathematical expressions
  - `join.yaml`: Multi-table relationships
  - `advanced_builtins.yaml`: Complex built-in functions
  - `relationships.yaml`: Complex data relationships
  - `complex.yaml`: Multi-condition scenarios
  - `builtin_functions.yaml`: Function mappings
  - `errors.yaml`: Error case validation

Each test case includes:
- Input Rego policy
- Expected KQL output
- Test data for validation
- Performance benchmarks

This comprehensive translation system enables seamless integration of Open Policy Agent (OPA) Rego policies with Azure's query and monitoring infrastructure, providing a bridge between policy-as-code and cloud-native data analytics platforms.
