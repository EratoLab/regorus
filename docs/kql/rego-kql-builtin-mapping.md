# Rego to KQL Builtin Function Mapping

This document maps Rego builtin functions to their KQL equivalents as implemented in the Rego-to-KQL translator.

## Currently Implemented Functions

These functions are fully implemented and tested in the translation system:

### String Functions (Perfect Matches)

| Rego Builtin                        | KQL Function                        | Implementation Status | Notes                             |
|--------------------------------------|-------------------------------------|----------------------|-----------------------------------|
| `contains(string, substring)`        | `contains(string, substring)`       | ✅ Implemented        | Exact match - same name and behavior |
| `endswith(string, suffix)`           | `endswith(string, suffix)`          | ✅ Implemented        | Exact match                       |
| `startswith(string, prefix)`         | `startswith(string, prefix)`        | ✅ Implemented        | Exact match                       |
| `split(string, delimiter)`           | `split(string, delimiter)`          | ✅ Implemented        | Exact match                       |
| `substring(string, start, length)`   | `substring(string, start, length)`  | ✅ Implemented        | Exact match                       |
| `indexof(string, substring)`         | `indexof(string, substring)`        | ✅ Implemented        | Exact match                       |

### String Functions (Name Mappings)

| Rego Builtin                        | KQL Function                        | Implementation Status | Notes                             |
|--------------------------------------|-------------------------------------|----------------------|-----------------------------------|
| `lower(string)`                      | `tolower(string)`                   | ✅ Implemented        | Simple name mapping               |
| `upper(string)`                      | `toupper(string)`                   | ✅ Implemented        | Simple name mapping               |
| `replace(string, old, new)`          | `replace_string(string, old, new)`  | ✅ Implemented        | Simple name mapping               |
| `trim_space(string)`                 | `trim(string, " ")`                 | ✅ Implemented        | Adds space parameter              |

### Mathematical Functions

| Rego Builtin                        | KQL Function                        | Implementation Status | Notes                             |
|--------------------------------------|-------------------------------------|----------------------|-----------------------------------|
| `abs(number)`                        | `abs(number)`                       | ✅ Implemented        | Exact match                       |
| `floor(number)`                      | `floor(number)`                     | ✅ Implemented        | Exact match                       |
| `round(number)`                      | `round(number)`                     | ✅ Implemented        | Supports 1 or 2 arguments         |
| `ceil(number)`                       | `ceiling(number)`                   | ✅ Implemented        | Simple name mapping               |

### Type Checking Functions

| Rego Builtin                        | KQL Implementation                  | Implementation Status | Notes                             |
|--------------------------------------|-------------------------------------|----------------------|-----------------------------------|
| `is_string(value)`                   | `gettype(value) == "string"`       | ✅ Implemented        | Uses gettype comparison           |
| `is_number(value)`                   | `gettype(value) in ("int", "real")` | ✅ Implemented        | Checks both int and real types    |
| `is_boolean(value)`                  | `gettype(value) == "bool"`         | ✅ Implemented        | Uses gettype comparison           |
| `is_array(value)`                    | `gettype(value) == "array"`        | ✅ Implemented        | Uses gettype comparison           |
| `is_object(value)`                   | `gettype(value) == "object"`       | ✅ Implemented        | Uses gettype comparison           |

### Array/Collection Functions

| Rego Builtin                        | KQL Function                        | Implementation Status | Notes                             |
|--------------------------------------|-------------------------------------|----------------------|-----------------------------------|
| `count(collection)`                  | `array_length(array)`               | ✅ Implemented        | For scalar context                |

### JSON Functions

| Rego Builtin                        | KQL Function                        | Implementation Status | Notes                             |
|--------------------------------------|-------------------------------------|----------------------|-----------------------------------|
| `json.marshal(object)`               | `tostring(object)`                  | ✅ Implemented        | Converts object to JSON string    |
| `json.unmarshal(string)`             | `parse_json(string)`                | ✅ Implemented        | Parses JSON string to object      |

### Type Conversion Functions

| Rego Builtin                        | KQL Function                        | Implementation Status | Notes                             |
|--------------------------------------|-------------------------------------|----------------------|-----------------------------------|
| `to_number(string)`                  | `todouble(string)`                  | ✅ Implemented        | Converts string to double         |

### Utility Functions

| Rego Builtin                        | KQL Function                        | Implementation Status | Notes                             |
|--------------------------------------|-------------------------------------|----------------------|-----------------------------------|
| `sprintf(format, ...)`               | `strcat(...)`                       | ✅ Implemented        | Basic string concatenation        |
| `concat(delimiter, array)`           | `strcat_delim(delimiter, ...)`      | ✅ Implemented        | String concatenation with delimiter |

## Translation Examples

### Basic String Operations
```rego
# Rego
contains(user.email, "@company.com")
startswith(user.name, "admin_")
lower(user.department)
```

```kql
# Generated KQL
email contains "@company.com"
name startswith "admin_"
tolower(department)
```

### Type Checking
```rego
# Rego
is_string(user.name)
is_number(user.age)
```

```kql
# Generated KQL  
gettype(name) == "string"
(gettype(age) == "int" or gettype(age) == "real")
```

### Mathematical Operations
```rego
# Rego
abs(temperature_diff)
ceil(score / 100.0)
```

```kql
# Generated KQL
abs(temperature_diff)
ceiling(score / 100.0)
```

### Array Functions (More Implemented)

| Rego Builtin                        | KQL Function                        | Implementation Status | Notes                             |
|--------------------------------------|-------------------------------------|----------------------|-----------------------------------|
| `array.concat(arr1, arr2)`           | `array_concat(arr1, arr2)`          | ✅ Implemented        | Array concatenation               |
| `array.reverse(array)`               | `array_reverse(array)`              | ✅ Implemented        | Reverse array order               |
| `array.slice(array, start, end)`     | `array_slice(array, start, end-1)`  | ✅ Implemented        | Extract array slice, end index adjusted |
| `array.length(array)`                | `array_length(array)`               | ✅ Implemented        | Get array length                  |
| `sort(array)`                        | `array_sort_asc(array)`             | ✅ Implemented        | Sort array ascending              |

### Additional String Functions (More Implemented)

| Rego Builtin                        | KQL Function                        | Implementation Status | Notes                             |
|--------------------------------------|-------------------------------------|----------------------|-----------------------------------|
| `strings.reverse(string)`            | `reverse(string)`                   | ✅ Implemented        | String reversal                   |
| `trim_left(string, chars)`           | `trim_start(string, chars)`         | ✅ Implemented        | Remove leading characters         |
| `format_int(number, base)`           | `tostring(number)`                  | ✅ Implemented        | Number to string (base ignored)   |
| `strings.replace_n(str, old, new, n)` | `replace_string(str, old, new)`     | ✅ Implemented        | String replacement (count ignored) |

### Regex Functions

| Rego Builtin                        | KQL Function                        | Implementation Status | Notes                             |
|--------------------------------------|-------------------------------------|----------------------|-----------------------------------|
| `regex.match(pattern, string)`       | `string matches regex pattern`      | ✅ Implemented        | Regex pattern matching            |

### Encoding Functions

| Rego Builtin                        | KQL Function                        | Implementation Status | Notes                             |
|--------------------------------------|-------------------------------------|----------------------|-----------------------------------|
| `base64.encode(string)`              | `base64_encode_tostring(string)`    | ✅ Implemented        | Base64 encoding                   |
| `base64.decode(string)`              | `base64_decode_tostring(string)`    | ✅ Implemented        | Base64 decoding                   |

### Additional Mathematical Functions

| Rego Builtin                        | KQL Function                        | Implementation Status | Notes                             |
|--------------------------------------|-------------------------------------|----------------------|-----------------------------------|
| `pow(base, exponent)`                | `pow(base, exponent)`               | ✅ Implemented        | Power function                    |
| `sqrt(number)`                       | `sqrt(number)`                      | ✅ Implemented        | Square root                       |
| `sin(number)`                        | `sin(number)`                       | ✅ Implemented        | Trigonometric sine                |

### Null Checking Functions

| Rego Builtin                        | KQL Function                        | Implementation Status | Notes                             |
|--------------------------------------|-------------------------------------|----------------------|-----------------------------------|
| `is_null(value)`                     | `isnull(value)`                     | ✅ Implemented        | Check if value is null            |

## Functions Not Currently Supported

These Rego functions are not yet implemented in the database subset:

### Array Aggregation Functions
- `max(array)`, `min(array)` - Array aggregations
- `sum(array)` - Array sum
- Array search and filtering functions

### Advanced String Functions
- `trim_right(string, chars)` - Remove trailing characters  
- `trim(string, chars)` - Custom character trimming (general form)
- `strings.has_prefix()`, `strings.has_suffix()` - Alternative prefix/suffix checks

### Set Operations
- Set intersection (`&`)
- Set union (`|`) 
- Set difference operations

### DateTime Functions
- `time.now_ns()` - Current time
- `time.parse_ns()` - Parse time
- `time.add_date()` - Date arithmetic
- `time.format()` - Format timestamps

### Advanced Type Functions
- `type_name(value)` - Get detailed type information
- `typeof(value)` - Alternative type checking

### Bitwise Operations
- `bits.or()`, `bits.and()`, `bits.xor()` - Bitwise operations
- `bits.negate()` - Bitwise negation

## Implementation Details

### Function Translation Process

1. **Function Name Resolution**: Handles both simple names (`lower`) and dotted names (`json.marshal`)
2. **Parameter Translation**: Converts Rego expressions to KQL expressions
3. **Name Mapping**: Maps Rego function names to KQL equivalents
4. **Parameter Transformation**: Handles cases where parameter order or types differ

### Code Structure

```rust
fn map_builtin_function(
    &self,
    func_name: &str,
    args: Vec<KqlExpression>,
) -> Result<KqlExpression> {
    match func_name {
        // Exact matches
        "contains" => Ok(KqlExpression::function("contains", args)),
        
        // Name mappings
        "lower" => Ok(KqlExpression::function("tolower", args)),
        
        // Complex transformations
        "is_string" => Ok(KqlExpression::Binary {
            op: KqlBinaryOp::Equal,
            left: Box::new(KqlExpression::function("gettype", args)),
            right: Box::new(KqlExpression::string_literal("string")),
        }),
        
        _ => bail!("Function '{}' not supported in database subset", func_name),
    }
}
```

## Test Coverage

All implemented functions have comprehensive test coverage in `tests/kql_codegen/cases/builtin_functions.yaml`:

- **Basic functionality**: Normal use cases with expected input/output
- **Integration tests**: Functions used within realistic policy rules  
- **Edge cases**: Empty strings, null values, boundary conditions
- **Complex scenarios**: Multiple functions combined in single rules

## Future Implementation Priority

### High Priority (Common Operations)
1. **Array Functions**: `array.concat`, `array.slice`, `sort`
2. **Advanced String**: `trim`, `format_int`, regex functions
3. **Set Operations**: Basic set arithmetic for policy logic

### Medium Priority
1. **Aggregation Functions**: `sum`, `max`, `min` for arrays
2. **Advanced Type Conversion**: `format_int`, `parse_int`
3. **Conditional Functions**: KQL-specific `iff`, `case`, `coalesce`

### Low Priority
1. **DateTime Functions**: When time-based policies are needed
2. **Advanced Math**: Trigonometric, statistical functions
3. **Encoding Functions**: Base64, URL encoding

## Error Handling

The translator provides detailed error messages for:

- **Unsupported functions**: Clear indication of what's not implemented
- **Parameter mismatches**: Wrong number of arguments
- **Type errors**: Invalid parameter types
- **Complex expressions**: Functions that can't be translated to database subset

## Performance Considerations

1. **Direct Translation**: Perfect matches have zero overhead
2. **Type Checking**: Some functions generate complex expressions but are optimized by KQL
3. **Function Calls**: All functions translate to native KQL functions for optimal performance

---

*Last updated: August 28, 2025*  
*Implementation status: 40+ functions across 9 categories*  
*Test coverage: 13 comprehensive test scenarios covering core functionality*
