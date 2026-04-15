# Builtin Function Implementation Summary

## Overview

Successfully implemented support for Rego builtin functions in the Rego-to-KQL translator. This enables translation of common Rego builtin function calls to their KQL equivalents.

## Implementation Details

### 1. Expression Translation (`src/rego_to_kql_ir.rs`)

- **Added `Expr::Call` handling** in `translate_expr_to_kql()` method
- **Added `translate_function_call()`** method to extract function name and translate parameters
- **Added `map_builtin_function()`** method to map Rego builtins to KQL equivalents

### 2. Database Parser Support (`src/database_parser.rs`)

- **Removed restriction** on function calls in database subset
- **Added validation** for supported builtin functions
- **Added `is_supported_builtin()`** method to whitelist allowed functions

### 3. KQL Code Generation (`src/kql_codegen.rs`)

- **Fixed parentheses handling** for OR expressions to ensure proper precedence
- **Maintained compatibility** with existing binary expression generation

## Supported Functions

### Perfect Matches (Same Name & Behavior)
- `contains(string, substring)` → `contains()`
- `endswith(string, suffix)` → `endswith()`
- `startswith(string, prefix)` → `startswith()`
- `split(string, delimiter)` → `split()`
- `substring(string, start, length)` → `substring()`
- `indexof(string, substring)` → `indexof()`
- `abs(number)` → `abs()`
- `floor(number)` → `floor()`
- `round(number)` → `round()`

### Close Equivalents (Different Names)
- `lower(string)` → `tolower()`
- `upper(string)` → `toupper()`
- `replace(string, old, new)` → `replace_string()`
- `trim_space(string)` → `trim(string, " ")`
- `ceil(number)` → `ceiling()`
- `concat(delimiter, array)` → `strcat_delim()`

### Type Checking Functions
- `is_string(value)` → `gettype(value) == "string"`
- `is_number(value)` → `(gettype(value) == "int" or gettype(value) == "real")`
- `is_boolean(value)` → `gettype(value) == "bool"`
- `is_array(value)` → `gettype(value) == "array"`
- `is_object(value)` → `gettype(value) == "object"`

### JSON Functions
- `json.marshal(value)` → `tostring()`
- `json.unmarshal(string)` → `parse_json()`

### Additional Functions
- `sprintf()` → `strcat()`
- `to_number()` → `toreal()`
- `array.slice()` → `array_slice()`
- `strings.replace_n()` → `replace_string()` (simplified)

## Test Coverage

Created comprehensive test suite in `tests/kql_codegen/cases/builtin_functions.yaml`:

- **String functions**: contains, startswith, endswith, lower, upper, replace
- **Math functions**: abs, floor, ceiling
- **Type checking**: is_string, is_number
- **Combined expressions**: nested function calls
- **Complex scenarios**: multiple functions in single rule

## Examples

### Simple Function Call
```rego
# Rego
email_users contains user if {
    some user in users
    contains(user.email, "@company.com")
}

# Generated KQL
users
| where contains(email, "@company.com")
```

### Nested Function Calls
```rego
# Rego
formatted_users contains user if {
    some user in users
    startswith(upper(user.role), "ADMIN")
}

# Generated KQL
users
| where startswith(toupper(role), "ADMIN")
```

### Type Checking with Complex Logic
```rego
# Rego
numeric_fields contains field if {
    some field in fields
    is_number(field.value)
}

# Generated KQL
fields
| where (gettype(value) == "int" or gettype(value) == "real")
```

## Error Handling

- **Unsupported functions** are rejected with clear error messages
- **Argument validation** ensures correct number of parameters
- **Complex function expressions** (e.g., `some_var()`) are not supported

## Benefits

1. **Expanded Rego Support**: Can now translate policies using common builtin functions
2. **Type Safety**: Validation ensures only supported functions are used
3. **Correct KQL Generation**: Proper precedence handling and function mapping
4. **Extensible Design**: Easy to add more builtin functions in the future

## Future Enhancements

1. **Array Functions**: `array.concat`, `array.contains`, etc.
2. **String Functions**: `regex.match`, `regex.split`, etc.
3. **Date/Time Functions**: `time.now_ns`, `time.parse_ns`, etc.
4. **Crypto Functions**: `crypto.md5`, `crypto.sha256`, etc.
5. **Advanced Logic**: Support for function expressions and custom functions
