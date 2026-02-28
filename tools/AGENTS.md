# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this directory.

## Overview

This **tools** directory contains the **ATM (AccessTokenManager) command-line tool** - a debugging and testing utility for the OpenHarmony access token management system.

### Tool Information
- **Tool Name**: `atm`
- **Language**: C++
- **Purpose**: Command-line interface for debugging and testing permission management features
- **Location**: `accesstoken/` subdirectory

## Directory Structure

```
tools/
├── accesstoken/
│   ├── include/           # Header files
│   │   ├── atm_command.h  # Main command processor
│   │   └── to_string.h    # String conversion utilities
│   ├── src/               # Source files
│   │   ├── main.cpp       # Entry point
│   │   ├── atm_command.cpp # Command implementation
│   │   └── to_string.cpp  # String utilities
│   └── BUILD.gn           # Build configuration
└── BUILD.gn               # Group build configuration
```

## Building the Tool

```bash
# From OpenHarmony root
./build.sh --product-name rk3568 --build-target access_token

# Or using part compile
hb build access_token -i

# Output location
./out/rk3568/security/access_token/tools/
```

Tool installation path on device: `/system/bin/atm`

## Commands

### help
```bash
atm help
```
Lists all available commands.

### dump
Dump system service/application token information, permissions, and records.

```bash
# List all permission definitions
atm dump -d
atm dump --definition

# List permission definition for specific permission
atm dump -d -p ohos.permission.CAMERA

# List all token information in system
atm dump -t
atm dump --all

# Get single token info by tokenId
atm dump -t -i <token-id>
atm dump --token-info --token-id <token-id>

# Get token info by bundle name
atm dump -t -b <bundle-name>
atm dump --token-info --bundle-name <bundle-name>

# Get token info by system service process name
atm dump -t -n <process-name>
atm dump --token-info --process-name <process-name>

# List permission used records (non-user builds only)
atm dump -r
atm dump -r -i <token-id>
atm dump -r -p <permission-name>

# List permission used types (non-user builds only)
atm dump -v
atm dump -v -i <token-id>
atm dump -v -p <permission-name>
```

### perm
Grant or revoke permissions (non-user builds only).

```bash
# Grant a permission
atm perm -g -i <token-id> -p <permission-name>
atm perm --grant --token-id <token-id> --permission-name <permission-name>

# Cancel/revoke a permission
atm perm -c -i <token-id> -p <permission-name>
atm perm --cancel --token-id <token-id> --permission-name <permission-name>
```

### toggle
Set/get toggle request/record status (non-user builds only).

```bash
# Set request status for user and permission
atm toggle request -s -i <user-id> -p <permission-name> -k <status>

# Get request status for user and permission
atm toggle request -o -i <user-id> -p <permission-name>

# Set record status for user (0=closed, 1=open)
atm toggle record -s -i <user-id> -k <status>

# Get record status for user
atm toggle record -o -i <user-id>
```

## Architecture

### Command Processing Flow

```
main.cpp
    ↓
AtmCommand::ExecCommand()
    ↓
Parse command (dump/perm/toggle)
    ↓
RunAsCommonCommandForDump() / RunAsCommonCommandForPerm() / RunAsCommonCommandForToggle()
    ↓
Execute specific operation
```

### Operation Types

The tool supports several operation types defined in `atm_command.h`:

- **DUMP_TOKEN**: Dump hap or native token info
- **DUMP_RECORD**: Dump permission used records
- **DUMP_TYPE**: Dump permission used types
- **DUMP_PERM**: Dump permission definition info
- **PERM_GRANT**: Grant permission to a token
- **PERM_REVOKE**: Revoke permission from a token

### Toggle Modes

- **TOGGLE_REQUEST**: Toggle permission request status
- **TOGGLE_RECORD**: Toggle permission recording status

## Build Variants

The tool has different capabilities based on build variant:

**User builds** (`ATM_BUILD_VARIANT_USER_ENABLE` defined):
- Limited to `dump` and `help` commands
- Cannot grant/revoke permissions
- Cannot toggle request/record status

**Non-user builds** (engineering/debug builds):
- Full functionality including `perm` and `toggle` commands
- Can modify permissions for testing
- Can control toggle states

## Dependencies

The tool depends on:
- `libaccesstoken_sdk` - Access token innerkit
- `libprivacy_sdk` - Privacy manager innerkit
- `accesstoken_common_cxx` - Common utilities
- `accesstoken_cjson_utils` - JSON parsing
- `cJSON` - External JSON library
- `ipc_single` - IPC communication

## Development Notes

### Adding New Commands

1. Add new `OptType` enum value in `atm_command.h`
2. Add help message in `atm_command.cpp`
3. Add command handler in `commandMap_` initialization
4. Implement command processing logic
5. Update BUILD.gn if new dependencies needed

### Code Style Guidelines

**Follow OpenHarmony C++ Coding Style**
- Use 4 spaces for indentation (no tabs)
- Maximum line length: 100 characters
- Use `camelCase` for function names and variables
- Use `PascalCase` for class names
- Use `UPPER_SNAKE_CASE` for constants and macros
- Always include copyright header in new files

**Naming Conventions**
```cpp
// Good
class AtmCommand final {
    void RunAsDumpCommand();
    std::string resultReceiver_;
    static constexpr int32_t MAX_COUNTER = 1000;
};

// Avoid
class atm_command {
    void run_as_dump_command();
    std::string ResultReceiver;
};
```

### Command Implementation Pattern

**Standard Command Flow**
```cpp
// 1. Parse arguments using getopt_long()
int option;
while ((option = getopt_long(argc, argv, "option_string", long_options, nullptr)) != -1) {
    // Handle each option
}

// 2. Validate required parameters
if (missingRequiredParams) {
    return RunAsCommandMissingOptionArgument(requiredOptions);
}

// 3. Call SDK/API methods
AccessTokenID tokenID = GetTokenIDByName(bundleName);
auto result = AccessTokenKit::VerifyAccessToken(tokenID, permissionName);

// 4. Format output
std::stringstream ss;
ss << "Result: " << result;
return ss.str();
```

### IPC Call Considerations

**All Service Calls Go Through IPC**
- The tool communicates with AccessTokenService via IPC (Binder)
- IPC calls can fail; always check return values
- Service may be temporarily unavailable; handle gracefully

### Build Configuration

**User Build Detection**
```cpp
// The tool automatically detects build variant via compile-time flag
#ifdef ATM_BUILD_VARIANT_USER_ENABLE
    // User build - hide sensitive commands
#else
    // Non-user build - show all commands
#endif
```

**Adding New Dependencies**
- Update `accesstoken/BUILD.gn` with new `deps` or `external_deps`
  - `deps` only supports dependencies within the module
  - `external_deps` supports dependencies from outside the module
- Keep dependencies minimal to reduce binary size
- Prefer using existing innerkits over direct service calls

### Unit Testing

**Write Tests for New Commands**
- Test files located in `tools/accesstoken/test`
- Use gtest framework
- Test both success and failure scenarios

### Code Review Checklist

Before submitting code changes, verify:

- [ ] All commands have help messages
- [ ] Error cases are handled with clear messages
- [ ] No memory leaks (use valgrind if needed)
- [ ] Log statements use `%{public}s` format
- [ ] User input is validated before use
- [ ] IPC return values are checked
- [ ] Code follows style guidelines
- [ ] Comments explain complex logic
- [ ] No hardcoded magic numbers (use named constants)
- [ ] Build succeeds for both user and non-user variants

### Common Coding Mistakes

1. **Not checking IPC return values**
   ```cpp
   // Wrong - ignores return value
   proxy->GrantPermission(tokenID, permission);

   // Correct - check return value
   int ret = proxy->GrantPermission(tokenID, permission);
   if (ret != RET_SUCCESS) { /* handle error */ }
   ```

2. **Using C-style strings**
   ```cpp
   // Wrong - unsafe
   char buffer[256];
   sprintf(buffer, "TokenID: %u", tokenID);

   // Correct - type-safe
   std::string result = "TokenID: " + std::to_string(tokenID);
   ```

3. **Hardcoded command strings**
   ```cpp
   // Wrong
   if (command == "dump") { ... }

   // Correct
   if (command == DUMP_COMMAND) { ... }  // Use constant
   ```

4. **Not handling build variant differences:** User-sensitive operations should only be supported in non-user builds
   ```cpp
   // Always wrap user-build-specific code with conditional compilation
   #ifndef ATM_BUILD_VARIANT_USER_ENABLE
   // Sensitive operations here
   #endif
   ```

### Error Handling

The tool uses standard error codes from `access_token_error.h`.
Error messages are returned via string output to stdout.

**Standard Error Format**
```cpp
return "error: " + errorMessage;
```

### Testing

Test the tool on a running OpenHarmony device:
```bash
# Check if tool is available
which atm

# Run help command
atm help

# List all tokens
atm dump -t
```

## Important Notes

### Security Considerations

⚠️ **Permission Modifications Affect System Security**
- The `perm` command directly modifies permission grants for applications
- Only use on test devices; never modify permissions on production devices
- Granting sensitive permissions (CAMERA, LOCATION, MICROPHONE, etc.) may compromise user privacy
- Revoking system-critical permissions may cause system instability or application failures

⚠️ **User Build Restrictions**
- User builds intentionally restrict `perm` and `toggle` commands for security
- These restrictions cannot be bypassed without recompiling the system
- Always use engineering/debug builds for development and testing

### Build Variant Compatibility

**Command availability varies by build type**:
- User builds: Only `dump` and `help` available
- Non-user builds: All commands available
