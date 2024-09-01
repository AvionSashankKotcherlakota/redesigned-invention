Sure! Here's a revised version of the `README.md` without the folder structure and references to the test project:

### README.md

```markdown
# CustomMembershipProvider.Core

## Overview

**CustomMembershipProvider.Core** is a .NET Core implementation of the `SqlMembershipProvider` from the .NET Framework. This custom membership provider is designed to handle user authentication, password management, and schema validation, closely aligned with the behavior of the original `SqlMembershipProvider`.

## Features

- **User Management**: Create, validate, and manage users with functionality similar to the original `SqlMembershipProvider`.
- **Password Validation**: Event-driven password validation using `ValidatePasswordEventArgs` to ensure compliance with custom password policies.
- **Schema Version Checking**: Verifies that the database schema is compatible with the provider, preventing operation with incompatible schemas.
- **Customizable**: Easily extendable and customizable to meet specific project needs.

## Components

### 1. `CustomSqlMembershipProvider`
The main provider class that implements all core membership functionalities such as user creation, password validation, and schema version checking.

### 2. `ValidatePasswordEventArgs`
A model class used to pass data during password validation events. It allows custom validation logic to be implemented when passwords are created or changed.

### 3. `MembershipValidatePasswordEventHandler`
A delegate used to handle password validation events, enabling the implementation of custom validation rules and policies.

### 4. `SecUtility`
A utility class that provides common helper methods such as parameter validation and encoding/decoding functionalities.

### 5. `CheckSchemaVersion`
Ensures that the database schema version is compatible with the provider, preventing operations with an incompatible schema.

## Getting Started

### Prerequisites

- .NET Core SDK installed on your machine.

### Setup

1. **Clone the repository**:
    ```bash
    git clone https://github.com/your-repo/CustomMembershipProvider.Core.git
    ```

2. **Navigate to the project directory**:
    ```bash
    cd CustomMembershipProvider.Core/src/CustomMembershipProvider.Core
    ```

3. **Build the project**:
    ```bash
    dotnet build
    ```

## Usage

To use the `CustomSqlMembershipProvider`, add it to your .NET Core application and configure it in your service setup or configuration files. 

### Example Configuration

```csharp
services.AddMembershipProvider<CustomSqlMembershipProvider>(options =>
{
    options.ConnectionString = "YourConnectionStringHere";
    // Additional configuration options
});
```
