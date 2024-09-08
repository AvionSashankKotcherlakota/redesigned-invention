# CustomMembershipProvider.Core

## Overview

**CustomMembershipProvider.Core** is a .NET Core implementation of the `SqlMembershipProvider` from the .NET Framework. This custom membership provider is designed to handle user authentication, password management, and schema validation, closely aligned with the behavior of the original `SqlMembershipProvider`, while using ADO.NET for database interactions.

## Features

- **User Management**: Create, validate, and manage users with functionality similar to the original `SqlMembershipProvider`.
- **Password Validation**: Event-driven password validation using `ValidatePasswordEventArgs` to ensure compliance with custom password policies.
- **Schema Version Checking**: Verifies that the database schema is compatible with the provider, preventing operation with incompatible schemas.
- **Legacy Compatibility**: Supports backward compatibility with older `SqlMembershipProvider` stores, including the use of `PasswordCompatMode` for hashing compatibility with legacy systems.
- **Dependency Injection**: Fully integrated with .NET Core's dependency injection system for easy integration into modern applications.
- **Customizable**: Easily extendable and customizable to meet specific project needs.

## Components

### 1. `CustomSqlMembershipProvider`
The main provider class that implements all core membership functionalities such as user creation, password validation, and schema version checking.

### 2. `ValidatePasswordEventArgs`
A model class used to pass data during password validation events. It allows custom validation logic to be implemented when passwords are created or changed.

### 3. `MembershipValidatePasswordEventHandler`
A delegate used to handle password validation events, enabling the implementation of custom validation rules and policies.

### 4. `SecUtility`
A utility class that provides common helper methods such as parameter validation, reading configuration values, and encoding/decoding functionalities.

### 5. `PasswordUtility`
Handles password encryption, decryption, and validation, utilizing .NET Core's `IDataProtectionProvider` for secure password management.

### 6. `MembershipDataAccess`
Handles direct interaction with the database, managing SQL commands related to membership functions (e.g., user creation, password checks, etc.).

## Getting Started

### Prerequisites

- .NET Core SDK installed on your machine.
- An existing SQL Server database with the legacy `aspnet_Membership` tables.

### Setup

1. **Clone the repository**:
    ```bash
    git clone https://github.com/AvionSashankKotcherlakota/redesigned-invention.git
    ```

2. **Navigate to the project directory**:
    ```bash
    cd CustomMembershipProvider/CustomMembershipProvider.Core
    ```

3. **Build the project**:
    ```bash
    dotnet build
    ```

4. **Configure your app**:
   Update the `appsettings.json` or use the provided `appsettings.example.json` to set up the required configuration such as connection strings and membership settings.

5. **Dependency Injection**:
   Make sure to register the `CustomSqlMembershipProvider`, `IPasswordUtility`, and `IMembershipDataAccess` in your service collection:

    ```csharp
    services.AddSingleton<IPasswordUtility, PasswordUtility>();
    services.AddSingleton<IMembershipDataAccess, MembershipDataAccess>();
    services.AddSingleton<ICustomSqlMembershipProvider, CustomSqlMembershipProvider>();
    ```

### Testing

A console app has been provided as part of this project for testing purposes. It uses the `CustomSqlMembershipProvider` to interact with the membership database and test its functionalities.

#### Running the Console App

1. **Configure**: Make sure the `appsettings.json` in the console app contains the correct connection string and membership settings.
   
2. **Run the Console App**: Execute the console app to test key functionalities like user validation, password reset, and user management.

   ```bash
   dotnet run --project MembershipProviderConsoleTest
   ```

3. **Sample Tests**: The console app contains tests for various functionalities:

   - User validation (login)
   - Password reset
   - Change password
   - Unlock user
   - Get user by username and user ID

Example usage in the console app:

```csharp
var provider = serviceProvider.GetService<ICustomSqlMembershipProvider>();

// Example: Validate user login
bool isValid = provider.ValidateUser("username", "password");

// Example: Test password reset
var resetPassword = provider.ResetPassword("username", "answer");
```

## Configuration

The provider uses `appsettings.json` for configuration. You can find a sample configuration in `appsettings.example.json` to set up the connection strings, password settings, and membership-specific options like password length, format, and retrieval options.
