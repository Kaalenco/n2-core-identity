# 🧠 Copilot Instructions

Welcome, Copilot! Here are some guidelines to help you assist effectively in this project.

## 📦 Project Overview

This project is a library that provides reusable components and services. The project is designed 
to be modular and extensible, allowing for easy integration with other systems and applications.
The library is intended to be used in a variety of scenarios, including web applications, desktop applications, 
and cloud-based services.

It is built using:

- Language(s): C# for back-end and Svelte/TypeScript for front-end development.
- Framework(s): ASP.NET Core
- Build System: MSBuild

## 🛠️ Development Guidelines

For C#, always conform to the coding style guidelines defined in csharp-codingstyle.md when generating code.

For Svelte, follow the Svelte style guide and conventions. Prefer using TypeScript for type safety. 

# Generic

Use inline comments to explain complex logic.

Use XML-style documentation for public methods.

Suggest helper functions to reduce duplication.

Prefer readability and maintainability over cleverness.

Avoid introducing external dependencies unless necessary.

Follow existing naming and architectural patterns.

### Naming conventions

Interfaces are defined in a project with the name 'Abstractions'

The 'Abstractions' project contains all interfaces and DTOs.

The 'Abstractions' name is never used in the namespaces. Otherwise, the namespace follows the default C# naming conventions.

A POCO (Plain Old CLR Object) or DTO (Data Transfer Object) is a class that does not implement any interfaces or inherit from any base classes. It has a postfix of 'Dto' and is used to transfer data between layers.

A class that is used for data access 'Repository'.

A class that is used for business logic should have a postfix of 'Service'.

A class that is used to access external services should have a postfix of 'Client'.

Extension methods should be in a static class with a postfix of 'Extensions'. The class name should be the name of the class that is extended, followed by 'Extensions'.


# Example code

```csharp

/// <summary>
/// This is a sample class. Its purpose is to demonstrate the preferred coding style.
/// </summary>
public class MyClass {

	private int myField;
	public int MyProperty { get; set; }
	protected int MyProtectedField { get;set; }
	protected ILogger<MyClass> Logger { get; }

	/// <summary>
	/// Initializes a new instance of the <see cref="MyClass"/> class.
	/// A logger should always be injected into the constructor.
	/// </summary>
	public MyClass(int myField, ILogger<MyClass> logger) {
		this.myField = myField;
		Logger = logger;
	}



}

```

