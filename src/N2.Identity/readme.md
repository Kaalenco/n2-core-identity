# N2.Core.Entity

## Classes

### ChangeLog : IChangeLog

The class `ChangeLog` implements the interface `IChangeLog` and represents a change log entry.
It is used to store information about changes made to an entity. The structure of the model can be used
as a template for other record definitions. It features:

	- `Id` : `int` : The unique identifier of the change log entry.
	- `LogRecordId` : `Guid` : A unique identifier for external references.
	- `ReferenceId` : `Guid` : The unique identifier of the entity that was changed.
	- Other columns to store information about the change.
	- A static BuildModel method to define the structure of the model.

Define the ChangeLog in the data context where you want to implement change tracking. If you define
a datacontext usig the `CoreDataContext` class, the `ChangeLog` class is added by default.

```csharp	
public class MyDataContext(DbContextOptions options) : DbContext(options)
{
    public virtual DbSet<ChangeLog> ChangeLog { get; set; }

	 protected override void OnModelCreating([NotNull] ModelBuilder modelBuilder)
	 {
		 base.OnModelCreating(modelBuilder);

		 // Add the ChangeLog model(s) to the data context.
		 ChangeLogBuilder.BuildModel(modelBuilder);
	 }
}
```

### ChangeLogBuilder

The `ChangeLogBuilder` class provides a static method to define the structure of the `ChangeLog` model.
For a set of tables that have some common goal, a static builder class should be defined to set up the
data context. The `BuildModel` method is used to define the structure of the model. Call this method
from the `OnModelCreating` method of the data context.

### DbBaseModel : IDbBaseModel

The `DbBaseModel` class implements the `IDbBaseModel` interface and represents a base model for all
entity classes. It is used to store common properties that are shared by all entities. The structure of
the DbBaseModel contains basic tracking information. A few things to note:

	- `Id` : This is the primary key, and it is automatically assigned by the database. It is an integer
	  as this is the type that is easily sorted and indexed.
	- `PublicId` : This is a unique identifier that is used to identify the entity in a public context.
	  This is useful when the entity is exposed to the public, as the internal identifier should not be.
	- RowVersion : This is a timestamp that is used to track changes to the entity. It is used to prevent
	  concurrent updates to the same entity. Using a timestamp is more efficient than using a date-timé
	  values and is more reliable than using a version number.A bonus is that Entity Framework Core
	  recognizes a timeatamp as a concurrency token.
	- The BuildModel method is used to define the structure of the model. It should be called from
	  the buildmodel method of any derived class.

### EntityConnectionService : IEntityConnectionService

The `EntityConnectionService` class implements the `IEntityConnectionService` interface and is used to
read connection string information from the configuration.