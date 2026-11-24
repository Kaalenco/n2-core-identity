# N2.Core.Identity — Developer guide

This document explains how to build, test, and maintain the project locally and in CI.

## Solution structure

```
n2-core-identity/
├── .github/workflows/                   # dotnet.yml
├── docs/
├── scripts/
└── src/
    ├── N2.Core.Identity.sln
    ├── N2.Core.Identity/                # Library (net10.0 + net11.0)
    └── N2.Core.Identity.UnitTests/      # MSTest test project
```

## Building

```bash
# Restore dependencies
dotnet restore src

# Build (debug)
dotnet build src

# Build (release) — also produces .nupkg via GeneratePackageOnBuild
dotnet build src --configuration Release
```

## Running tests

### Unit tests

```bash
dotnet test src --filter "TestCategory!=Integration" --configuration Release
```

### Single test by name

```bash
dotnet test src --filter "FullyQualifiedName~N2.Core.Identity.UnitTests.N2UserManagerTests.TestUserCreateAsync"
```

Test results are written to the console and, when run in CI, published as a pipeline test attachment.

### Integration tests

Integration tests are tagged `[TestCategory("Integration")]` and require a running SQL Server database:

| Category              | Required connection string key |
|-----------------------|-------------------------------|
| `Integration.SqlServer` | `ConnectionStrings:UserDbSqlServerTest` |

Supply the connection string via user secrets (ID `N2-Core-0c368d89-5cb3-4451-9c68-b79e69920a09`) or the matching double-underscore environment variable (`ConnectionStrings__UserDbSqlServerTest`).

MySQL support and its Docker-based integration tests were removed in 2.0.0; MySQL is planned to
return as a separate package (N2.Core.Identity.MySql) once a stable EF Core 10 MySQL provider exists.

### Known flaky tests

Flaky tests carry `[TestCategory("Flaky")]`. A failure of a test listed here is not a regression
by itself; rerun it. Exclude them with `--filter "TestCategory!=Flaky"`.

There are no known flaky tests at the moment.

Fixed: the 7-day alert window test (`UserFindRecord_AlertAtExact7DayBoundary_ShouldNotBeIncluded`)
failed in about 1 of 3 runs because an alert at exactly `UtcNow.AddDays(-7)` is decided by clock
resolution and datetime precision. It is replaced by two tests with a 2-second margin on either
side of the boundary (`UserFindRecord_AlertJustOutside7DayWindow_ShouldNotBeIncluded`,
`UserFindRecord_AlertJustInside7DayWindow_ShouldBeIncluded`).

## CI/CD

GitHub Actions (`.github/workflows/`) is the CI system:

| File | Purpose | Trigger |
|------|---------|---------|
| `dotnet.yml` | Restore, Release build, unit tests, publish to `vault-packages` | push and PR to `trunk` (publish: push only) |

The feed credential is the repository secret `NUGET_PAT`; it is added to the runner's copy of
`src/nuget.config` and never committed. Publishing uses `--skip-duplicate`, so only a version bump
produces a new package. nuget.org is handled by n2-publishing from the feed.

## Regular maintenance

### Runtime targets

The library targets `net10.0` and `net11.0`. Both SDK versions are installed in the workflows via `actions/setup-dotnet`. When adding or dropping a target framework:

1. Update `<TargetFrameworks>` in `src/N2.Core.Identity/N2.Core.Identity.csproj`.
2. Update the `dotnet-version` list of `setup-dotnet` in both workflow files.
3. Update the framework-conditional `<ItemGroup>` blocks in the `.csproj` for any packages that differ by TFM.

### Package version

The version is set in `src/N2.Core.Identity/N2.Core.Identity.csproj`:

```xml
<Version>3.0.1</Version>
<PackageVersion>3.0.1</PackageVersion>
<AssemblyVersion>3.0.0.0</AssemblyVersion>
<FileVersion>3.0.1.0</FileVersion>
```

Bump them (AssemblyVersion only on a major bump) before tagging a release. The `.nupkg` is produced automatically by `GeneratePackageOnBuild` on Release builds.

### Dependencies

Check for outdated or vulnerable packages with:

```bash
dotnet list src package --outdated
dotnet list src package --vulnerable
```

Both targets share one dependency set (no framework-conditional `<ItemGroup>` blocks). EF Core and ASP.NET Core packages use the 10.0.x band. Use `dotnet list src package --vulnerable --include-transitive` to include transitive packages.
