# N2.Core.Identity — Developer guide

This document explains how to build, test, and maintain the project locally and in CI.

## Solution structure

```
n2-core-identity/
├── Pipelines/
│   ├── n2-core-identity-ci-pr.yml       # PR pipeline
│   └── n2-core-identity-ci-publish.yml  # Trunk publish pipeline
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

| Test | Category | Symptom | Cause |
|------|----------|---------|-------|
| `UserFindRecord_AlertAtExact7DayBoundary_ShouldNotBeIncluded` (`N2IdentityContextIntegrationTestsBase`) | Integration.SqlServer | Fails in about 1 of 3 runs, on net10.0 and net11.0 | Known issue. The alert is stored at exactly `UtcNow.AddDays(-7)` and the filter is `CreatedAt > UtcNow.AddDays(-7)`; the result depends on clock resolution and SQL Server datetime precision at the boundary. Fix: test with a margin (for example 1 second) on either side of the boundary. |

## CI/CD pipeline

Two pipelines are registered in Azure DevOps:

| File | Purpose | Trigger |
|------|---------|---------|
| `Pipelines/n2-core-identity-ci-pr.yml` | PR validation | PR targeting `trunk` |
| `Pipelines/n2-core-identity-ci-publish.yml` | Build, analyse, and publish | Push to `trunk` |

Path filter: only changes under `src/N2.*/**` trigger a run. Documentation-only commits are excluded.

### PR pipeline stages

| # | Stage | Runs on |
|---|-------|---------|
| 1 | Build and Test | every PR |
| 2 | Code Analysis (coverage + complexity) | after Build passes |

### Publish pipeline stages

| # | Stage | Runs on |
|---|-------|---------|
| 1 | Build and Test | push to trunk |
| 2 | Long-Running Tests | after Build, only for a new package version |
| 3 | Code Analysis | after Build |
| 4 | Publish NuGet | after Build and Long-Running Tests pass, only for a new package version |

### Pipeline variables

| Variable | Where set | Description |
|----------|-----------|-------------|
| `buildConfiguration` | YAML | MSBuild configuration (`Release`) |
| `artifactsFeedName` | YAML | Azure Artifacts feed (`vault-packages`) |

### Azure DevOps setup required

- **Artifacts feed permissions:** `vault-packages` → Feed settings → Permissions → add `N2 Vault services Build Service (gjkaal)` with role **Contributor**.
- **Pipeline setting:** enable **Allow scripts to access the OAuth token** (required for the run-retention steps).

### Run retention

- PR builds are retained for **3 days**.
- Trunk builds are retained for **10 days**.
- Published builds (after a successful Publish stage) are retained for **365 days**.

## Regular maintenance

### Runtime targets

The library targets `net10.0` and `net11.0`. Both SDK versions are installed in the pipeline via `UseDotNet@2` steps. When adding or dropping a target framework:

1. Update `<TargetFrameworks>` in `src/N2.Core.Identity/N2.Core.Identity.csproj`.
2. Add or remove the matching `UseDotNet@2` step in both pipeline YAML files.
3. Update the framework-conditional `<ItemGroup>` blocks in the `.csproj` for any packages that differ by TFM.

### Package version

The version is set in `src/N2.Core.Identity/N2.Core.Identity.csproj`:

```xml
<Version>2.0.1</Version>
<PackageVersion>2.0.1</PackageVersion>
<AssemblyVersion>2.0.1</AssemblyVersion>
```

Bump all three before tagging a release. The `.nupkg` is produced automatically by `GeneratePackageOnBuild` on Release builds.

### Dependencies

Check for outdated or vulnerable packages with:

```bash
dotnet list src package --outdated
dotnet list src package --vulnerable
```

Both targets share one dependency set (no framework-conditional `<ItemGroup>` blocks). EF Core and ASP.NET Core packages use the 10.0.x band. Use `dotnet list src package --vulnerable --include-transitive` to include transitive packages.
