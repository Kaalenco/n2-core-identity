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
    ├── N2.Core.Identity/                # Library (net8.0 + net10.0)
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

Integration tests are tagged `[TestCategory("Integration")]` and require a running database. There are two variants:

| Category              | Required connection string key |
|-----------------------|-------------------------------|
| `Integration.MySql`   | `ConnectionStrings:UserDbMySqlTest`    |
| `Integration.SqlServer` | `ConnectionStrings:UserDbSqlServerTest` |

Supply the connection string via user secrets (ID `N2-Core-0c368d89-5cb3-4451-9c68-b79e69920a09`) or the matching double-underscore environment variable (`ConnectionStrings__UserDbMySqlTest`).

To run the MySQL integration tests locally using Docker:

```bash
docker compose -f src/docker-compose.integration.yml up \
  --build --exit-code-from integration-tests --abort-on-container-exit

docker compose -f src/docker-compose.integration.yml down --volumes
```

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
| 2 | Code Analysis | parallel with Integration Tests, after Build |
| 3 | Integration Tests (MySQL) | parallel with Code Analysis — opt-in, see below |
| 4 | Publish NuGet | after Build passes and Integration Tests passed or skipped |

### Pipeline variables

| Variable | Where set | Description |
|----------|-----------|-------------|
| `buildConfiguration` | YAML | MSBuild configuration (`Release`) |
| `artifactsFeedName` | YAML | Azure Artifacts feed (`vault-packages`) |
| `MYSQL_INTEGRATION_TESTS` | Pipeline UI | Enables the Integration Tests stage (see below) |

#### Enabling MySQL integration tests

The Integration Tests stage in the publish pipeline is **skipped by default**. It runs only when `MYSQL_INTEGRATION_TESTS` is set to exactly `true` in the Azure DevOps pipeline UI.

To enable it:

1. Go to **Pipelines → n2-core-identity-ci-publish → Edit → Variables**.
2. Add a variable named `MYSQL_INTEGRATION_TESTS` with value `true`.
3. Optionally tick **Settable at queue time** to toggle it per run without editing the variable permanently.

When the variable is absent or set to any other value, the stage is skipped and the Publish stage proceeds normally.

### Azure DevOps setup required

- **Artifacts feed permissions:** `vault-packages` → Feed settings → Permissions → add `N2 Vault services Build Service (gjkaal)` with role **Contributor**.
- **Pipeline setting:** enable **Allow scripts to access the OAuth token** (required for the run-retention steps).

### Run retention

- PR builds are retained for **3 days**.
- Trunk builds are retained for **10 days**.
- Published builds (after a successful Publish stage) are retained for **365 days**.

## Regular maintenance

### Runtime targets

The library targets `net8.0` and `net10.0`. Both SDK versions are installed in the pipeline via `UseDotNet@2` steps. When adding or dropping a target framework:

1. Update `<TargetFrameworks>` in `src/N2.Core.Identity/N2.Core.Identity.csproj`.
2. Add or remove the matching `UseDotNet@2` step in both pipeline YAML files.
3. Update the framework-conditional `<ItemGroup>` blocks in the `.csproj` for any packages that differ by TFM.

### Package version

The version is set in `src/N2.Core.Identity/N2.Core.Identity.csproj`:

```xml
<Version>1.7.3</Version>
<PackageVersion>1.7.3</PackageVersion>
<AssemblyVersion>1.7.3</AssemblyVersion>
```

Bump all three before tagging a release. The `.nupkg` is produced automatically by `GeneratePackageOnBuild` on Release builds.

### Dependencies

Check for outdated or vulnerable packages with:

```bash
dotnet list src package --outdated
dotnet list src package --vulnerable
```

Framework-specific packages (e.g. `Microsoft.AspNetCore.*`) have separate versions under the `net8.0` and `net10.0` conditional `<ItemGroup>` blocks — update both.
