# N2.Core.Identity — Developer Guide

This document explains how to build, test, and maintain the project locally and in CI.

## Solution Structure

```
src/
├── N2.Core.Identity/               # Main library (multi-targeted: net8.0, net10.0)
├── N2.Core.Identity.UnitTests/     # Unit and integration tests (MSTest)
├── Dockerfile.integration          # Docker image for MySQL integration tests
├── docker-compose.integration.yml  # Spins up MySQL + runs integration tests
├── Directory.Build.props           # Shared build settings (warnings as errors, analyzers)
└── N2.Core.Identity.sln
```

## Building

```bash
# Restore dependencies
dotnet restore src

# Build (Debug, all targets)
dotnet build src --no-restore

# Build (Release — also produces the .nupkg)
dotnet build src --no-restore --configuration Release
```

> `GeneratePackageOnBuild` is enabled, so a `.nupkg` is created automatically on Release builds.

## Running Tests

### Unit tests (excludes integration tests)

```bash
dotnet test src --no-build --verbosity normal --filter "TestCategory!=Integration"
```

### All tests including integration (requires a running SQL Server or MySQL instance)

```bash
dotnet test src --no-build --verbosity normal
```

### Single test by name

```bash
dotnet test src --filter "FullyQualifiedName=N2.Core.Identity.UnitTests.N2UserManagerTests.TestUserCreateAsync"
```

Test results (`.trx` files) are written to `src/TestResults/`.

## MySQL Integration Tests (Docker)

Integration tests marked `[TestCategory("Integration.MySql")]` run against a real MySQL 8.0
instance via Docker Compose. Both `docker-compose.integration.yml` and `Dockerfile.integration`
live in `src/` and should be kept together.

```bash
# Run integration tests
docker compose -f src/docker-compose.integration.yml up \
  --build \
  --exit-code-from integration-tests \
  --abort-on-container-exit

# Tear down (removes MySQL data volume)
docker compose -f src/docker-compose.integration.yml down --volumes
```

Test results (`.trx`) are written to `src/test-results/` via the volume mount defined in
`docker-compose.integration.yml`.

## CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/dotnet.yml`) runs three jobs in sequence:

| # | Job | Trigger |
|---|-----|---------|
| 1 | **Build and Test** — restore, build, unit tests | push + PR to `trunk` |
| 2 | **Integration Tests — MySQL** — Docker Compose run | after job 1 passes |
| 3 | **Publish NuGet** — Release build + `nuget push` | push to `trunk` only, after job 2 passes |

The NuGet package is only published after **both** test stages pass. PRs never trigger a publish.

## Regular Maintenance

### GitHub Actions versions

The workflow pins specific versions of community actions. Periodically check for updates using
the GitHub CLI:

```bash
gh release list --repo actions/checkout --limit 5
gh release list --repo actions/upload-artifact --limit 5
```

Always review the changelog for breaking changes before bumping a major version.
Current versions in use are documented in a comment at the top of the workflow file.

### .NET SDK targets

The library targets `net8.0` and `net10.0`. When a .NET version reaches end-of-life, remove
its `<TargetFramework>` entry from `N2.Core.Identity.csproj` and the corresponding
`<PackageReference>` condition block, then update the workflow's `Setup .NET` steps accordingly.

### NuGet package version

The package version is set manually in `N2.Core.Identity.csproj`:

```xml
<PackageVersion>1.5.3</PackageVersion>
<AssemblyVersion>1.5.3</AssemblyVersion>
<ProductVersion>1.5.3</ProductVersion>
```

Bump all three values together before merging a release to `trunk`.

### NuGet dependencies

Dependency versions are split by target framework in `N2.Core.Identity.csproj`.
Keep `net8.0` and `net10.0` dependency versions aligned where possible, and update
them when security advisories are published for any of the referenced packages.

### MySQL Docker image

The integration test compose file pins `mysql:8.0`. Update this when the production
database version changes, and verify the `Pomelo.EntityFrameworkCore.MySql` package
version is compatible with the new MySQL version.
