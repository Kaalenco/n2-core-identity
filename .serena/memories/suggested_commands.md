# Suggested Commands

> IMPORTANT: Claude Code must NEVER run `dotnet build` or `dotnet test` automatically. Always ask the user to run these manually.

## Build
```bash
dotnet restore src
dotnet build src
dotnet build src --no-restore
dotnet build src --configuration Release
```

## Test
```bash
dotnet test src
dotnet test src --no-build --verbosity normal
dotnet test src --filter "FullyQualifiedName~N2.Core.Identity.UnitTests.N2UserManagerTests"
dotnet test src --filter "FullyQualifiedName=N2.Core.Identity.UnitTests.N2UserManagerTests.TestUserCreateAsync"
```

## NuGet Package
```bash
dotnet build src --configuration Release   # GeneratePackageOnBuild=True in csproj
```

## Git (Windows/bash)
```bash
git status
git log --oneline -10
git diff
git add <file>
git commit -m "message"
```

## File navigation (bash on Windows)
```bash
ls /c/git/n2-core-identity/
find /c/git/n2-core-identity/src -name "*.cs"
```
