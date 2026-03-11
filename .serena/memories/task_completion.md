# What To Do When a Task Is Completed

1. **Never auto-run build or test** — always ask the user to run `dotnet build src` and `dotnet test src` manually.
2. **Verify XML doc comments** are present on any new public methods.
3. **Check naming conventions** (see code_style.md).
4. **For security-sensitive changes** (auth, tokens, MFA, hashing):
   - Ensure constant-time comparison is used where appropriate.
   - Ensure no timing attack vectors introduced.
   - Check that secrets come from configuration, not hardcoded.
5. **Do not commit automatically** — only commit when explicitly asked.
6. **Do not push** unless explicitly instructed.
7. **Multi-targeting**: ensure changes work for both net8.0 and net10.0 targets. Check `<ItemGroup Condition="...">` blocks in the csproj if adding packages.
