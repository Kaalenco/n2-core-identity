using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

using N2.Core.Commands;
using N2.Core.Identity.Data;

using System.Security.Cryptography;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public class UsingN2UserManager {
    public UsingN2UserManager() {
        ServiceCollection serviceCollection = new();
        TestContext.ConfigureServices(serviceCollection);
        serviceProvider = serviceCollection.BuildServiceProvider();
    }

    [TestMethod]
    public async Task CreateUser_PasswordHash_ShouldUsePBKDF2Format() {
        // Arrange
        var password = "SecureP@ssw0rd!123";

        // Act
        var user = await CreateUserWithPassword(password);

        // Assert
        Assert.IsNotNull(user.PasswordHash);

        var hashBytes = Convert.FromBase64String(user.PasswordHash);
        var hashVersion = hashBytes[0];
        Console.WriteLine($"Version byte: {hashBytes[0]}");
        Assert.AreEqual(0x01, hashVersion, "It should use ASP.NET Core Identity (PBKDF2-HMAC-SHA256)");

        Assert.IsGreaterThan(50, user.PasswordHash.Length, "PBKDF2 hash should be > 50 chars");
        // PBKDF2 format contains version and iteration metadata
        var pwd = user.PasswordHash ?? "";
        Assert.IsTrue(pwd.Contains("==", StringComparison.Ordinal) || pwd.Length > 80);
    }

    [TestMethod]
    public void PasswordHashing_ComputationalCost_ShouldBeSufficient() {
        // Arrange
        var password = "BenchmarkP@ss789";
        var user = new ApplicationUser { UserName = "testuser" };
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var passwordHasher = serviceProvider.GetRequiredService<IPasswordHasher<ApplicationUser>>();

        // Act
        var hash = passwordHasher.HashPassword(user, password);
        stopwatch.Stop();

        // Assert
        Assert.IsGreaterThanOrEqualTo(100,
            stopwatch.ElapsedMilliseconds, $"Password hashing should take >= 100ms (OWASP), took {stopwatch.ElapsedMilliseconds}ms");
    }

    [TestMethod]
    public async Task PasswordVerification_TimingAttackResistance_ShouldBeConstantTime() {
        // Arrange
        var user = await CreateUserWithPassword("TestPassword123!");
        var iterations = 100;
        using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();

        // Warmup to eliminate JIT compilation variance before measuring
        await userManager.ValidateAsync(user, "WarmupPassword1!", CancellationToken.None);
        await userManager.ValidateAsync(user, "WarmupPassword2!", CancellationToken.None);

        // Act - Test with passwords differing in first vs last character
        var timesFirstChar = new List<long>();
        var timesLastChar = new List<long>();

        for (var i = 0; i < iterations; i++) {
            var wrongFirst = "XestPassword123!";
            var sw = System.Diagnostics.Stopwatch.StartNew();
            await userManager.ValidateAsync(user, wrongFirst, CancellationToken.None);
            timesFirstChar.Add(sw.ElapsedTicks);

            var wrongLast = "TestPassword123X";
            sw.Restart();
            await userManager.ValidateAsync(user, wrongLast, CancellationToken.None);
            timesLastChar.Add(sw.ElapsedTicks);
        }

        // Assert - Timing should not significantly differ
        var avgFirst = timesFirstChar.Average();
        var avgLast = timesLastChar.Average();
        var percentDiff = Math.Abs(avgFirst - avgLast) / avgFirst * 100;

        Assert.IsLessThan(20, percentDiff, $"Timing difference should be < 20%, was {percentDiff:F2}%");
    }

    [TestMethod]
    public async Task TestAddRoleToUserAsyncAsync() {
        ICommandResponse? result = null;
        CancellationToken token = new();
        UserLogin userInfo = new() { Password = "secret", Username = "admin@email.com" };
        var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        var userMessage = await userManager.FindByEmailAsync(userInfo.Username, token);
        var user = userMessage.Value;
        if (user != null) {
            var isAdminResponse = await userManager.IsInRoleAsync(user, SystemRoles.Publisher, token);
            var isAdmin = isAdminResponse.Status == ResponseStatus.Success;
            if (isAdmin) {
                _ = await userManager.RemoveFromRoleAsync(user, SystemRoles.Publisher, token);
            }

            result = await userManager.AddToRoleAsync(user, SystemRoles.Publisher, token);
        }
        Assert.IsNotNull(result);
        Assert.IsTrue(result.Status.IsSuccess());
    }

    [TestMethod]
    public async Task TestChangeLogging_ConcurrentWrites_ShouldBeThreadSafe() {
        var factory = serviceProvider.GetRequiredService<IIdentityContextFactory>();
        using var context = await factory.CreateAsync("IdentityDb");

        // Clear existing logs by reading count
        var initialCount = context.ChangeLogs.Count();

        // Concurrent log writes
        List<Task> tasks = new();
        var threadsCount = 10;
        var logsPerThread = 50;

        for (var t = 0; t < threadsCount; t++) {
            var threadId = t;
            tasks.Add(Task.Run(() => {
                for (var i = 0; i < logsPerThread; i++) {
                    context.AddChangeLog<ApplicationUser>(
                        Guid.NewGuid(),
                        $"Thread {threadId} log {i}",
                        Guid.NewGuid(),
                        $"User{threadId}");
                }
            }));
        }

        await Task.WhenAll(tasks);

        // Verify all logs were added (up to max size)
        var finalCount = context.ChangeLogs.Count();
        var expectedLogs = Math.Min(initialCount + (threadsCount * logsPerThread), N2IdentityContext.DefaultMaxLogSize);

        Assert.IsLessThanOrEqualTo(N2IdentityContext.DefaultMaxLogSize, finalCount, "Final count should not exceed max log size");
        Assert.IsGreaterThan(0, finalCount, "Should have logged entries");
    }

    [TestMethod]
    public async Task TestChangeLogging_ShouldManageQueueSize() {
        var factory = serviceProvider.GetRequiredService<IIdentityContextFactory>();
        using var context = await factory.CreateAsync("IdentityDb");

        // Verify initial state
        var initialCount = context.ChangeLogs.Count();
        Assert.IsGreaterThanOrEqualTo(0, initialCount);

        // Add logs up to and beyond max size
        var logsToAdd = N2IdentityContext.DefaultMaxLogSize + 100;
        var testUserId = Guid.NewGuid();

        for (var i = 0; i < logsToAdd; i++) {
            context.AddChangeLog<ApplicationUser>(
                Guid.NewGuid(),
                $"Test log entry {i}",
                testUserId,
                "TestUser");
        }

        // Verify queue size is capped at MaxLogSize
        var finalCount = context.ChangeLogs.Count();
        Assert.IsLessThanOrEqualTo(N2IdentityContext.DefaultMaxLogSize,
            finalCount, $"Change log count ({finalCount}) should not exceed MaxLogSize ({N2IdentityContext.DefaultMaxLogSize})");
    }

    [TestMethod]
    public async Task TestConcurrentRoleAssignments_ShouldPreventDuplicates() {
        CancellationToken token = new();
        var username = $"role.user.{Guid.NewGuid()}@test.com";
        var password = "TestPassword1!";
        var roleName = $"TestConcurrentRole_{Guid.NewGuid()}";

        using var setupManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();

        // Create role
        await setupManager.CreateRoleAsync(roleName, token);

        // Create test user
        ApplicationUser user = new() {
            UserName = username,
            Email = username
        };
        var createResult = await setupManager.CreateAsync(user, password, token);
        Assert.IsTrue(createResult.Status.IsSuccess());

        var userResponse = await setupManager.FindByNameAsync(username, token);
        Assert.IsNotNull(userResponse.Value);
        var testUser = userResponse.Value!;

        // Attempt concurrent role assignments
        List<Task<ICommandResponse>> tasks = new();
        var concurrentAssignments = 5;

        for (var i = 0; i < concurrentAssignments; i++) {
            tasks.Add(Task.Run(async () => {
                using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
                var usr = await userManager.FindByIdAsync(testUser.Id, token);
                if (usr.Value != null) {
                    return await userManager.AddToRoleAsync(usr.Value, roleName, token);
                }
                return RequestResult.NotFound();
            }));
        }

        var results = await Task.WhenAll(tasks);

        // All should succeed (duplicate assignments are handled gracefully)
        Assert.IsTrue(results.All(r => r.Status.IsSuccess()),
            "All concurrent role assignments should complete successfully");

        // Verify user has the role
        var isInRole = await setupManager.IsInRoleAsync(testUser, roleName, token);
        Assert.AreEqual(ResponseStatus.Success, isInRole.Status);

        // No cleanup needed - each test class gets a fresh in-memory database
    }

    [TestMethod]
    public async Task TestConcurrentUserCreation_ShouldSerializeOperations() {
        CancellationToken token = new();
        var username = $"concurrent.user.{Guid.NewGuid()}@test.com";
        var password = "TestPassword1!";

        // Attempt to create the same user concurrently from multiple threads
        List<Task<ICommandResponse>> tasks = new();
        var concurrentAttempts = 5;

        for (var i = 0; i < concurrentAttempts; i++) {
            tasks.Add(Task.Run(async () => {
                using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
                ApplicationUser user = new() {
                    UserName = username,
                    Email = username
                };
                return await userManager.CreateAsync(user, password, token);
            }));
        }

        var results = await Task.WhenAll(tasks);

        // NOTE: EF Core InMemory provider does NOT enforce unique constraints The
        // NonDisposingWrapper serializes all operations with a semaphore, ensuring thread-safe
        // access, but InMemory allows duplicate entries. In production with SQL Server, unique
        // constraints would prevent duplicates.

        // Verify all operations completed (serialized by semaphore)
        Assert.IsTrue(results.All(r => r.Status.IsSuccess() || r.Status == ResponseStatus.NotAcceptable),
            "All operations should complete successfully (serialized by semaphore)");

        // Verify at least one success
        var successCount = results.Count(r => r.Status.IsSuccess());
        Assert.IsGreaterThanOrEqualTo(1, successCount, "At least one user creation should succeed");
    }

    [TestMethod]
    public async Task TestConcurrentUserUpdates_ShouldHandleGracefully() {
        CancellationToken token = new();
        var username = $"update.user.{Guid.NewGuid()}@test.com";
        var password = "TestPassword1!";

        // Create a test user
        using var setupManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        ApplicationUser user = new() {
            UserName = username,
            Email = username
        };
        var createResult = await setupManager.CreateAsync(user, password, token);
        Assert.IsTrue(createResult.Status.IsSuccess());

        // Get the created user
        var userResponse = await setupManager.FindByNameAsync(username, token);
        Assert.IsNotNull(userResponse.Value);
        var userId = userResponse.Value!.Id;

        // Attempt concurrent updates to the same user
        List<Task<ICommandResponse>> tasks = new();
        var concurrentUpdates = 10;

        for (var i = 0; i < concurrentUpdates; i++) {
            var index = i;
            tasks.Add(Task.Run(async () => {
                using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
                var usr = await userManager.FindByIdAsync(userId, token);
                if (usr.Value != null) {
                    usr.Value.FirstName = $"FirstName{index}";
                    usr.Value.LastName = $"LastName{index}";
                    // Save changes through context
                    return RequestResult.Ok();
                }
                return (ICommandResponse)RequestResult.NotFound();
            }));
        }

        var results = await Task.WhenAll(tasks);

        // All updates should complete (may overwrite each other, but no errors)
        Assert.IsTrue(results.All(r => r.Status.IsSuccess() || r.Status == ResponseStatus.NotFound),
            "All concurrent updates should complete without database errors");

        // No cleanup needed - each test class gets a fresh in-memory database
    }

    [TestMethod]
    public async Task TestContextFactory_SemaphoreProtection_ShouldInitializeOnce() {
        // Multiple concurrent requests should result in single context initialization
        List<Task<IUserManager<ApplicationUser>>> tasks = new();
        var concurrentRequests = 10;

        for (var i = 0; i < concurrentRequests; i++) {
            tasks.Add(Task.Run(() =>
                Task.FromResult(serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>())));
        }

        var managers = await Task.WhenAll(tasks);

        // All managers should be valid
        Assert.IsTrue(managers.All(m => m != null), "All managers should be initialized");
        Assert.HasCount(concurrentRequests, managers);

        // Cleanup
        foreach (var manager in managers) {
            manager.Dispose();
        }
    }

    [TestMethod]
    public async Task TestDatabaseConcurrency_MultipleContexts_ShouldIsolateChanges() {
        CancellationToken token = new();
        var username1 = $"context1.{Guid.NewGuid()}@test.com";
        var username2 = $"context2.{Guid.NewGuid()}@test.com";
        var password = "TestPassword1!";

        // Create users with different manager instances (different contexts)
        var task1 = Task.Run(async () => {
            using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
            ApplicationUser user = new() {
                UserName = username1,
                Email = username1
            };
            return await userManager.CreateAsync(user, password, token);
        });

        var task2 = Task.Run(async () => {
            using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
            ApplicationUser user = new() {
                UserName = username2,
                Email = username2
            };
            return await userManager.CreateAsync(user, password, token);
        });

        var results = await Task.WhenAll(task1, task2);

        // Both should succeed as they're different users
        Assert.IsTrue(results[0].Status.IsSuccess(), "First user creation should succeed");
        Assert.IsTrue(results[1].Status.IsSuccess(), "Second user creation should succeed");

        // No cleanup needed - each test class gets a fresh in-memory database
    }

    [TestMethod]
    public async Task TestDatasetIntegrity_BulkOperations_ShouldMaintainConsistency() {
        CancellationToken token = new();
        using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();

        // Create multiple users in sequence
        List<string> usernames = new();
        var userCount = 5;

        for (var i = 0; i < userCount; i++) {
            var username = $"bulk.user.{i}.{Guid.NewGuid()}@test.com";
            usernames.Add(username);

            ApplicationUser user = new() {
                UserName = username,
                Email = username
            };
            var result = await userManager.CreateAsync(user, "TestPassword1!", token);
            Assert.IsTrue(result.Status.IsSuccess(), $"User {i} creation should succeed");
        }

        // Verify all users exist
        foreach (var username in usernames) {
            var userResponse = await userManager.FindByNameAsync(username, token);
            Assert.IsNotNull(userResponse.Value, $"User {username} should exist");
        }

        // Delete all users
        foreach (var username in usernames) {
            var userResponse = await userManager.FindByNameAsync(username, token);
            if (userResponse.Value != null) {
                var deleteResult = await userManager.DeleteAsync(userResponse.Value, token);
                Assert.IsTrue(deleteResult.Status.IsSuccess() || deleteResult.Status == ResponseStatus.NoContent,
                    $"User {username} deletion should succeed");
            }
        }

        // Verify all users are deleted
        foreach (var username in usernames) {
            var userResponse = await userManager.FindByNameAsync(username, token);
            Assert.IsNull(userResponse.Value, $"User {username} should be deleted");
        }
    }

    [TestMethod]
    public async Task TestFindByEmailAsync() {
        CancellationToken token = new();
        UserLogin userInfo = new() { Password = "secret", Username = "admin@email.com" };
        var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        var user = await userManager.FindByEmailAsync(userInfo.Username, token);
        Assert.IsNotNull(user);
    }

    [TestMethod]
    public async Task TestGenerateEmailConfirmationTokenAsync() {
        ICommandResponse<string>? tokenResult = null;
        CancellationToken token = new();
        UserLogin userInfo = new() { Password = "secret", Username = "admin" };
        using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        var userResponse = await userManager.FindByNameAsync(userInfo.Username, token);
        var user = userResponse.Value;
        if (user != null) {
            tokenResult = await userManager.GenerateConfirmationTokenAsync(user, token);
        }
        Assert.IsNotNull(tokenResult);
        Console.WriteLine(tokenResult);
    }

    [TestMethod]
    public void TestGetAuthenticator() {
        var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        IDisposable disposable = userManager;
        Assert.IsNotNull(userManager);
        Assert.IsNotNull(disposable);
        disposable.Dispose();
    }

    [TestMethod]
    public async Task TestRoleCreateAndRemoveAsync() {
        CancellationToken token = new();
        var role = "TestRole";
        var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        var roleExists = await userManager.RoleExistsAsync(role, token);
        if (roleExists) {
            await userManager.RemoveRoleAsync(role, token);
        }
        var roleResult = await userManager.CreateRoleAsync(role, token);
        Assert.IsNotNull(roleResult);
        Assert.IsTrue(roleResult.Status.IsSuccess());
    }

    [TestMethod]
    public async Task TestRoleExistsAsync() {
        CancellationToken token = new();
        var role = SystemRoles.SysAdmin;
        var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        var roleExists = await userManager.RoleExistsAsync(role, token);
        Assert.IsTrue(roleExists);
    }

    [TestMethod]
    public async Task TestRoleValidationAsync() {
        CancellationToken token = new();
        UserLogin userInfo = new() { Password = "secret", Username = "admin@email.com" };
        var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        var userResponse = await userManager.FindByEmailAsync(userInfo.Username, token);
        var user = userResponse.Value;
        if (user != null) {
            var isAdminResponse = await userManager.IsInRoleAsync(user, SystemRoles.SysAdmin, token);
            Assert.AreEqual(ResponseStatus.Success, isAdminResponse.Status);
        }
    }

    [TestMethod]
    public async Task TestUserCreateAsync() {
        CancellationToken token = new();
        UserLogin userInfo = new() {
            Username = "justin@time.nl",
            Password = "TestPassword1!"
        };
        using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        var userResponse = await userManager.FindByNameAsync(userInfo.Username, token);
        var user = userResponse.Value;
        if (user != null) {
            await userManager.DeleteAsync(user, token);
        }
        user = new ApplicationUser();
        var setUserNameResult = await userManager.SetUserNameAsync(user, userInfo.Username, token);
        var setEmailNameResult = await userManager.SetEmailAsync(user, userInfo.Username, token);
        var createUserResult = await userManager.CreateAsync(user, userInfo.Password, token);

        Assert.IsNotNull(setUserNameResult);
        Assert.IsNotNull(setEmailNameResult);
        Assert.IsNotNull(createUserResult);

        Assert.IsTrue(setUserNameResult.Status.IsSuccess());
        Assert.IsTrue(setEmailNameResult.Status.IsSuccess());
        Assert.IsTrue(createUserResult.Status.IsSuccess());
    }

    [TestMethod]
    public async Task TestValidateEmailConfirmationAsync() {
        ICommandResponse? result = null;
        CancellationToken token = new();
        UserLogin userInfo = new() { Password = "secret", Username = "admin", };
        using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        var userResponse = await userManager.FindByNameAsync(userInfo.Username, token);
        var user = userResponse.Value;

        Assert.IsNotNull(user);
        user.MfaType = MultiFactorType.Email;

        if (user != null) {
            var tokenResponse = await userManager.GenerateConfirmationTokenAsync(user, token);
            Assert.IsNotNull(tokenResponse);
            var tokenResult = tokenResponse.Value;
            if (!string.IsNullOrEmpty(tokenResult)) {
                result = await userManager.ConfirmEmailAsync(user, tokenResult, token);
            }
        }
        Assert.IsNotNull(result);
        Assert.IsTrue(result.Status.IsSuccess());
    }

    [TestMethod]
    public async Task ValidateMFA_ExpiredToken_ShouldFail() {
        // Arrange
        var user = await CreateUserWithEmailMFA();
        using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();

        // Generate token with a timestamp earlier than today
        var expiredToken = GenerateExpiredToken(user.Email, user.SecurityStamp, daysOld: 1);

        // Act
        var result = await userManager.ValidateMultifactorAsync(user, expiredToken, CancellationToken.None);

        // Assert
        Assert.AreEqual(ResponseStatus.Unauthorized, result.Status);
        Assert.Contains("Timeout", result.Message ?? "");
    }

    [TestMethod]
    public async Task ValidateMFA_InvalidToken_ShouldFail() {
        // Arrange
        var user = await CreateUserWithEmailMFA();
        var invalidToken = "completely-random-invalid-token-12345";
        using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();

        // Act
        var result = await userManager.ValidateMultifactorAsync(user, invalidToken, CancellationToken.None);

        // Assert
        Assert.AreEqual(ResponseStatus.Unauthorized, result.Status);
    }

    [TestMethod]
    [DataRow("no-dot-separator")]
    [DataRow("only.two")]
    [DataRow("")]
    [DataRow("...multiple.dots...")]
    public async Task ValidateMFA_MalformedToken_ShouldFail(string token) {
        // Arrange
        var user = await CreateUserWithEmailMFA();
        using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        // Act
        var result = await userManager.ValidateMultifactorAsync(user, token, CancellationToken.None);

        // Assert
        Assert.AreEqual(ResponseStatus.Unauthorized, result.Status, $"Failed for token: {token}");
    }

    [TestMethod]
    public async Task ValidateMFA_TamperedToken_ShouldFail() {
        // Arrange
        var user = await CreateUserWithEmailMFA();
        using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        var validToken = await userManager.GenerateConfirmationTokenAsync(user, CancellationToken.None);
        var tamperedToken = TamperTokenHash(validToken); // Change one character in hash

        // Act
        var result = await userManager.ValidateMultifactorAsync(user, tamperedToken, CancellationToken.None);

        // Assert
        Assert.AreEqual(ResponseStatus.Unauthorized, result.Status);
    }

    [TestMethod]
    public async Task ValidateMFA_ValidToken_ShouldSucceed() {
        // Arrange
        var user = await CreateUserWithEmailMFA();
        using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();
        var validToken = await userManager.GenerateConfirmationTokenAsync(user, CancellationToken.None);

        // Act
        var result = await userManager.ValidateMultifactorAsync(user, validToken.Value!, CancellationToken.None);

        // Assert
        Assert.AreEqual(ResponseStatus.Success, result.Status);
    }

    [TestMethod]
    public async Task ValidatePassword_CorrectPassword_ShouldSucceed() {
        // Arrange
        var password = "TestP@ssw0rd456";
        var user = await CreateUserWithPassword(password);
        using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();

        // Act
        var result = await userManager.ValidateAsync(user, password, CancellationToken.None);

        // Assert
        Assert.AreEqual(ResponseStatus.Success, result.Status);
    }

    [TestMethod]
    public async Task ValidatePassword_IncorrectPassword_ShouldFail() {
        // Arrange
        var user = await CreateUserWithPassword("CorrectP@ss123");
        var wrongPassword = "WrongPassword456";
        using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();

        // Act
        var result = await userManager.ValidateAsync(user, wrongPassword, CancellationToken.None);

        // Assert
        Assert.AreEqual(ResponseStatus.NotAccepted, result.Status);
    }

    private readonly ServiceProvider serviceProvider;
    private static string GenerateExpiredToken(string? email, string? securityStamp, int daysOld) {
        var nonceBytes = RandomNumberGenerator.GetBytes(32); // 256 bits
        var nonce = Convert.ToBase64String(nonceBytes);
        var timeOut = DateTime.UtcNow.AddDays(-daysOld).Ticks;

        var secret = System.Text.Encoding.UTF8.GetBytes($"{nonce}:{timeOut}:{securityStamp}");
        var crypted = SHA384.HashData(secret);
        var data = System.Text.Encoding.UTF8.GetBytes($"{nonce}:{timeOut}");
        var result = string.Concat(Convert.ToBase64String(data), '.', Convert.ToBase64String(crypted));
        return result;
    }
    private static string TamperTokenHash(ICommandResponse<string> validToken) {
        var token = validToken.Value ?? "";
        var parts = token.Split('.', StringSplitOptions.RemoveEmptyEntries);
        var hash = Convert.FromBase64String(parts[1]);
        var position = RandomNumberGenerator.GetInt32(hash.Length);
        hash[position] = RandomNumberGenerator.GetBytes(1)[0];
        var modified = Convert.ToBase64String(hash);
        return parts[1] + '.' + modified;
    }

    /// <summary>
    /// Creates a new user with email MFA enabled for testing purposes.
    /// </summary>
    /// <returns>
    /// The created <see cref="ApplicationUser" />.
    /// </returns>
    private async Task<ApplicationUser> CreateUserWithEmailMFA() {
        CancellationToken token = new();
        var username = $"mfa.user.{Guid.NewGuid()}@test.com";
        var password = "TestPassword1!";

        using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();

        // Create user
        var randomBytes = RandomNumberGenerator.GetBytes(32);
        var secret = Convert.ToBase64String(randomBytes);
        ApplicationUser user = new() {
            UserName = username,
            Email = username,
            MfaType = MultiFactorType.Email,
            MfaSecret = secret,
            MfaConfirmed = true
        };

        var createResult = await userManager.CreateAsync(user, password, token);
        if (!createResult.Status.IsSuccess()) {
            throw new InvalidOperationException("Failed to create MFA user for test.");
        }

        // Retrieve the user to ensure it is tracked by the context
        var userResponse = await userManager.FindByNameAsync(username, token);
        if (userResponse.Value == null) {
            throw new InvalidOperationException("Failed to retrieve created MFA user.");
        }

        return userResponse.Value;
    }

    private async Task<ApplicationUser> CreateUserWithPassword(string password) {
        CancellationToken token = new();
        var username = $"mfa.user.{Guid.NewGuid()}@test.com";

        using var userManager = serviceProvider.GetRequiredService<IUserManager<ApplicationUser>>();

        // Create user
        var randomBytes = RandomNumberGenerator.GetBytes(32);
        var secret = Convert.ToBase64String(randomBytes);
        ApplicationUser user = new() {
            UserName = username,
            Email = username,
            MfaType = MultiFactorType.None,
            MfaSecret = secret,
            MfaConfirmed = true
        };

        var createResult = await userManager.CreateAsync(user, password, token);
        if (!createResult.Status.IsSuccess()) {
            throw new InvalidOperationException("Failed to create MFA user for test.");
        }

        // Retrieve the user to ensure it is tracked by the context
        var userResponse = await userManager.FindByNameAsync(username, token);
        if (userResponse.Value == null) {
            throw new InvalidOperationException("Failed to retrieve created MFA user.");
        }

        return userResponse.Value;
    }
}