using Microsoft.Extensions.Logging;

using Moq;

using N2.Core.Commands;
using N2.Core.Identity.Commands;
using N2.Core.Identity.Data;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public sealed class UsingN2AuthenticationService {
    private readonly Mock<IUserManager<ApplicationUser>> userManager = new();
    private readonly Mock<ILogger<N2AuthenticationService>> logger = new();

    private N2AuthenticationService CreateService() =>
        new(userManager.Object, logger.Object);

    private static ApplicationUser MakeUser(string userName = "alice", string email = "alice@example.com") => new() {
        Id = Guid.NewGuid(),
        UserName = userName,
        Email = email,
        NormalizedUserName = userName.ToUpperInvariant(),
        EmailConfirmed = true
    };

    private void SetupUserFound(ApplicationUser user) =>
        userManager
            .Setup(m => m.FindByNameAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ApplicationUserResponse(user));

    private void SetupUserNotFound() =>
        userManager
            .Setup(m => m.FindByNameAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ApplicationUserResponse((ApplicationUser?)null));

    private void SetupValidateSuccess() =>
        userManager
            .Setup(m => m.ValidateAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(RequestResult.Ok());

    private void SetupValidateFail(ResponseStatus status = ResponseStatus.NotAccepted) =>
        userManager
            .Setup(m => m.ValidateAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RequestResult(status, "fail"));

    private void SetupCanSignIn(bool canSignIn) =>
        userManager
            .Setup(m => m.CanSignInAsync(It.IsAny<ApplicationUser>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(canSignIn);

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    [TestMethod]
    public void N2AuthenticationServiceCanInitialize() {
        var service = CreateService();
        Assert.IsNotNull(service);
    }

    // -------------------------------------------------------------------------
    // Guard clauses
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task AuthenticateAsync_NullLogin_ShouldThrow() {
        var service = CreateService();

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => service.AuthenticateAsync(null!));
    }

    [TestMethod]
    public async Task AuthenticateAsync_EmptyUsername_ShouldThrow() {
        var service = CreateService();

        await Assert.ThrowsAsync<ArgumentException>(
            () => service.AuthenticateAsync(new UserLogin { Username = "", Password = "secret" }));
    }

    [TestMethod]
    public async Task AuthenticateAsync_EmptyPassword_ShouldThrow() {
        var service = CreateService();

        await Assert.ThrowsAsync<ArgumentException>(
            () => service.AuthenticateAsync(new UserLogin { Username = "alice", Password = "" }));
    }

    // -------------------------------------------------------------------------
    // User-not-found path
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task AuthenticateAsync_UserNotFound_ShouldReturnNull() {
        SetupUserNotFound();
        var service = CreateService();

        var result = await service.AuthenticateAsync(new UserLogin { Username = "ghost", Password = "secret" });

        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task AuthenticateAsync_UserNotFound_ShouldNotCallValidate() {
        SetupUserNotFound();
        var service = CreateService();

        await service.AuthenticateAsync(new UserLogin { Username = "ghost", Password = "secret" });

        userManager.Verify(
            m => m.ValidateAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    // -------------------------------------------------------------------------
    // Validate path
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task AuthenticateAsync_WrongPassword_ShouldReturnNull() {
        SetupUserFound(MakeUser());
        SetupValidateFail(ResponseStatus.NotAccepted);
        var service = CreateService();

        var result = await service.AuthenticateAsync(new UserLogin { Username = "alice", Password = "wrong" });

        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task AuthenticateAsync_LockedAccount_ShouldReturnNull() {
        SetupUserFound(MakeUser());
        SetupValidateFail(ResponseStatus.Locked);
        var service = CreateService();

        var result = await service.AuthenticateAsync(new UserLogin { Username = "alice", Password = "secret" });

        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task AuthenticateAsync_LockedAccount_ShouldNotCheckCanSignIn() {
        SetupUserFound(MakeUser());
        SetupValidateFail(ResponseStatus.Locked);
        var service = CreateService();

        await service.AuthenticateAsync(new UserLogin { Username = "alice", Password = "secret" });

        userManager.Verify(
            m => m.CanSignInAsync(It.IsAny<ApplicationUser>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    // -------------------------------------------------------------------------
    // CanSignIn path
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task AuthenticateAsync_CannotSignIn_ShouldReturnNull() {
        SetupUserFound(MakeUser());
        SetupValidateSuccess();
        SetupCanSignIn(false);
        var service = CreateService();

        var result = await service.AuthenticateAsync(new UserLogin { Username = "alice", Password = "secret" });

        Assert.IsNull(result);
    }

    // -------------------------------------------------------------------------
    // Happy path
    // -------------------------------------------------------------------------

    [TestMethod]
    public async Task AuthenticateAsync_ValidCredentials_ShouldReturnContext() {
        SetupUserFound(MakeUser());
        SetupValidateSuccess();
        SetupCanSignIn(true);

        var service = CreateService();

        var result = await service.AuthenticateAsync(new UserLogin { Username = "alice", Password = "secret" });

        Assert.IsNotNull(result);
    }

    [TestMethod]
    public async Task AuthenticateAsync_ValidCredentials_ShouldBeAuthenticated() {
        SetupUserFound(MakeUser());
        SetupValidateSuccess();
        SetupCanSignIn(true);

        var service = CreateService();

        var result = await service.AuthenticateAsync(new UserLogin { Username = "alice", Password = "secret" });

        Assert.IsTrue(result!.IsAuthenticated);
    }

    [TestMethod]
    public async Task AuthenticateAsync_ValidCredentials_ShouldPopulateUserDetails() {
        var user = MakeUser("alice", "alice@example.com");
        SetupUserFound(user);
        SetupValidateSuccess();
        SetupCanSignIn(true);

        var service = CreateService();

        var result = await service.AuthenticateAsync(new UserLogin { Username = "alice", Password = "secret" });

        Assert.AreEqual(user.Id, result!.PublicId);
        Assert.AreEqual("alice", result.Name);
        Assert.AreEqual("alice@example.com", result.Email);
    }

    [TestMethod]
    public async Task AuthenticateAsync_ValidCredentials_NoTenantMemberships_CurrentRolesIsEmpty() {
        // Roles are now tenant-scoped. The auth service populates them via GetTenantMembershipsAsync
        // on the concrete N2UserManager. A mock IUserManager never satisfies that guard, so the
        // returned context has no tenant memberships and therefore no roles.
        SetupUserFound(MakeUser());
        SetupValidateSuccess();
        SetupCanSignIn(true);
        var service = CreateService();

        var result = await service.AuthenticateAsync(new UserLogin { Username = "alice", Password = "secret" });

        Assert.IsNotNull(result);
        Assert.IsFalse(result!.CurrentRoles().Any());
    }

    [TestMethod]
    public async Task AuthenticateAsync_ValidCredentials_NoTenantContext_IsAdminReturnsFalse() {
        // IsAdmin() is strictly tenant-scoped; it requires SetTenantContext to be called first.
        // Without a tenant context the result is always false regardless of underlying roles.
        SetupUserFound(MakeUser());
        SetupValidateSuccess();
        SetupCanSignIn(true);
        var service = CreateService();

        var result = await service.AuthenticateAsync(new UserLogin { Username = "alice", Password = "secret" });

        Assert.IsFalse(result!.IsAdmin());
    }
}