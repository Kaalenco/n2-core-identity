using Microsoft.Extensions.DependencyInjection;

using N2.Core.Identity.Data;
using N2.Core.Identity.Services;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public class UsingN2UserAlerts : N2IdentityTestsBase {

    private N2UserManager GetN2UserManager() =>
        (N2UserManager)ServiceProvider.GetRequiredService<IUserManager<ApplicationUser>>();

    private N2IdentityContext GetRawContext() =>
        ServiceProvider.GetRequiredService<N2IdentityContext>();

    // -----------------------------------------------------------------------
    // CreateUserAlert — persistence
    // -----------------------------------------------------------------------

    [TestMethod]
    public async Task CreateUserAlert_ValidUser_ShouldPersistAlert() {
        var user = await CreateTestUser($"alert_{Guid.NewGuid():N}", "P@ssword1!", MultiFactorType.None);
        var userManager = GetN2UserManager();

        await userManager.CreateUserAlert(user.Id, new UserAlert("Test alert", Priority.Normal), CancellationToken.None);

        var alert = GetRawContext().UserAlert.SingleOrDefault(a => a.ApplicationUserId == user.Id);
        Assert.IsNotNull(alert);
        Assert.AreEqual("Test alert", alert!.Message);
        Assert.AreEqual(Priority.Normal, alert.Priority);
        Assert.IsFalse(alert.Acknowledged);
    }

    [TestMethod]
    public async Task CreateUserAlert_SetsCreatedAtToApproximatelyUtcNow() {
        var user = await CreateTestUser($"alert_{Guid.NewGuid():N}", "P@ssword1!", MultiFactorType.None);
        var userManager = GetN2UserManager();
        var before = DateTime.UtcNow;

        await userManager.CreateUserAlert(user.Id, new UserAlert("Timestamp", Priority.Low), CancellationToken.None);

        var alert = GetRawContext().UserAlert.Single(a => a.ApplicationUserId == user.Id);
        Assert.IsTrue(alert.CreatedAt >= before && alert.CreatedAt <= DateTime.UtcNow,
            $"CreatedAt {alert.CreatedAt:O} should be between {before:O} and now");
    }

    [TestMethod]
    public async Task CreateUserAlert_MultipleAlerts_ShouldPersistAll() {
        var user = await CreateTestUser($"alert_{Guid.NewGuid():N}", "P@ssword1!", MultiFactorType.None);
        var userManager = GetN2UserManager();

        await userManager.CreateUserAlert(user.Id, new UserAlert("First", Priority.Low), CancellationToken.None);
        await userManager.CreateUserAlert(user.Id, new UserAlert("Second", Priority.High), CancellationToken.None);

        var alerts = GetRawContext().UserAlert.Where(a => a.ApplicationUserId == user.Id).ToList();
        Assert.AreEqual(2, alerts.Count);
        Assert.IsTrue(alerts.Any(a => a.Message == "First"));
        Assert.IsTrue(alerts.Any(a => a.Message == "Second"));
    }

    // -----------------------------------------------------------------------
    // Visibility — unacknowledged alerts within 7 days are included
    // -----------------------------------------------------------------------

    [TestMethod]
    public async Task UserFindRecord_UnacknowledgedRecentAlert_ShouldBeIncluded() {
        var user = await CreateTestUser($"alert_{Guid.NewGuid():N}", "P@ssword1!", MultiFactorType.None);
        await GetN2UserManager().CreateUserAlert(user.Id, new UserAlert("Visible", Priority.Normal), CancellationToken.None);

        var ctx = await GetIdentityContext();
        var found = await ctx.UserFindRecord(user.Id, CancellationToken.None);

        Assert.IsNotNull(found);
        Assert.AreEqual(1, found!.ApplicationUserAlert.Count);
        Assert.AreEqual("Visible", found.ApplicationUserAlert.First().Message);
    }


    // -----------------------------------------------------------------------
    // Alerts propagated through authentication
    // -----------------------------------------------------------------------

    [TestMethod]
    public async Task Authenticate_WithPendingAlert_ShouldPopulateAlertsOnUserContext() {
        var userName = $"alert_{Guid.NewGuid():N}";
        var user = await CreateTestUser(userName, "P@ssword1!", MultiFactorType.None);
        await GetN2UserManager().CreateUserAlert(user.Id, new UserAlert("Login notice", Priority.Normal), CancellationToken.None);

        var userContext = await GetAuthenticator().AuthenticateAsync(new UserLogin { Username = userName, Password = "P@ssword1!" });

        Assert.IsNotNull(userContext);
        Assert.AreEqual(1, userContext!.Alerts.Count());
        Assert.AreEqual("Login notice", userContext.Alerts.First().Message);
        Assert.AreEqual(Priority.Normal, userContext.Alerts.First().Priority);
    }

    [TestMethod]
    public async Task Authenticate_WithNoAlerts_ShouldReturnEmptyAlerts() {
        var userName = $"alert_{Guid.NewGuid():N}";
        await CreateTestUser(userName, "P@ssword1!", MultiFactorType.None);

        var userContext = await GetAuthenticator().AuthenticateAsync(new UserLogin { Username = userName, Password = "P@ssword1!" });

        Assert.IsNotNull(userContext);
        Assert.AreEqual(0, userContext!.Alerts.Count());
    }


    // -----------------------------------------------------------------------
    // Runtime alerts via IUserContext.Alert()
    // -----------------------------------------------------------------------

    [TestMethod]
    public async Task Alert_ShouldAddToInMemoryList() {
        var userName = $"alert_{Guid.NewGuid():N}";
        await CreateTestUser(userName, "P@ssword1!", MultiFactorType.None);
        var userContext = await GetAuthenticator().AuthenticateAsync(new UserLogin { Username = userName, Password = "P@ssword1!" });
        Assert.IsNotNull(userContext);

        userContext!.Alert("Runtime alert", Priority.High);

        Assert.AreEqual(1, userContext.Alerts.Count());
        Assert.AreEqual("Runtime alert", userContext.Alerts.First().Message);
        Assert.AreEqual(Priority.High, userContext.Alerts.First().Priority);
    }

    [TestMethod]
    public async Task Alert_ShouldBePersistedToDatabase() {
        var userName = $"alert_{Guid.NewGuid():N}";
        var user = await CreateTestUser(userName, "P@ssword1!", MultiFactorType.None);
        var userContext = await GetAuthenticator().AuthenticateAsync(new UserLogin { Username = userName, Password = "P@ssword1!" });
        Assert.IsNotNull(userContext);

        userContext!.Alert("Persisted alert", Priority.Low);

        // StoreUserAlert uses task.Wait(100ms) — the InMemory store completes well within that window.
        // NOTE: on a real database under load the 100ms timeout may be insufficient and the alert
        // could be silently dropped. See StoreUserAlert in N2AuthenticationService.
        await Task.Delay(200);

        var stored = GetRawContext().UserAlert
            .Where(a => a.ApplicationUserId == user.Id && a.Message == "Persisted alert")
            .SingleOrDefault();
        Assert.IsNotNull(stored, "Alert created via IUserContext.Alert() should be persisted to the database");
        Assert.AreEqual(Priority.Low, stored!.Priority);
    }

    [TestMethod]
    public async Task Alert_ExistingDbAlerts_AndRuntimeAlerts_ShouldBothAppearOnContext() {
        var userName = $"alert_{Guid.NewGuid():N}";
        var user = await CreateTestUser(userName, "P@ssword1!", MultiFactorType.None);
        await GetN2UserManager().CreateUserAlert(user.Id, new UserAlert("DB alert", Priority.Normal), CancellationToken.None);

        var userContext = await GetAuthenticator().AuthenticateAsync(new UserLogin { Username = userName, Password = "P@ssword1!" });
        Assert.IsNotNull(userContext);
        userContext!.Alert("Runtime alert", Priority.High);

        Assert.AreEqual(2, userContext.Alerts.Count());
        Assert.IsTrue(userContext.Alerts.Any(a => a.Message == "DB alert"));
        Assert.IsTrue(userContext.Alerts.Any(a => a.Message == "Runtime alert"));
    }
}
