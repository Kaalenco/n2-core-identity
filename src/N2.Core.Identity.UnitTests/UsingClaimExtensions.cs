using System.Security.Claims;

namespace N2.Core.Identity.UnitTests;

/// <summary>
/// Unit tests for <see cref="ClaimExtensions"/>.
/// </summary>
[TestClass]
public class UsingClaimExtensions {

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Builds an authenticated <see cref="ClaimsPrincipal"/> with the given roles.
    /// </summary>
    private static ClaimsPrincipal BuildAuthenticatedUser(params string[] roles) {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
            new(ClaimTypes.Name, "testuser"),
        };

        foreach (var role in roles) {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        var identity = new ClaimsIdentity(claims, authenticationType: "TestAuth");
        return new ClaimsPrincipal(identity);
    }

    /// <summary>
    /// Builds an unauthenticated <see cref="ClaimsPrincipal"/> (no authentication type set).
    /// </summary>
    private static ClaimsPrincipal BuildUnauthenticatedUser() {
        var identity = new ClaimsIdentity(); // no authenticationType → IsAuthenticated = false
        return new ClaimsPrincipal(identity);
    }

    // -------------------------------------------------------------------------
    // ArraysAreEqual
    // -------------------------------------------------------------------------

    [TestMethod]
    public void ArraysAreEqual_BothNull_ReturnsFalse() {
        byte[]? left = null;
        byte[]? right = null;
        Assert.IsFalse(left!.ArraysAreEqual(right!));
    }

    [TestMethod]
    public void ArraysAreEqual_LeftNull_ReturnsFalse() {
        byte[]? left = null;
        var right = new byte[] { 1, 2, 3 };
        Assert.IsFalse(left!.ArraysAreEqual(right));
    }

    [TestMethod]
    public void ArraysAreEqual_RightNull_ReturnsFalse() {
        var left = new byte[] { 1, 2, 3 };
        Assert.IsFalse(left.ArraysAreEqual(null!));
    }

    [TestMethod]
    public void ArraysAreEqual_IdenticalArrays_ReturnsTrue() {
        var left = new byte[] { 10, 20, 30 };
        var right = new byte[] { 10, 20, 30 };
        Assert.IsTrue(left.ArraysAreEqual(right));
    }

    [TestMethod]
    public void ArraysAreEqual_DifferentValues_ReturnsFalse() {
        var left = new byte[] { 10, 20, 30 };
        var right = new byte[] { 10, 20, 31 };
        Assert.IsFalse(left.ArraysAreEqual(right));
    }

    [TestMethod]
    public void ArraysAreEqual_DifferentLengths_ReturnsFalse() {
        var left = new byte[] { 1, 2, 3 };
        var right = new byte[] { 1, 2 };
        Assert.IsFalse(left.ArraysAreEqual(right));
    }

    [TestMethod]
    public void ArraysAreEqual_EmptyArrays_ReturnsTrue() {
        var left = Array.Empty<byte>();
        var right = Array.Empty<byte>();
        Assert.IsTrue(left.ArraysAreEqual(right));
    }

    // -------------------------------------------------------------------------
    // IsInRole
    // -------------------------------------------------------------------------

    [TestMethod]
    public void IsInRole_NullUser_ReturnsFalse() {
        ClaimsPrincipal? user = null;
        Assert.IsFalse(ClaimExtensions.IsInRole(user!, SystemRoles.Admin));
    }

    [TestMethod]
    public void IsInRole_UserWithRole_ReturnsTrue() {
        var user = BuildAuthenticatedUser(SystemRoles.Admin);
        Assert.IsTrue(ClaimExtensions.IsInRole(user, SystemRoles.Admin));
    }

    [TestMethod]
    public void IsInRole_UserWithoutRole_ReturnsFalse() {
        var user = BuildAuthenticatedUser(SystemRoles.User);
        Assert.IsFalse(ClaimExtensions.IsInRole(user, SystemRoles.Admin));
    }

    // -------------------------------------------------------------------------
    // IsAuthenticated
    // -------------------------------------------------------------------------

    [TestMethod]
    public void IsAuthenticated_NullUser_ReturnsFalse() {
        ClaimsPrincipal? user = null;
        Assert.IsFalse(ClaimExtensions.IsAuthenticated(user));
    }

    [TestMethod]
    public void IsAuthenticated_AuthenticatedUser_ReturnsTrue() {
        var user = BuildAuthenticatedUser();
        Assert.IsTrue(ClaimExtensions.IsAuthenticated(user));
    }

    [TestMethod]
    public void IsAuthenticated_UnauthenticatedUser_ReturnsFalse() {
        var user = BuildUnauthenticatedUser();
        Assert.IsFalse(ClaimExtensions.IsAuthenticated(user));
    }

    // -------------------------------------------------------------------------
    // CanPublish
    // -------------------------------------------------------------------------

    [TestMethod]
    public void CanPublish_NullUser_ReturnsFalse() {
        ClaimsPrincipal? user = null;
        Assert.IsFalse(ClaimExtensions.CanPublish(user));
    }

    [TestMethod]
    public void CanPublish_UnauthenticatedUser_ReturnsFalse() {
        var user = BuildUnauthenticatedUser();
        Assert.IsFalse(ClaimExtensions.CanPublish(user));
    }

    [TestMethod]
    public void CanPublish_PublisherRole_ReturnsTrue() {
        var user = BuildAuthenticatedUser(SystemRoles.Publisher);
        Assert.IsTrue(ClaimExtensions.CanPublish(user));
    }

    [TestMethod]
    public void CanPublish_AdminRole_ReturnsTrue() {
        var user = BuildAuthenticatedUser(SystemRoles.Admin);
        Assert.IsTrue(ClaimExtensions.CanPublish(user));
    }

    [TestMethod]
    public void CanPublish_UserRole_ReturnsFalse() {
        var user = BuildAuthenticatedUser(SystemRoles.User);
        Assert.IsFalse(ClaimExtensions.CanPublish(user));
    }

    // -------------------------------------------------------------------------
    // CanModifyRights
    // -------------------------------------------------------------------------

    [TestMethod]
    public void CanModifyRights_NullUser_ReturnsFalse() {
        ClaimsPrincipal? user = null;
        Assert.IsFalse(ClaimExtensions.CanModifyRights(user));
    }

    [TestMethod]
    public void CanModifyRights_UnauthenticatedUser_ReturnsFalse() {
        var user = BuildUnauthenticatedUser();
        Assert.IsFalse(ClaimExtensions.CanModifyRights(user));
    }

    [TestMethod]
    public void CanModifyRights_AuthManagerRole_ReturnsTrue() {
        var user = BuildAuthenticatedUser(SystemRoles.AuthManager);
        Assert.IsTrue(ClaimExtensions.CanModifyRights(user));
    }

    [TestMethod]
    public void CanModifyRights_AdminRole_ReturnsTrue() {
        var user = BuildAuthenticatedUser(SystemRoles.Admin);
        Assert.IsTrue(ClaimExtensions.CanModifyRights(user));
    }

    [TestMethod]
    public void CanModifyRights_UserRole_ReturnsFalse() {
        var user = BuildAuthenticatedUser(SystemRoles.User);
        Assert.IsFalse(ClaimExtensions.CanModifyRights(user));
    }

    // -------------------------------------------------------------------------
    // CanDesign
    // -------------------------------------------------------------------------

    [TestMethod]
    public void CanDesign_NullUser_ReturnsFalse() {
        ClaimsPrincipal? user = null;
        Assert.IsFalse(ClaimExtensions.CanDesign(user));
    }

    [TestMethod]
    public void CanDesign_UnauthenticatedUser_ReturnsFalse() {
        var user = BuildUnauthenticatedUser();
        Assert.IsFalse(ClaimExtensions.CanDesign(user));
    }

    [TestMethod]
    public void CanDesign_DesignerRole_ReturnsTrue() {
        var user = BuildAuthenticatedUser(SystemRoles.Designer);
        Assert.IsTrue(ClaimExtensions.CanDesign(user));
    }

    [TestMethod]
    public void CanDesign_AdminRole_ReturnsTrue() {
        var user = BuildAuthenticatedUser(SystemRoles.Admin);
        Assert.IsTrue(ClaimExtensions.CanDesign(user));
    }

    [TestMethod]
    public void CanDesign_UserRole_ReturnsFalse() {
        var user = BuildAuthenticatedUser(SystemRoles.User);
        Assert.IsFalse(ClaimExtensions.CanDesign(user));
    }
}