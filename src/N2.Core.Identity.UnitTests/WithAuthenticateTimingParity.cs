using Microsoft.Extensions.Logging.Abstractions;

using Moq;

using N2.Core.Commands;
using N2.Core.Identity.Commands;
using N2.Core.Identity.Data;
using N2.Core.Identity.Services;

namespace N2.Core.Identity.UnitTests;

/// <summary>
/// Authenticate must cost the same for an unknown user and for an existing user with a wrong
/// password: FindByName plus one padded Validate. The tests use a mocked user manager so the
/// timing assertions have a deterministic lower bound and no upper bound.
/// </summary>
[TestClass]
public class WithAuthenticateTimingParity {

    private const int FindByNameDelayMs = 100;
    // Validate pads to 500 ms; allow 20 ms for timer resolution.
    private const long ValidatePaddingLowerBoundMs = 480;

    private static Mock<IUserManager<ApplicationUser>> CreateManager(ApplicationUser? found) {
        var manager = new Mock<IUserManager<ApplicationUser>>();
        manager.Setup(m => m.FindByName(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(async (string _, CancellationToken ct) => {
                await Task.Delay(FindByNameDelayMs, ct);
                return (ICommandResponse<ApplicationUser>)new ApplicationUserResponse(found);
            });
        // Stand-in for the real Validate, which pads its failure paths to 500 ms from its own start.
        manager.Setup(m => m.Validate(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(async (ApplicationUser _, string _, CancellationToken ct) => {
                await new TimeoutTimer(500).Wait(ct);
                return (ICommandResponse)new RequestResult(ResponseStatus.NotAccepted, "Not accepted");
            });
        return manager;
    }

    [TestMethod]
    public async Task Authenticate_UnknownUser_ShouldCallValidateWithDummyUserAndPad() {
        // Arrange
        var manager = CreateManager(found: null);
        var service = new N2AuthenticationService(manager.Object, NullLogger<N2AuthenticationService>.Instance);
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // Act
        var result = await service.Authenticate(
            new UserLogin { Username = "nobody", Password = "wrong" }, CancellationToken.None);
        stopwatch.Stop();

        // Assert
        Assert.IsNull(result);
        manager.Verify(m => m.Validate(
            It.Is<ApplicationUser>(u => u.UserName == "nobody" && u.Id == Guid.Empty),
            "wrong",
            It.IsAny<CancellationToken>()), Times.Once);
        Assert.IsGreaterThanOrEqualTo(FindByNameDelayMs + ValidatePaddingLowerBoundMs, stopwatch.ElapsedMilliseconds);
    }

    [TestMethod]
    public async Task Authenticate_WrongPassword_ShouldCostFindByNamePlusValidate() {
        // Arrange
        var manager = CreateManager(found: new ApplicationUser { Id = Guid.NewGuid(), UserName = "someone" });
        var service = new N2AuthenticationService(manager.Object, NullLogger<N2AuthenticationService>.Instance);
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // Act
        var result = await service.Authenticate(
            new UserLogin { Username = "someone", Password = "wrong" }, CancellationToken.None);
        stopwatch.Stop();

        // Assert
        Assert.IsNull(result);
        Assert.IsGreaterThanOrEqualTo(FindByNameDelayMs + ValidatePaddingLowerBoundMs, stopwatch.ElapsedMilliseconds);
    }
}
