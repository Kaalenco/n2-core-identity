using Microsoft.Extensions.Logging;

using Moq;

using N2.Core.Identity.Data;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public sealed class N2AuthenticationServiceTests {
    private readonly Mock<IUserManager<ApplicationUser>> userManager = new();
    private readonly Mock<ILogger<N2AuthenticationService>> logger = new();

    [TestMethod]
    public void N2AuthenticationServiceCanInitialize() {
        N2AuthenticationService service = new(
            userManager.Object,
            logger.Object);
        Assert.IsNotNull(service);
    }


}