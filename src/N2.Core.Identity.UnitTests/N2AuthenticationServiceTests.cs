using Microsoft.Extensions.Logging;
using Moq;
using N2.Identity.Data;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public class N2AuthenticationServiceTests
{
    private readonly Mock<IUserManager<ApplicationUser>> userManager = new();
    private readonly Mock<ILogger<N2AuthenticationService>> logger = new();

    [TestMethod]
    public void N2AuthenticationServiceCanInitialize()
    {
        var service = new N2AuthenticationService(
            userManager.Object,
            logger.Object);
        Assert.IsNotNull(service);
    }
}