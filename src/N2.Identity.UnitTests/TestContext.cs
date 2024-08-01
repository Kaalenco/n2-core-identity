using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using N2.Core.Identity;
using N2.Identity.Data;
using N2.Identity.Services;

namespace N2.Identity.UnitTests;

internal static class TestContext { 
    public static void ConfigureServices(ServiceCollection serviceCollection)
    {
        Mock<IIdentityContextFactory> IdentityMockFactory = new Mock<IIdentityContextFactory>();
        Mock<IIdentityContext> IdentityMock = new Mock<IIdentityContext>();
        Mock<IdentityUserRole<Guid>> roleMock = new Mock<IdentityUserRole<Guid>>();

       serviceCollection.AddLogging(configure =>
        {
            configure.SetMinimumLevel(LogLevel.Debug);
            configure.AddConsole();
        });

        serviceCollection.AddScoped<IUserManager<ApplicationUser>>(_ => new N2UserManager(IdentityMockFactory.Object, "TEST"));
        serviceCollection.AddScoped<IAuthenticator, N2AuthenticationService>();
        serviceCollection.AddScoped(_ => IdentityMockFactory.Object);

        var adminGuid = Guid.NewGuid();
        var listUsers = new List<ApplicationUser>
        {
            new ApplicationUser { 
                Id = adminGuid, 
                UserName = "admin", 
                Email = "admin@email.com", 
                NormalizedUserName = "ADMIN",
                NormalizedEmail = "ADMIN@EMAIL.COM",
            PasswordHash = "WAHOc9FHgcRnZpCb01LhD8sFcLF5+MPz+sL2Rq/dYTmMiXyXXNNSxztzbqtBdWYX"},
            new ApplicationUser {
                Id = Guid.NewGuid(),
                UserName = "lockedOut",
                Email = "admin@email.com",
                NormalizedUserName = "LOCKEDOUT",
            PasswordHash = "WAHOc9FHgcRnZpCb01LhD8sFcLF5+MPz+sL2Rq/dYTmMiXyXXNNSxztzbqtBdWYX"}
        };

        IdentityMockFactory.Setup(m => m.CreateAsync(It.IsAny<string>())).ReturnsAsync(IdentityMock.Object);
        IdentityMock.Setup(m => m.ApplicationUser).Returns(listUsers.AsQueryable());
        IdentityMock.Setup(m => m.ApplicationUserFirstOrDefaultAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .Returns<Guid, CancellationToken>((s, _) => Task.FromResult(listUsers.Find(m => m.Id == s)));
        IdentityMock.Setup(m => m.ApplicationUserFirstOrDefaultAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns<string, CancellationToken>((s, _) => Task.FromResult(listUsers.Find(m => m.NormalizedUserName==s)));
        IdentityMock.Setup(m => m.ApplicationUserByEmailAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns<string, CancellationToken>((s, _) => Task.FromResult(listUsers.Find(m => m.NormalizedEmail == s)));
        IdentityMock.Setup(m => m.FindRecordAsync<ApplicationUser>(It.IsAny<Guid>()))
            .Returns<Guid>((g) => Task.FromResult(listUsers.Find(m => m.Id==g)));
        IdentityMock.Setup(m => m.ApplicationRoleAsync("SYSADMIN", It.IsAny<CancellationToken>()))
            .Returns<string, CancellationToken>((_, _) => Task.FromResult((ApplicationRole?)new ApplicationRole { Name= "SysAdmin" }));
        IdentityMock.Setup(m => m.ApplicationRoleAsync("PUBLISHER", It.IsAny<CancellationToken>()))
            .Returns<string, CancellationToken>((_, _) => Task.FromResult((ApplicationRole?)new ApplicationRole { Name = "Publisher" }));
        IdentityMock.Setup(m => m.IdentityUserRoleAsync(adminGuid, It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .Returns<Guid, Guid, CancellationToken>((g, _, _) => Task.FromResult(g==adminGuid ? roleMock.Object : null));


        IdentityMock.Setup(m => m.CanSignInAsync(It.Is<Guid>(g => g==adminGuid))).ReturnsAsync(true);

    }


}