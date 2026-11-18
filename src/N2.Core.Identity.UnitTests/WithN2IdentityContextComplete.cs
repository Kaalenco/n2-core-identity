using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

using N2.Core.Commands;
using N2.Core.Identity.Data;

namespace N2.Core.Identity.UnitTests;

[TestClass]
public class WithN2IdentityContextComplete {

    private static DbContextOptions<N2IdentityContext> InMemoryOptions() =>
        new DbContextOptionsBuilder<N2IdentityContext>()
            .UseInMemoryDatabase($"complete_{Guid.NewGuid():N}")
            .Options;

    [TestMethod]
    public async Task Complete_NoChanges_ShouldReturnSuccess() {
        using var context = new N2IdentityContext(InMemoryOptions(), NullLogger<N2IdentityContext>.Instance);

        var (status, _) = await context.Complete(CancellationToken.None);

        Assert.AreEqual(ResponseStatus.Success, status);
    }

    [TestMethod]
    public async Task Complete_ConcurrencyException_ShouldMapToConflict() {
        using var context = new ThrowingIdentityContext(InMemoryOptions(), new DbUpdateConcurrencyException("concurrency"));

        var (status, message) = await context.Complete(CancellationToken.None);

        Assert.AreEqual(ResponseStatus.Conflict, status);
        Assert.AreEqual("concurrency", message);
    }

    [TestMethod]
    public async Task Complete_UpdateException_ShouldMapToServerErrorWithInnerMessage() {
        using var context = new ThrowingIdentityContext(
            InMemoryOptions(),
            new DbUpdateException("outer", new InvalidOperationException("inner")));

        var (status, message) = await context.Complete(CancellationToken.None);

        Assert.AreEqual(ResponseStatus.ServerError, status);
        Assert.AreEqual("inner", message);
    }

    [TestMethod]
    public async Task Complete_Cancelled_ShouldNotBeSwallowed() {
        using var context = new ThrowingIdentityContext(InMemoryOptions(), new OperationCanceledException());

        await Assert.ThrowsAsync<OperationCanceledException>(() => context.Complete(CancellationToken.None));
    }

    private sealed class ThrowingIdentityContext(DbContextOptions<N2IdentityContext> options, Exception exception)
        : N2IdentityContext(options, NullLogger<N2IdentityContext>.Instance) {
        public override Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = default) =>
            Task.FromException<int>(exception);
    }
}
