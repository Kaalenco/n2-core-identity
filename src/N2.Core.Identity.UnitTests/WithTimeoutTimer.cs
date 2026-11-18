namespace N2.Core.Identity.UnitTests;

[TestClass]
public class WithTimeoutTimer {

    [TestMethod]
    public async Task Wait_WithinBudget_ShouldPadAndReturnTrue() {
        var timer = new TimeoutTimer(30);

        var padded = await timer.Wait(CancellationToken.None);

        Assert.IsTrue(padded);
    }

    [TestMethod]
    public async Task Wait_BudgetAlreadyUsed_ShouldReturnFalse() {
        var timer = new TimeoutTimer(0);

        var padded = await timer.Wait(CancellationToken.None);

        Assert.IsFalse(padded);
    }

    [TestMethod]
    public async Task Wait_CancelledToken_ShouldThrow() {
        var timer = new TimeoutTimer(500);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAsync<OperationCanceledException>(() => timer.Wait(cts.Token));
    }
}
