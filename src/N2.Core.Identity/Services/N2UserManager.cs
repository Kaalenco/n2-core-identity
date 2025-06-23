using System.Diagnostics.CodeAnalysis;
using System.Net.Mail;
using System.Security.Cryptography;

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

using N2.Core.Commands;
using N2.Core.Identity.Commands;
using N2.Core.Identity.Data;

namespace N2.Core.Identity.Services;

public class N2UserManager : IUserManager<ApplicationUser>
{
    private readonly IIdentityContextFactory factory;
    private readonly string catalog;
    private bool disposedValue;
    private readonly Semaphore lockObject = new(1, 1);
    private IIdentityContext? context;

    public bool SupportsUserEmail { get; }

    public N2UserManager(
        IIdentityContextFactory identityContextFactory,
        string catalog)
    {
        this.factory = identityContextFactory;
        this.catalog = catalog;
    }

    private async Task<IIdentityContext> InitializeContextAsync()
    {
        if (context != null)
        {
            return context;
        }

        lockObject.WaitOne();
        try
        {
            context = await factory.CreateAsync(catalog);
        }
        finally
        {
            lockObject.Release();
        }
        return context;
    }

    public async Task<bool> CanSignInAsync([NotNull] ApplicationUser user, CancellationToken token)
    {
        IIdentityContext ctx = await InitializeContextAsync();
        return await ctx.CanSignInAsync(user.Id);
    }

    public async Task<ICommandResponse> DeleteAsync([NotNull] ApplicationUser user, CancellationToken token)
    {
        IIdentityContext ctx = await InitializeContextAsync();
        ctx.RemoveApplicationUser(user);
        (ResponseStatus code, string? message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> ConfirmEmailAsync([NotNull] ApplicationUser user, string confirmationToken, CancellationToken token)
    {
        ArgumentException.ThrowIfNullOrEmpty(confirmationToken);
        IIdentityContext ctx = await InitializeContextAsync();
        ApplicationUser? dbUser = await ctx.ApplicationUserAsync(user.Id, token);
        if (dbUser == null)
        {
            return RequestResult.NotFound();
        }
        if (dbUser.UserName != user.UserName || dbUser.Email != user.Email)
        {
            return RequestResult.NotFound();
        }
        user = dbUser;
        string[] parts = confirmationToken.Split('.');
        if (parts.Length != 2)
        {
            return RequestResult.BadRequest();
        }
        byte[] dataPart = Convert.FromBase64String(parts[0]);
        string[] data = System.Text.Encoding.UTF8.GetString(dataPart).Split(':');
        if (data.Length != 2)
        {
            return RequestResult.BadRequest();
        }

        if (!long.TryParse(data[1], out long timeOut))
        {
            return RequestResult.BadRequest();
        }

        if (data[0] != user.NormalizedEmail)
        {
            return RequestResult.BadRequest();
        }

        if (DateTime.UtcNow.Ticks > timeOut)
        {
            return RequestResult.TimeOut();
        }

        byte[] secret = System.Text.Encoding.UTF8.GetBytes($"{user.NormalizedEmail}:{timeOut}:{user.SecurityStamp}");
        string crypted = Convert.ToBase64String(SHA384.HashData(secret));
        if (parts[1] != crypted)
        {
            return RequestResult.BadRequest();
        }

        dbUser.LockoutEnabled = true;
        dbUser.EmailConfirmed = true;
        (ResponseStatus code, string? message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> CreateAsync([NotNull] ApplicationUser user, string password, CancellationToken token)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);

        IIdentityContext ctx = await InitializeContextAsync();
        ApplicationUser? dbUser = await ApplicationUserByNameAsync(user.UserName ?? string.Empty, token);
        if (dbUser != null)
        {
            return new RequestResult(406, "Already exists");
        }

        ArgumentException.ThrowIfNullOrEmpty(user.UserName);
        ArgumentException.ThrowIfNullOrEmpty(user.Email);

        user.NormalizedUserName = user.UserName.ToUpperInvariant();
        user.NormalizedEmail = user.Email.ToUpperInvariant();
        user.EmailConfirmed = false;
        user.SecurityStamp = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
        user.PasswordHash = GetPasswordHash(user.UserName, user.SecurityStamp, password);
        await ctx.AddApplicationUserAsync(user, token);
        (ResponseStatus code, string? message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    private async Task<ApplicationUser?> ApplicationUserByIdAsync(Guid userId, CancellationToken token)
    {
        ArgumentOutOfRangeException.ThrowIfEqual(userId, Guid.Empty);
        IIdentityContext ctx = await InitializeContextAsync();
        return await ctx.ApplicationUserAsync(userId, token);
    }

    public async Task<ICommandResponse<ApplicationUser>> FindByIdAsync(Guid userId, CancellationToken token)
    {
        ApplicationUser? user = await ApplicationUserByIdAsync(userId, token);
        return new ApplicationUserResponse(user);
    }

    private async Task<ApplicationUser?> ApplicationUserByNameAsync(string? userName, CancellationToken token)
    {
        ArgumentException.ThrowIfNullOrEmpty(userName);
        IIdentityContext ctx = await InitializeContextAsync();
        string normalizedName = userName.ToUpperInvariant();
        return await ctx.ApplicationUserAsync(normalizedName, token);
    }

    public async Task<ICommandResponse<ApplicationUser>> FindByNameAsync(string? userName, CancellationToken token)
    {
        ApplicationUser? user = await ApplicationUserByNameAsync(userName, token);
        return new ApplicationUserResponse(user);
    }

    public async Task<ICommandResponse<string>> GenerateEmailConfirmationTokenAsync([NotNull] ApplicationUser user, CancellationToken token)
    {
        if (user.Id == Guid.Empty)
        {
            ApplicationUser? dbUser = await ApplicationUserByNameAsync(user.UserName, token);
            if (dbUser == null)
            {
                throw new InvalidOperationException("Invalid user");
            }
        }
        long timeOut = DateTime.UtcNow.AddDays(5).Ticks;
        byte[] secret = System.Text.Encoding.UTF8.GetBytes($"{user.NormalizedEmail}:{timeOut}:{user.SecurityStamp}");
        byte[] crypted = SHA384.HashData(secret);
        byte[] data = System.Text.Encoding.UTF8.GetBytes($"{user.NormalizedEmail}:{timeOut}");
        string result = string.Concat(Convert.ToBase64String(data), '.', Convert.ToBase64String(crypted));
        return StringResponse.Accept(result);
    }

    public async Task<IListResponse<string>> GetRolesAsync([NotNull] ApplicationUser user, CancellationToken token)
    {
        IIdentityContext ctx = await InitializeContextAsync();
        IEnumerable<string> roles = await ctx.UserRolesAsync(user.Id);
        ListResponse<string> response = new(roles);
        return response;
    }

    public async Task<ICommandResponse<Guid>> GetUserIdAsync(ApplicationUser user, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(user);
        IIdentityContext ctx = await InitializeContextAsync();
        string normalizedName = user.UserName ?? "".ToUpperInvariant();
        ApplicationUser? userRecord = await ctx.ApplicationUser.FirstOrDefaultAsync(u => u.NormalizedUserName == normalizedName, token);
        Guid result = userRecord?.Id ?? Guid.Empty;
        return GuidResponse.Accept(result);
    }

    public async Task<ICommandResponse> SetEmailAsync([NotNull] ApplicationUser user, string email, CancellationToken token)
    {
        ArgumentException.ThrowIfNullOrEmpty(email);
        (bool emailValid, string message) = ValidateEmail(email);
        if (!emailValid)
        {
            return new RequestResult(406, message);
        }
        ApplicationUser? dbUser = await ApplicationUserByNameAsync(user.UserName ?? string.Empty, token);
        if (dbUser != null && dbUser.Id != user.Id)
        {
            return new RequestResult(406, "Already occupied");
        }
        user.Email = email;
        user.NormalizedEmail = email.ToUpperInvariant();
        user.EmailConfirmed = false;
        user.SecurityStamp = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
        return RequestResult.Ok();
    }

    public async Task<ICommandResponse> SetUserNameAsync([NotNull] ApplicationUser user, string userName, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(userName);
        ApplicationUser? dbUser = await ApplicationUserByNameAsync(userName, token);
        if (dbUser != null && dbUser.Id != user.Id)
        {
            return new RequestResult(406, "Already occupied");
        }
        user.UserName = userName;
        user.NormalizedUserName = userName.ToUpperInvariant();
        user.SecurityStamp = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
        return RequestResult.Ok();
    }

    private static (bool valid, string message) ValidateEmail(string email)
    {
        string valid = string.Empty;

        try
        {
            _ = new MailAddress(email);
        }
        catch (FormatException)
        {
            valid = "Invalid email format";
        }
        catch (ArgumentNullException)
        {
            valid = "Value is null or empty";
        }
        catch (ArgumentException e)
        {
            valid = e.Message;
        }

        return (valid.Length == 0, valid);
    }

    public async Task<ICommandResponse> ValidateAsync(ApplicationUser user, string password, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrEmpty(password);
        IIdentityContext ctx = await InitializeContextAsync();
        ApplicationUser? appUser = await ctx.FindRecordAsync<ApplicationUser>(user.Id);
        if (appUser == null)
        {
            return new RequestResult(404, "Not accepted");
        }
        string passwordHash = GetPasswordHash(appUser.UserName, appUser.SecurityStamp, password);
        if (passwordHash != appUser.PasswordHash)
        {
            return new RequestResult(404, "Not accepted");
        }
        return new RequestResult(200, user.UserName ?? string.Empty);
    }

    private static string GetPasswordHash(string? userName, string? salt, string password)
    {
        string normalizedName = userName?.ToUpperInvariant() ?? "";
        string source = string.Concat(normalizedName, ':', password, ':', salt);
        byte[] secret = System.Text.Encoding.UTF8.GetBytes(source);
        byte[] crypted = SHA384.HashData(secret);
        return Convert.ToBase64String(crypted);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!disposedValue)
        {
            if (disposing)
            {
                context?.Dispose();
                lockObject?.Dispose();
            }
            disposedValue = true;
        }
    }

    public void Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    public async Task<ICommandResponse> CreateRoleAsync(string role, CancellationToken token)
    {
        ArgumentException.ThrowIfNullOrEmpty(role);
        IIdentityContext ctx = await InitializeContextAsync();
        string normalizedName = role.ToUpperInvariant();
        ApplicationRole? roleItem = await ctx.ApplicationRoleAsync(normalizedName, token);
        if (roleItem != null)
        {
            return new RequestResult(406, "Already exists");
        }
        roleItem = new ApplicationRole
        {
            Name = role,
            NormalizedName = normalizedName
        };
        await ctx.AddApplicationRoleAsync(roleItem, token);
        (ResponseStatus code, string? message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse<ApplicationUser>> FindByEmailAsync(string emailAddress, CancellationToken token)
    {
        ApplicationUser? result = await ApplicationUserByEmailAsync(emailAddress, token);
        return new ApplicationUserResponse(result);
    }

    private async Task<ApplicationUser?> ApplicationUserByEmailAsync(string emailAddress, CancellationToken token)
    {
        ArgumentException.ThrowIfNullOrEmpty(emailAddress);
        using IIdentityContext ctx = await InitializeContextAsync();
        string normalizedName = emailAddress.ToUpperInvariant();
        return await ctx.ApplicationUserByEmailAsync(normalizedName, token);
    }

    public async Task<ICommandResponse> IsInRoleAsync(ApplicationUser user, string role, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrEmpty(role);
        using IIdentityContext ctx = await InitializeContextAsync();
        string normalizedName = role.ToUpperInvariant();
        ApplicationRole? roleItem = await ctx.ApplicationRoleAsync(normalizedName, token);
        if (roleItem == null)
        {
            return new GuidResponse(Guid.Empty, (int)ResponseStatus.NotFound, $"Role not found: {role}");
        }
        IdentityUserRole<Guid>? isAssigned = await ctx.IdentityUserRoleAsync(user.Id, roleItem.Id, token);
        if (isAssigned != null)
        {
            return new GuidResponse(roleItem.Id, (int)ResponseStatus.Success, role);
        }
        else
        {
            return new GuidResponse(roleItem.Id, (int)ResponseStatus.NotAccepted, role);
        }
    }

    public async Task<ICommandResponse> RemoveRoleAsync(string role, CancellationToken token)
    {
        ArgumentException.ThrowIfNullOrEmpty(role);
        using IIdentityContext ctx = await InitializeContextAsync();
        string normalizedName = role.ToUpperInvariant();
        ApplicationRole? roleItem = await ctx.ApplicationRole.FirstOrDefaultAsync(r => r.NormalizedName == normalizedName, token);
        if (roleItem == null)
        {
            return RequestResult.NotFound();
        }
        ctx.RemoveApplicationRole(roleItem);
        (ResponseStatus code, string? message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<bool> RoleExistsAsync(string role, CancellationToken token)
    {
        ArgumentException.ThrowIfNullOrEmpty(role);
        using IIdentityContext ctx = await InitializeContextAsync();
        string normalizedName = role.ToUpperInvariant();
        ApplicationRole? roleId = await ctx.ApplicationRoleAsync(normalizedName, token);
        return roleId != null;
    }

    public async Task<ICommandResponse> RemoveFromRoleAsync(ApplicationUser user, string role, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrEmpty(role);
        IIdentityContext ctx = await InitializeContextAsync();
        string normalizedName = role.ToUpperInvariant();
        ApplicationRole? roleItem = await ctx.ApplicationRoleAsync(normalizedName, token);
        if (roleItem == null)
        {
            return new RequestResult(406, $"Role '{role}' does not exist");
        }
        IdentityUserRole<Guid>? isAssigned = await ctx.IdentityUserRoleAsync(user.Id, roleItem.Id, token);
        if (isAssigned == null)
        {
            return RequestResult.Ok();
        }
        ctx.RemoveApplicationUserRole(isAssigned);
        (ResponseStatus code, string? message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }

    public async Task<ICommandResponse> AddToRoleAsync(ApplicationUser user, string role, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrEmpty(role);
        IIdentityContext ctx = await InitializeContextAsync();
        string normalizedName = role.ToUpperInvariant();
        ApplicationRole? roleItem = await ctx.ApplicationRoleAsync(normalizedName, token);
        if (roleItem == null)
        {
            return new RequestResult(406, $"Role '{role}' does not exist");
        }
        IdentityUserRole<Guid>? isAssigned = await ctx.IdentityUserRoleAsync(user.Id, roleItem.Id, token);
        if (isAssigned != null)
        {
            return RequestResult.Ok();
        }
        IdentityUserRole<Guid> userRole = new()
        {
            RoleId = roleItem.Id,
            UserId = user.Id
        };
        await ctx.AddIdentityUserRoleAsync(userRole, token);
        (ResponseStatus code, string? message) = await ctx.Complete();
        return new RequestResult(code, message ?? string.Empty);
    }
}