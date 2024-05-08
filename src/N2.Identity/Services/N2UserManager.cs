using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using N2.Core;
using N2.Core.Identity;
using N2.Identity.Data;
using System.Diagnostics.CodeAnalysis;
using System.Net.Mail;
using System.Security.Cryptography;

namespace N2.Identity.Services;

public class N2UserManager : IUserManager<ApplicationUser>
{
    private readonly IIdentityContextFactory factory;
    private readonly string catalog;
    private bool disposedValue;
    private readonly Semafore lockObject = new Semafore(1);
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
        if (context != null) return context;

        lockObject.Wait();
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
        var ctx = await InitializeContextAsync();
        return await ctx.CanSignInAsync(user.Id);
    }

    public async Task<IRequestResult> DeleteAsync([NotNull] ApplicationUser user, CancellationToken token)
    {
        var ctx = await InitializeContextAsync();
        ctx.ApplicationUser.Remove(user);
        var (code, message) = await ctx.SaveChangesAsync();
        return new RequestResult(code, message);
    }

    public async Task<IRequestResult> ConfirmEmailAsync([NotNull] ApplicationUser user, string confirmationToken, CancellationToken token)
    {
        Contracts.Requires(confirmationToken, nameof(confirmationToken));
        var ctx = await InitializeContextAsync();
        var dbUser = await ctx.ApplicationUser.FirstOrDefaultAsync(m => m.Id==user.Id, token);
        if (dbUser == null)
        {
            return RequestResult.NotFound();
        }
        if(dbUser.UserName != user.UserName || dbUser.Email != user.Email)
        {
            return RequestResult.NotFound();
        }
        user = dbUser;
        var parts = confirmationToken.Split('.');
        if (parts.Length != 2) { 
            return RequestResult.BadRequest();
        }
        var dataPart = Convert.FromBase64String(parts[0]);
        var data = System.Text.Encoding.UTF8.GetString(dataPart).Split(':');
        if (data.Length != 2) return RequestResult.BadRequest();
        if (!long.TryParse(data[1], out var timeOut)) return RequestResult.BadRequest();
        if (data[0] != user.NormalizedEmail) return RequestResult.BadRequest();
        if (DateTime.UtcNow.Ticks > timeOut) return RequestResult.TimeOut();
        var secret = System.Text.Encoding.UTF8.GetBytes($"{user.NormalizedEmail}:{timeOut}:{user.SecurityStamp}");
        var crypted = Convert.ToBase64String(SHA384.HashData(secret));
        if (parts[1] != crypted) return RequestResult.BadRequest();
        dbUser.LockoutEnabled = true;
        dbUser.EmailConfirmed = true;
        var (code, message) = await ctx.SaveChangesAsync();
        return new RequestResult(code, message);
    }

    public async Task<IRequestResult> CreateAsync([NotNull] ApplicationUser user, string password, CancellationToken token) {
        Contracts.Requires(password, nameof(password));
        var ctx = await InitializeContextAsync();
        var dbUser = await FindByNameAsync(user.UserName ?? string.Empty, token);
        if (dbUser!=null)
        {
            return new RequestResult(406, "Already exists");
        }
        Contracts.Requires(user.UserName, "user.UserName");
        Contracts.Requires(user.Email, "user.Email");
        user.NormalizedUserName = user.UserName.ToUpperInvariant();
        user.NormalizedEmail = user.Email.ToUpperInvariant();
        user.EmailConfirmed = false;
        user.SecurityStamp = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
        user.PasswordHash = GetPasswordHash(user.UserName, user.SecurityStamp, password);
        await ctx.ApplicationUser.AddAsync(user, token);
        var (code, message) = await ctx.SaveChangesAsync();
        return new RequestResult(code, message);
    }

    public async Task<ApplicationUser?> FindByIdAsync(Guid userId, CancellationToken token)
    {
        Contracts.NotDefault(userId, nameof(userId));
        var ctx = await InitializeContextAsync();
        return await ctx.ApplicationUser.FirstOrDefaultAsync(u => u.Id == userId, token);
    }

    public async Task<ApplicationUser?> FindByNameAsync(string? userName, CancellationToken token)
    {
        Contracts.Requires(userName, nameof(userName));
        var ctx = await InitializeContextAsync();
        var normalizedName = userName.ToUpperInvariant();
        return await ctx.ApplicationUser.Where(u => u.NormalizedUserName == normalizedName).FirstOrDefaultAsync(token);
    }

    public async Task<string> GenerateEmailConfirmationTokenAsync([NotNull] ApplicationUser user, CancellationToken token){
        if (user.Id == Guid.Empty)
        {
            var dbUser = await FindByNameAsync(user.UserName, token);
            if (dbUser == null)
            {
                throw new InvalidOperationException("Invalid user");
            }
        }
        var timeOut = DateTime.UtcNow.AddDays(5).Ticks;
        var secret = System.Text.Encoding.UTF8.GetBytes($"{user.NormalizedEmail}:{timeOut}:{user.SecurityStamp}");
        var crypted = SHA384.HashData(secret);
        var data = System.Text.Encoding.UTF8.GetBytes($"{user.NormalizedEmail}:{timeOut}");
        return string.Concat( Convert.ToBase64String(data), '.', Convert.ToBase64String(crypted)) ;
    }

    public async Task<IList<string>> GetRolesAsync([NotNull] ApplicationUser user, CancellationToken token) {
        var ctx = await InitializeContextAsync();
        var roles = await ctx.UserRolesAsync(user.Id);
        return roles.ToList();
    }

    public async Task<Guid> GetUserIdAsync(ApplicationUser user, CancellationToken token) {
        Contracts.Requires(user, nameof(user));
        var ctx = await InitializeContextAsync();
        var normalizedName = user.UserName ?? "".ToUpperInvariant();
        var userRecord = await ctx.ApplicationUser.FirstOrDefaultAsync(u => u.NormalizedUserName == normalizedName, token);
        return userRecord?.Id ?? Guid.Empty;
    }

    public async Task<IRequestResult> SetEmailAsync([NotNull] ApplicationUser user, string email, CancellationToken token)
    {
        Contracts.Requires(email, nameof(email));
        var (emailValid, message) = ValidateEmail(email);
        if (!emailValid)
        {
            return new RequestResult(406, message);
        }
        var dbUser = await FindByNameAsync(user.UserName ?? string.Empty, token);
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

    public async Task<IRequestResult> SetUserNameAsync([NotNull] ApplicationUser user, string userName, CancellationToken token) {
        var dbUser = await FindByNameAsync(userName, token);
        if (dbUser!=null && dbUser.Id != user.Id)
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
        var valid = string.Empty;

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

        return (valid.Length==0, valid);
    }

    public async Task<IRequestResult> ValidateAsync(ApplicationUser user, string password, CancellationToken token)
    {
        Contracts.Requires(user, nameof(user));
        Contracts.Requires(password, nameof(password));
        var ctx = await InitializeContextAsync();
        var appUser = await ctx.FindRecordAsync<ApplicationUser>(user.Id);
        if (appUser == null)
        {
            return new RequestResult(404, "Not accepted");
        }
        var passwordHash = GetPasswordHash(appUser.UserName, appUser.SecurityStamp, password);
        if (passwordHash != appUser.PasswordHash)
        {
            return new RequestResult(404, "Not accepted");
        }
        return new RequestResult(200, user.UserName ?? string.Empty);
    }

    private static string GetPasswordHash(string? userName, string? salt, string password)
    {
        var normalizedName = userName?.ToUpperInvariant() ?? "";
        var source = string.Concat(normalizedName, ':', password, ':', salt);
        var secret = System.Text.Encoding.UTF8.GetBytes(source);
        var crypted = SHA384.HashData(secret);
        return Convert.ToBase64String(crypted);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!disposedValue)
        {
            if (disposing)
            {
                context?.Dispose();
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

    public async Task<IRequestResult> CreateRoleAsync(string role, CancellationToken token) 
    { 
        Contracts.Requires(role, nameof(role));
        var ctx = await InitializeContextAsync();
        var normalizedName = role.ToUpperInvariant();
        var roleItem = await ctx.ApplicationRole.FirstOrDefaultAsync(r => r.NormalizedName == normalizedName, token);
        if (roleItem != null)
        {
            return new RequestResult(406, "Already exists");
        }
        roleItem = new ApplicationRole
        {
            Name = role,
            NormalizedName = normalizedName
        };
        await ctx.ApplicationRole.AddAsync(roleItem, token);
        var (code, message) = await ctx.SaveChangesAsync();
        return new RequestResult(code, message);
    }

    public async Task<ApplicationUser?> FindByEmailAsync(string emailAddress, CancellationToken token)
    {
        Contracts.Requires(emailAddress, nameof(emailAddress));
        var ctx = await InitializeContextAsync();
        var normalizedName = emailAddress.ToUpperInvariant();
        return await ctx.ApplicationUser.Where(u => u.NormalizedEmail == normalizedName).FirstOrDefaultAsync(token);
    }

    public async Task<bool> IsInRoleAsync(ApplicationUser user, string role, CancellationToken token) {
        Contracts.Requires(user, nameof(user));
        Contracts.Requires(role, nameof(role));
        var ctx = await InitializeContextAsync();
        var normalizedName = role.ToUpperInvariant();
        var roleId = await ctx.ApplicationRole.Where(r => r.NormalizedName == normalizedName).Select(r => r.Id).FirstOrDefaultAsync(token);
        if (roleId == Guid.Empty)
        {
            return false;
        }
        return await ctx.ApplicationUserRole.AnyAsync(r => r.UserId == user.Id && r.RoleId == roleId, token);
    }
    public async Task<IRequestResult> RemoveRoleAsync(string role, CancellationToken token)
    {
        Contracts.Requires(role, nameof(role));
        var ctx = await InitializeContextAsync();
        var normalizedName = role.ToUpperInvariant();
        var roleItem = await ctx.ApplicationRole.FirstOrDefaultAsync(r => r.NormalizedName == normalizedName, token);
        if (roleItem == null)
        {
            return RequestResult.NotFound();
        }
        ctx.ApplicationRole.Remove(roleItem);
        var (code, message) = await ctx.SaveChangesAsync();
        return new RequestResult(code, message);
    }

    public async Task<bool> RoleExistsAsync(string role, CancellationToken token) {
        Contracts.Requires(role, nameof(role));
        var ctx = await InitializeContextAsync();
        var normalizedName = role.ToUpperInvariant();
        return await ctx.ApplicationRole.AnyAsync(r => r.NormalizedName == normalizedName, token);
    }

    public async Task<IRequestResult> RemoveFromRoleAsync(ApplicationUser user, string role, CancellationToken token) {
        Contracts.Requires(user, nameof(user));
        Contracts.Requires(role, nameof(role));
        var ctx = await InitializeContextAsync();
        var normalizedName = role.ToUpperInvariant();
        var roleId = await ctx.ApplicationRole.Where(r => r.NormalizedName == normalizedName).Select(r => r.Id).FirstOrDefaultAsync(token);
        if (roleId == Guid.Empty)
        {
            return new RequestResult(406, $"Role '{role}' does not exist");
        }
        var isAssigned = await ctx.ApplicationUserRole.FirstOrDefaultAsync(r => r.UserId == user.Id && r.RoleId == roleId, token);
        if (isAssigned == null)
        {
            return RequestResult.Ok();
        }
        ctx.ApplicationUserRole.Remove(isAssigned);
        var (code, message) = await ctx.SaveChangesAsync();
        return new RequestResult(code, message);
    }
    
    public async Task<IRequestResult> AddToRoleAsync(ApplicationUser user, string role, CancellationToken token){
        Contracts.Requires(user, nameof(user));
        Contracts.Requires(role, nameof(role));
        var ctx = await InitializeContextAsync();
        var normalizedName = role.ToUpperInvariant();
        var roleId = await ctx.ApplicationRole.Where(r => r.NormalizedName == normalizedName).Select(r => r.Id).FirstOrDefaultAsync(token);
        if (roleId == Guid.Empty)
        {
            return new RequestResult(406, $"Role '{role}' does not exist");
        }
        var isAssigned = await ctx.ApplicationUserRole.AnyAsync(r => r.UserId == user.Id && r.RoleId == roleId, token);
        if (isAssigned)
        {
            return RequestResult.Ok();
        }
        var userRole = new IdentityUserRole<Guid>
        {
            RoleId = roleId,
            UserId = user.Id
        };
        await ctx.ApplicationUserRole.AddAsync(userRole, token);
        var (code, message) = await ctx.SaveChangesAsync();
        return new RequestResult(code, message);
    }
}