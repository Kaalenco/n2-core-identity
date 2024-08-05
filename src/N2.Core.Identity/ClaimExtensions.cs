using System.Security.Claims;

namespace N2.Core.Identity;

public static class ClaimExtensions
{
    public static bool IsInRole(this ClaimsPrincipal user, string role)
    {
        if (user == null)
        {
            return false;
        }

        return user.IsInRole(role);
    }

    public static bool IsAuthenticated(this ClaimsPrincipal? user) => user?.Identity?.IsAuthenticated ?? false;

    public static bool CanPublish(this ClaimsPrincipal? user)
    {
        if (user == null)
        {
            return false;
        }

        if (!user.IsAuthenticated())
        {
            return false;
        }

        if (user.IsInRole(SystemRoles.Publisher))
        {
            return true;
        }

        if (user.IsInRole(SystemRoles.Admin))
        {
            return true;
        }

        return false;
    }

    public static bool CanModifyRights(this ClaimsPrincipal? user)
    {
        if (user == null)
        {
            return false;
        }

        if (!user.IsAuthenticated())
        {
            return false;
        }

        if (user.IsInRole(SystemRoles.AuthManager))
        {
            return true;
        }

        if (user.IsInRole(SystemRoles.Admin))
        {
            return true;
        }

        return false;
    }

    public static bool CanDesign(this ClaimsPrincipal? user)
    {
        if (user == null)
        {
            return false;
        }

        if (!user.IsAuthenticated())
        {
            return false;
        }

        if (user.IsInRole(SystemRoles.Designer))
        {
            return true;
        }

        if (user.IsInRole(SystemRoles.Admin))
        {
            return true;
        }

        return false;
    }
}