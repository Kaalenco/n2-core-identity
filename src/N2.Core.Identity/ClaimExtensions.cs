using System.Security.Claims;

namespace N2.Core.Identity;

public static class ClaimExtensions {

    /// <summary>
    /// Time-constant comparison of two byte arrays. This is used to prevent timing attacks when
    /// comparing secrets such as password hashes or tokens. Do not use this method for general byte
    /// array comparisons, as it is less efficient than a simple equality check.
    /// </summary>
    /// <param name="lValue">The first byte array to compare.</param>
    /// <param name="rValue">The second byte array to compare.</param>
    /// <returns>True if the byte arrays are equal, false otherwise.</returns>
    public static bool ArraysAreEqual(this byte[] lValue, byte[] rValue) {
        if (lValue == null || rValue == null) {
            return false;
        }

        var len = Math.Max(lValue.Length, rValue.Length);
        var a1 = new byte[len];
        var a2 = new byte[len];
        Array.Copy(lValue, 0, a1, 0, lValue.Length);
        Array.Copy(rValue, 0, a2, 0, rValue.Length);

        var count = len;
        var errcount = 0;
        for (var i = 0; i < len; i++) {
            if (a1[i] != a2[i]) {
                errcount++;
            }
            count--;
        }

        return errcount == 0 && count == 0;
    }

    public static bool IsInRole(this ClaimsPrincipal user, string role) {
        if (user == null) {
            return false;
        }

        return user.IsInRole(role);
    }

    public static bool IsAuthenticated(this ClaimsPrincipal? user) => user?.Identity?.IsAuthenticated ?? false;

    public static bool CanPublish(this ClaimsPrincipal? user) {
        if (user == null) {
            return false;
        }

        if (!user.IsAuthenticated()) {
            return false;
        }

        if (user.IsInRole(SystemRoles.Publisher)) {
            return true;
        }

        if (user.IsInRole(SystemRoles.Admin)) {
            return true;
        }

        return false;
    }

    public static bool CanModifyRights(this ClaimsPrincipal? user) {
        if (user == null) {
            return false;
        }

        if (!user.IsAuthenticated()) {
            return false;
        }

        if (user.IsInRole(SystemRoles.AuthManager)) {
            return true;
        }

        if (user.IsInRole(SystemRoles.Admin)) {
            return true;
        }

        return false;
    }

    public static bool CanDesign(this ClaimsPrincipal? user) {
        if (user == null) {
            return false;
        }

        if (!user.IsAuthenticated()) {
            return false;
        }

        if (user.IsInRole(SystemRoles.Designer)) {
            return true;
        }

        if (user.IsInRole(SystemRoles.Admin)) {
            return true;
        }

        return false;
    }
}