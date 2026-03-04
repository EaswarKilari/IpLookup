using System.Net;
using System.Net.Sockets;

namespace IpLookup.Utils;

public static class IpValidator
{
    public record IpValidationResult(
        bool IsValid,
        bool IsPrivate,
        string? IpVersion,
        string? ErrorMessage
    );

    public static IpValidationResult Validate(string? ipAddress)
    {
        if (string.IsNullOrWhiteSpace(ipAddress))
        {
            return new IpValidationResult(false, false, null, "IP address is required");
        }

        if (!IPAddress.TryParse(ipAddress.Trim(), out var ip))
        {
            return new IpValidationResult(false, false, null, "Invalid IP address format");
        }

        var version = ip.AddressFamily == AddressFamily.InterNetwork ? "IPv4" : "IPv6";
        var isPrivate = IsPrivateIp(ip);

        return new IpValidationResult(true, isPrivate, version, null);
    }

    private static bool IsPrivateIp(IPAddress ip)
    {
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            // IPv4 private ranges
            byte[] bytes = ip.GetAddressBytes();

            // 10.0.0.0/8
            if (bytes[0] == 10)
                return true;

            // 172.16.0.0/12
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                return true;

            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168)
                return true;

            // 127.0.0.0/8 (loopback)
            if (bytes[0] == 127)
                return true;

            // 169.254.0.0/16 (link-local)
            if (bytes[0] == 169 && bytes[1] == 254)
                return true;

            // 0.0.0.0/8
            if (bytes[0] == 0)
                return true;

            // 100.64.0.0/10 (Carrier-grade NAT)
            if (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127)
                return true;

            // 192.0.0.0/24 (IETF Protocol Assignments)
            if (bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 0)
                return true;

            // 192.0.2.0/24 (TEST-NET-1)
            if (bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 2)
                return true;

            // 198.51.100.0/24 (TEST-NET-2)
            if (bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100)
                return true;

            // 203.0.113.0/24 (TEST-NET-3)
            if (bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113)
                return true;

            // 224.0.0.0/4 (Multicast)
            if (bytes[0] >= 224 && bytes[0] <= 239)
                return true;

            // 240.0.0.0/4 (Reserved)
            if (bytes[0] >= 240)
                return true;

            // 255.255.255.255 (Broadcast)
            if (bytes[0] == 255 && bytes[1] == 255 && bytes[2] == 255 && bytes[3] == 255)
                return true;
        }
        else
        {
            // IPv6 private/special ranges
            byte[] bytes = ip.GetAddressBytes();

            // ::1 (loopback)
            if (IPAddress.IsLoopback(ip))
                return true;

            // fe80::/10 (link-local)
            if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80)
                return true;

            // fc00::/7 (unique local)
            if ((bytes[0] & 0xfe) == 0xfc)
                return true;

            // :: (unspecified)
            if (ip.Equals(IPAddress.IPv6None))
                return true;

            // ::ffff:0:0/96 (IPv4-mapped)
            if (ip.IsIPv4MappedToIPv6)
            {
                var ipv4 = ip.MapToIPv4();
                return IsPrivateIp(ipv4);
            }
        }

        return false;
    }
}
