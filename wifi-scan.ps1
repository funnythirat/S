param(
    [string]$OutputPath = (Join-Path ([Environment]::GetFolderPath("Desktop")) "wifi-scan.json")
)

$ErrorActionPreference = "Stop"

$nativeWifiSource = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class NativeWifiScanner
{
    [StructLayout(LayoutKind.Sequential)]
    private struct WLAN_INTERFACE_INFO
    {
        public Guid InterfaceGuid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string Description;
        public UInt32 State;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DOT11_SSID
    {
        public UInt32 Length;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] Bytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WLAN_ASSOCIATION_ATTRIBUTES
    {
        public UInt32 BssType;
        public DOT11_SSID Ssid;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] Bssid;
        public UInt32 PhyType;
        public UInt32 PhyIndex;
        public UInt32 SignalQuality;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WLAN_SECURITY_ATTRIBUTES
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool SecurityEnabled;
        [MarshalAs(UnmanagedType.Bool)]
        public bool OneXEnabled;
        public UInt32 Authentication;
        public UInt32 Cipher;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WLAN_CONNECTION_ATTRIBUTES
    {
        public UInt32 State;
        public UInt32 ConnectionMode;
        public WLAN_ASSOCIATION_ATTRIBUTES Association;
        public WLAN_SECURITY_ATTRIBUTES Security;
    }

    [DllImport("wlanapi.dll")]
    private static extern UInt32 WlanOpenHandle(
        UInt32 clientVersion, IntPtr reserved, out UInt32 negotiatedVersion, out IntPtr clientHandle);

    [DllImport("wlanapi.dll")]
    private static extern UInt32 WlanEnumInterfaces(
        IntPtr clientHandle, IntPtr reserved, out IntPtr interfaceList);

    [DllImport("wlanapi.dll")]
    private static extern UInt32 WlanQueryInterface(
        IntPtr clientHandle, ref Guid interfaceGuid, UInt32 opcode, IntPtr reserved,
        out UInt32 dataSize, out IntPtr data, out UInt32 opcodeValueType);

    [DllImport("wlanapi.dll")]
    private static extern void WlanFreeMemory(IntPtr memory);

    [DllImport("wlanapi.dll")]
    private static extern UInt32 WlanCloseHandle(IntPtr clientHandle, IntPtr reserved);

    public static object ReadConnectedNetwork()
    {
        IntPtr client = IntPtr.Zero;
        IntPtr list = IntPtr.Zero;
        try
        {
            UInt32 negotiatedVersion;
            UInt32 result = WlanOpenHandle(2, IntPtr.Zero, out negotiatedVersion, out client);
            if (result != 0) throw new InvalidOperationException("WlanOpenHandle failed: " + result);

            result = WlanEnumInterfaces(client, IntPtr.Zero, out list);
            if (result != 0) throw new InvalidOperationException("WlanEnumInterfaces failed: " + result);

            UInt32 count = (UInt32)Marshal.ReadInt32(list);
            int itemOffset = 8;
            int itemSize = Marshal.SizeOf(typeof(WLAN_INTERFACE_INFO));
            for (UInt32 index = 0; index < count; index++)
            {
                IntPtr itemPointer = IntPtr.Add(list, itemOffset + checked((int)index * itemSize));
                WLAN_INTERFACE_INFO item = (WLAN_INTERFACE_INFO)Marshal.PtrToStructure(
                    itemPointer, typeof(WLAN_INTERFACE_INFO));
                if (item.State != 1) continue;

                IntPtr data = IntPtr.Zero;
                try
                {
                    UInt32 dataSize;
                    UInt32 valueType;
                    result = WlanQueryInterface(
                        client, ref item.InterfaceGuid, 7, IntPtr.Zero,
                        out dataSize, out data, out valueType);
                    if (result != 0)
                        throw new InvalidOperationException("WlanQueryInterface failed: " + result);

                    WLAN_CONNECTION_ATTRIBUTES connection =
                        (WLAN_CONNECTION_ATTRIBUTES)Marshal.PtrToStructure(
                            data, typeof(WLAN_CONNECTION_ATTRIBUTES));
                    byte[] ssidBytes = new byte[connection.Association.Ssid.Length];
                    Array.Copy(connection.Association.Ssid.Bytes, ssidBytes, ssidBytes.Length);
                    return new
                    {
                        schemaVersion = 1,
                        capturedAtUtc = DateTime.UtcNow.ToString("o"),
                        interfaceName = item.Description,
                        ssid = Encoding.UTF8.GetString(ssidBytes),
                        signalQualityPercent = connection.Association.SignalQuality,
                        authentication = AuthenticationName(connection.Security.Authentication),
                        cipher = CipherName(connection.Security.Cipher),
                        securityEnabled = connection.Security.SecurityEnabled,
                        enterpriseAuthentication = connection.Security.OneXEnabled
                    };
                }
                finally
                {
                    if (data != IntPtr.Zero) WlanFreeMemory(data);
                }
            }

            throw new InvalidOperationException("No connected Wi-Fi network was found.");
        }
        finally
        {
            if (list != IntPtr.Zero) WlanFreeMemory(list);
            if (client != IntPtr.Zero) WlanCloseHandle(client, IntPtr.Zero);
        }
    }

    private static string AuthenticationName(UInt32 value)
    {
        switch (value)
        {
            case 1: return "OPEN";
            case 2: return "SHARED";
            case 3: return "WPA";
            case 4: return "WPA-PSK";
            case 5: return "WPA-NONE";
            case 6: return "WPA2";
            case 7: return "WPA2-PSK";
            case 8: return "WPA3";
            case 9: return "WPA3-ENT-192";
            case 10: return "WPA3-SAE";
            case 11: return "WPA3-ENT";
            default: return "UNKNOWN-" + value;
        }
    }

    private static string CipherName(UInt32 value)
    {
        switch (value)
        {
            case 0: return "NONE";
            case 1: return "WEP40";
            case 2: return "TKIP";
            case 4: return "AES-CCMP";
            case 5: return "WEP104";
            case 6: return "BIP";
            case 8: return "GCMP";
            case 9: return "GCMP-256";
            case 10: return "CCMP-256";
            case 11: return "BIP-GMAC-128";
            case 12: return "BIP-GMAC-256";
            case 13: return "BIP-CMAC-256";
            default: return "UNKNOWN-" + value;
        }
    }
}
'@

if (-not ("NativeWifiScanner" -as [type])) {
    Add-Type -TypeDefinition $nativeWifiSource
}
$scan = [NativeWifiScanner]::ReadConnectedNetwork()
$json = ConvertTo-Json -InputObject $scan -Depth 4
$resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$outputDirectory = [System.IO.Path]::GetDirectoryName($resolvedOutputPath)
if (-not [System.IO.Directory]::Exists($outputDirectory)) {
    [System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
}
[System.IO.File]::WriteAllText(
    $resolvedOutputPath,
    $json,
    [System.Text.UTF8Encoding]::new($false)
)
Write-Output "Wi-Fi scan report saved to: $resolvedOutputPath"
