using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using System.Xml.Serialization;
using System.Text.RegularExpressions;
using Microsoft.Win32;

[assembly: AssemblyTitle("CampusFlow")]
[assembly: AssemblyProduct("CampusFlow")]
[assembly: AssemblyVersion("1314.5.2.0")]
[assembly: AssemblyFileVersion("1314.5.2.0")]

public sealed class PortalSettings
{
    public string PortalUrl { get; set; }
    public string SubmitUrl { get; set; }
    public string Method { get; set; }
    public string UsernameField { get; set; }
    public string PasswordField { get; set; }
    public string ExtraFields { get; set; }
    public string ConnectivityUrl { get; set; }
    public string ConnectivityExpected { get; set; }
    public string SuccessKeywords { get; set; }
    public int CheckIntervalSeconds { get; set; }
    public bool DiscoverRedirect { get; set; }
    public bool NightMode { get; set; }
    public bool AutoDetect { get; set; }

    public static PortalSettings ChinaMobileTemplate()
    {
        return new PortalSettings
        {
            PortalUrl = "http://211.143.60.126:8888/showLogin.do?wlanuserip={local_ip}&wlanacname=0042.0317.311.00",
            SubmitUrl = "http://211.143.60.126:8888/login.do",
            Method = "POST",
            UsernameField = "bpssUSERNAME",
            PasswordField = "bpssBUSPWD",
            ExtraFields = "showVerify=false\r\nloginType=1",
            ConnectivityUrl = "http://www.msftconnecttest.com/connecttest.txt",
            ConnectivityExpected = "Microsoft Connect Test",
            SuccessKeywords = "登录成功|您已成功登录",
            CheckIntervalSeconds = 60,
            DiscoverRedirect = true,
            NightMode = true,
            AutoDetect = true
        };
    }
}

static class AppData
{
    internal const string AppName = "CampusFlow";
    internal const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    internal const string RunName = "CampusFlow";
    internal const string MutexName = @"Local\CampusFlow.SingleInstance";
    internal const string StopEventName = @"Local\CampusFlow.Stop";
    internal static readonly string DirectoryPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), AppName);
    internal static readonly string SettingsPath = Path.Combine(DirectoryPath, "settings.xml");
    internal static readonly string CredentialPath = Path.Combine(DirectoryPath, "credentials.dat");
    internal static readonly string LogPath = Path.Combine(DirectoryPath, "campusflow.log");

    internal static PortalSettings LoadSettings()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                string xml = File.ReadAllText(SettingsPath, Encoding.UTF8);
                using (var reader = new StringReader(xml))
                {
                    var settings = (PortalSettings)new XmlSerializer(typeof(PortalSettings)).Deserialize(reader);
                    if (!xml.Contains("<NightMode>")) settings.NightMode = true;
                    if (!xml.Contains("<AutoDetect>")) settings.AutoDetect = true;
                    return settings;
                }
            }
        }
        catch (Exception ex) { Log("读取设置失败：" + ex.Message); }
        return PortalSettings.ChinaMobileTemplate();
    }

    internal static void SaveSettings(PortalSettings settings)
    {
        Directory.CreateDirectory(DirectoryPath);
        using (var stream = File.Create(SettingsPath))
            new XmlSerializer(typeof(PortalSettings)).Serialize(stream, settings);
    }

    internal static void SaveCredential(string username, string password)
    {
        Directory.CreateDirectory(DirectoryPath);
        string plain = Convert.ToBase64String(Encoding.UTF8.GetBytes(username)) + "\n" + Convert.ToBase64String(Encoding.UTF8.GetBytes(password));
        File.WriteAllBytes(CredentialPath, ProtectedData.Protect(Encoding.UTF8.GetBytes(plain), null, DataProtectionScope.CurrentUser));
    }

    internal static string[] LoadCredential()
    {
        try
        {
            if (!File.Exists(CredentialPath)) return null;
            byte[] plain = ProtectedData.Unprotect(File.ReadAllBytes(CredentialPath), null, DataProtectionScope.CurrentUser);
            string[] parts = Encoding.UTF8.GetString(plain).Split('\n');
            if (parts.Length != 2) return null;
            return new[] { Encoding.UTF8.GetString(Convert.FromBase64String(parts[0])), Encoding.UTF8.GetString(Convert.FromBase64String(parts[1])) };
        }
        catch (Exception ex) { Log("读取凭据失败：" + ex.Message); return null; }
    }

    internal static void Log(string message)
    {
        try
        {
            Directory.CreateDirectory(DirectoryPath);
            File.AppendAllText(LogPath, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss  ") + message + Environment.NewLine, Encoding.UTF8);
        }
        catch { }
    }
}

static class PortalClient
{
    static readonly object Gate = new object();

    internal sealed class DetectedForm
    {
        internal string SubmitUrl;
        internal string Method;
        internal string UsernameField;
        internal string PasswordField;
        internal string ExtraFields;
    }

    internal static DetectedForm DetectForm(string portalUrl)
    {
        return DetectForm(portalUrl, new CookieContainer());
    }

    internal static DetectedForm DetectForm(string portalUrl, CookieContainer cookies)
    {
        string expanded = Expand(portalUrl);
        string html = Request(expanded, null, "GET", cookies, PortalSettings.ChinaMobileTemplate());
        string formHtml = html;
        Match formMatch = Regex.Match(html, "<form\\b[^>]*>([\\s\\S]*?)</form>", RegexOptions.IgnoreCase);
        if (formMatch.Success) formHtml = formMatch.Value;

        Match actionMatch = Regex.Match(formHtml, "\\baction\\s*=\\s*([\\\"'])(.*?)\\1", RegexOptions.IgnoreCase);
        string action = actionMatch.Success ? WebUtility.HtmlDecode(actionMatch.Groups[2].Value.Trim()) : "";
        string submit = String.IsNullOrEmpty(action) ? expanded : new Uri(new Uri(expanded), action).AbsoluteUri;
        Match methodMatch = Regex.Match(formHtml, "\\bmethod\\s*=\\s*([\\\"'])(.*?)\\1", RegexOptions.IgnoreCase);
        string method = methodMatch.Success && String.Equals(methodMatch.Groups[2].Value.Trim(), "get", StringComparison.OrdinalIgnoreCase) ? "GET" : "POST";

        var hidden = new Dictionary<string, string>();
        foreach (Match input in Regex.Matches(formHtml, "<input\\b[^>]*>", RegexOptions.IgnoreCase))
        {
            string tag = input.Value;
            string name = HtmlAttribute(tag, "name");
            if (String.IsNullOrEmpty(name)) continue;
            string type = HtmlAttribute(tag, "type");
            string value = HtmlAttribute(tag, "value");
            if (String.Equals(type, "password", StringComparison.OrdinalIgnoreCase)) continue;
            if (String.Equals(type, "hidden", StringComparison.OrdinalIgnoreCase)) hidden[name] = value;
        }

        string usernameField = FindField(formHtml, false);
        string passwordField = FindField(formHtml, true);
        if (String.IsNullOrEmpty(usernameField) || String.IsNullOrEmpty(passwordField)) return null;
        var extras = new List<string>();
        foreach (var pair in hidden) extras.Add(pair.Key + "=" + pair.Value);
        return new DetectedForm { SubmitUrl = submit, Method = method, UsernameField = usernameField, PasswordField = passwordField, ExtraFields = String.Join("\r\n", extras.ToArray()) };
    }

    static string FindField(string html, bool password)
    {
        string fallback = null;
        foreach (Match input in Regex.Matches(html, "<input\\b[^>]*>", RegexOptions.IgnoreCase))
        {
            string tag = input.Value;
            string type = HtmlAttribute(tag, "type");
            string name = HtmlAttribute(tag, "name");
            string id = HtmlAttribute(tag, "id");
            string hint = (name + " " + id).ToLowerInvariant();
            if (password && String.Equals(type, "password", StringComparison.OrdinalIgnoreCase) && !String.IsNullOrEmpty(name)) return name;
            if (!password && !String.Equals(type, "password", StringComparison.OrdinalIgnoreCase) && !String.Equals(type, "hidden", StringComparison.OrdinalIgnoreCase) && !String.IsNullOrEmpty(name) && (hint.Contains("user") || hint.Contains("account") || hint.Contains("login") || hint.Contains("name") || hint.Contains("账号") || hint.Contains("用户名"))) return name;
            if (!password && String.IsNullOrEmpty(fallback) && !String.Equals(type, "password", StringComparison.OrdinalIgnoreCase) && !String.Equals(type, "hidden", StringComparison.OrdinalIgnoreCase) && !String.IsNullOrEmpty(name) && !hint.Contains("captcha") && !hint.Contains("verify") && !hint.Contains("code")) fallback = name;
        }
        return password ? null : fallback;
    }

    static string HtmlAttribute(string tag, string attribute)
    {
        Match match = Regex.Match(tag, "\\b" + Regex.Escape(attribute) + "\\s*=\\s*([\\\"'])(.*?)\\1", RegexOptions.IgnoreCase);
        return match.Success ? WebUtility.HtmlDecode(match.Groups[2].Value) : "";
    }

    internal static string TryLogin(PortalSettings settings)
    {
        if (!Monitor.TryEnter(Gate)) return "已有登录检测正在运行";
        try
        {
            if (!NetworkInterface.GetIsNetworkAvailable()) return "未检测到可用网络";
            if (HasInternet(settings)) return "网络已经可以正常访问";
            string[] credential = AppData.LoadCredential();
            if (credential == null) return "尚未保存账号密码";

            var cookies = new CookieContainer();
            string portalUrl = ResolvePortalUrl(settings);
            Request(portalUrl, null, "GET", cookies, settings);

            if (settings.AutoDetect)
            {
                try
                {
                    DetectedForm detected = DetectForm(portalUrl, cookies);
                    if (detected != null)
                    {
                        settings.SubmitUrl = detected.SubmitUrl;
                        settings.Method = detected.Method;
                        settings.UsernameField = detected.UsernameField;
                        settings.PasswordField = detected.PasswordField;
                        settings.ExtraFields = detected.ExtraFields;
                        AppData.Log("已自动识别登录表单：" + detected.Method + " " + detected.SubmitUrl);
                    }
                }
                catch (Exception detectEx) { AppData.Log("自动识别表单失败，使用已保存配置：" + detectEx.Message); }
            }

            var fields = ParseExtraFields(settings.ExtraFields);
            fields[settings.UsernameField] = credential[0];
            fields[settings.PasswordField] = credential[1];
            string form = BuildForm(fields);
            string response = Request(Expand(settings.SubmitUrl), form, settings.Method, cookies, settings);
            Thread.Sleep(1800);

            bool keywordMatched = false;
            foreach (string keyword in (settings.SuccessKeywords ?? "").Split('|'))
                if (keyword.Trim().Length > 0 && response.Contains(keyword.Trim())) keywordMatched = true;

            if (keywordMatched || HasInternet(settings))
            {
                AppData.Log("认证成功。入口：" + portalUrl);
                return "认证成功";
            }
            AppData.Log("认证请求已提交，但未确认联网。请检查字段、验证码或终端限制。");
            return "已提交，但未确认联网";
        }
        catch (Exception ex)
        {
            AppData.Log("认证失败：" + ex.Message);
            return "认证失败：" + ex.Message;
        }
        finally { Monitor.Exit(Gate); }
    }

    internal static bool HasInternet(PortalSettings settings)
    {
        try
        {
            string content = Request(Expand(settings.ConnectivityUrl), null, "GET", new CookieContainer(), settings);
            return content.Trim().Contains((settings.ConnectivityExpected ?? "").Trim());
        }
        catch { return false; }
    }

    static string ResolvePortalUrl(PortalSettings settings)
    {
        if (settings.DiscoverRedirect)
        {
            try
            {
                var request = MakeRequest(Expand(settings.ConnectivityUrl), new CookieContainer());
                request.AllowAutoRedirect = false;
                using (var response = (HttpWebResponse)request.GetResponse())
                {
                    string location = response.Headers["Location"];
                    if (!String.IsNullOrEmpty(location) && Uri.IsWellFormedUriString(location, UriKind.Absolute)) return location;
                }
            }
            catch { }
        }
        return Expand(settings.PortalUrl);
    }

    static Dictionary<string, string> ParseExtraFields(string text)
    {
        var result = new Dictionary<string, string>();
        foreach (string raw in (text ?? "").Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
        {
            int separator = raw.IndexOf('=');
            if (separator > 0) result[raw.Substring(0, separator).Trim()] = Expand(raw.Substring(separator + 1).Trim());
        }
        return result;
    }

    static string BuildForm(Dictionary<string, string> fields)
    {
        var parts = new List<string>();
        foreach (var field in fields)
            parts.Add(Uri.EscapeDataString(field.Key) + "=" + Uri.EscapeDataString(field.Value ?? ""));
        return String.Join("&", parts.ToArray());
    }

    static string Request(string url, string form, string method, CookieContainer cookies, PortalSettings settings)
    {
        if (String.IsNullOrWhiteSpace(url)) throw new InvalidOperationException("请求地址不能为空");
        string normalizedMethod = String.Equals(method, "GET", StringComparison.OrdinalIgnoreCase) ? "GET" : "POST";
        if (normalizedMethod == "GET" && !String.IsNullOrEmpty(form)) url += (url.Contains("?") ? "&" : "?") + form;
        var request = MakeRequest(url, cookies);
        request.Method = normalizedMethod;
        if (normalizedMethod == "POST" && form != null)
        {
            byte[] data = Encoding.UTF8.GetBytes(form);
            request.ContentType = "application/x-www-form-urlencoded; charset=UTF-8";
            request.ContentLength = data.Length;
            using (Stream stream = request.GetRequestStream()) stream.Write(data, 0, data.Length);
        }
        using (var response = (HttpWebResponse)request.GetResponse())
        using (var reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8)) return reader.ReadToEnd();
    }

    static HttpWebRequest MakeRequest(string url, CookieContainer cookies)
    {
        var request = (HttpWebRequest)WebRequest.Create(url);
        request.Timeout = 10000;
        request.ReadWriteTimeout = 10000;
        request.CookieContainer = cookies;
        request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CampusFlow/1.0";
        request.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
        return request;
    }

    static string Expand(string value)
    {
        return (value ?? "").Replace("{local_ip}", GetLocalIPv4());
    }

    static string GetLocalIPv4()
    {
        string fallback = "";
        try
        {
            foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (adapter.OperationalStatus != OperationalStatus.Up || adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (UnicastIPAddressInformation address in adapter.GetIPProperties().UnicastAddresses)
                {
                    if (address.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
                    string ip = address.Address.ToString();
                    if (ip.StartsWith("10.") || ip.StartsWith("192.168.") || IsPrivate172(ip)) return ip;
                    if (!ip.StartsWith("169.254.")) fallback = ip;
                }
            }
        }
        catch { }
        return fallback;
    }

    static bool IsPrivate172(string ip)
    {
        string[] parts = ip.Split('.');
        int second;
        return parts.Length == 4 && parts[0] == "172" && Int32.TryParse(parts[1], out second) && second >= 16 && second <= 31;
    }
}

static class BackgroundHost
{
    static System.Threading.Timer timer;
    static readonly object StateGate = new object();
    static bool connected;
    static bool checkQueued;

    internal static void Run()
    {
        bool created;
        using (var mutex = new Mutex(true, AppData.MutexName, out created))
        {
            if (!created) return;
            bool stopCreated;
            using (var stop = new EventWaitHandle(false, EventResetMode.ManualReset, AppData.StopEventName, out stopCreated))
            {
                stop.Reset();
                NetworkChange.NetworkAvailabilityChanged += delegate { SetConnected(false); QueueCheck(3000); };
                NetworkChange.NetworkAddressChanged += delegate { SetConnected(false); QueueCheck(3000); };
                PortalSettings settings = AppData.LoadSettings();
                int interval = Math.Max(20, Math.Min(3600, settings.CheckIntervalSeconds));
                timer = new System.Threading.Timer(delegate { QueueCheck(0); }, null, 500, interval * 1000);
                AppData.Log("后台服务已启动，未联网时检查间隔 " + interval + " 秒。");
                stop.WaitOne();
                timer.Dispose();
                AppData.Log("后台服务已停止。");
            }
        }
    }

    static void QueueCheck(int delay)
    {
        lock (StateGate)
        {
            // 网络已确认可用时不再轮询，交给网络变化事件在断网后唤醒。
            if (connected) return;
            if (checkQueued) return;
            checkQueued = true;
        }
        ThreadPool.QueueUserWorkItem(delegate
        {
            try
            {
                if (delay > 0) Thread.Sleep(delay);
                PortalSettings settings = AppData.LoadSettings();
                bool online = PortalClient.HasInternet(settings);
                if (online)
                {
                    SetConnected(true);
                }
                else
                {
                    SetConnected(false);
                    PortalClient.TryLogin(settings);
                }
            }
            finally
            {
                lock (StateGate) checkQueued = false;
            }
        });
    }

    static void SetConnected(bool value)
    {
        lock (StateGate)
        {
            connected = value;
            if (timer != null)
            {
                int intervalMs = Math.Max(20, Math.Min(3600, AppData.LoadSettings().CheckIntervalSeconds)) * 1000;
                timer.Change(value ? Timeout.Infinite : intervalMs, value ? Timeout.Infinite : intervalMs);
            }
        }
    }
}

static class StartupManager
{
    internal static bool IsEnabled
    {
        get
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(AppData.RunKey))
                return key != null && key.GetValue(AppData.RunName) != null;
        }
    }

    internal static void Enable()
    {
        RemoveLegacyTask();
        Stop();
        using (RegistryKey key = Registry.CurrentUser.CreateSubKey(AppData.RunKey))
            key.SetValue(AppData.RunName, "\"" + Application.ExecutablePath + "\" --background");
        Process.Start(Application.ExecutablePath, "--background");
    }

    internal static void Disable()
    {
        RemoveLegacyTask();
        using (RegistryKey key = Registry.CurrentUser.OpenSubKey(AppData.RunKey, true))
            if (key != null) key.DeleteValue(AppData.RunName, false);
        Stop();
    }

    internal static void Restart()
    {
        if (!IsEnabled) return;
        Stop();
        Thread.Sleep(500);
        Process.Start(Application.ExecutablePath, "--background");
    }

    static void Stop()
    {
        try { EventWaitHandle.OpenExisting(AppData.StopEventName).Set(); }
        catch { }
    }

    static void RemoveLegacyTask()
    {
        RunHidden("schtasks.exe", "/End /TN CampusAutoLogin");
        RunHidden("schtasks.exe", "/Delete /TN CampusAutoLogin /F");
        using (RegistryKey key = Registry.CurrentUser.OpenSubKey(AppData.RunKey, true))
            if (key != null) key.DeleteValue("CampusAutoLogin", false);
    }

    static void RunHidden(string file, string arguments)
    {
        try
        {
            var info = new ProcessStartInfo(file, arguments) { CreateNoWindow = true, UseShellExecute = false, WindowStyle = ProcessWindowStyle.Hidden };
            using (Process process = Process.Start(info)) process.WaitForExit(4000);
        }
        catch { }
    }
}

static class NativeWindow
{
    [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
    [DllImport("user32.dll")] internal static extern bool ReleaseCapture();
    [DllImport("user32.dll")] internal static extern IntPtr SendMessage(IntPtr hwnd, int message, IntPtr wParam, IntPtr lParam);

    internal static void ApplyBackdrop(IntPtr handle)
    {
        try
        {
            int dark = 1;
            DwmSetWindowAttribute(handle, 20, ref dark, sizeof(int));
            int acrylic = 3;
            DwmSetWindowAttribute(handle, 38, ref acrylic, sizeof(int));
            int corners = 2;
            DwmSetWindowAttribute(handle, 33, ref corners, sizeof(int));
        }
        catch { }
    }
}

sealed class RoundPanel : Panel
{
    public Color FillColor { get; set; }
    public Color BorderColor { get; set; }

    public RoundPanel()
    {
        FillColor = Color.FromArgb(196, 31, 40, 52);
        BorderColor = Color.FromArgb(70, 255, 255, 255);
        DoubleBuffered = true;
        BackColor = Color.Transparent;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
        using (GraphicsPath path = Rounded(ClientRectangle, 8))
        using (SolidBrush brush = new SolidBrush(FillColor))
        using (Pen pen = new Pen(BorderColor))
        {
            e.Graphics.FillPath(brush, path);
            e.Graphics.DrawPath(pen, path);
        }
        base.OnPaint(e);
    }

    static GraphicsPath Rounded(Rectangle rectangle, int radius)
    {
        int d = radius * 2;
        var path = new GraphicsPath();
        path.AddArc(rectangle.Left, rectangle.Top, d, d, 180, 90);
        path.AddArc(rectangle.Right - d - 1, rectangle.Top, d, d, 270, 90);
        path.AddArc(rectangle.Right - d - 1, rectangle.Bottom - d - 1, d, d, 0, 90);
        path.AddArc(rectangle.Left, rectangle.Bottom - d - 1, d, d, 90, 90);
        path.CloseFigure();
        return path;
    }
}

sealed class GlassButton : Button
{
    bool hovered;
    bool pressed;

    public GlassButton()
    {
        FlatStyle = FlatStyle.Flat;
        FlatAppearance.BorderSize = 0;
        BackColor = Color.FromArgb(37, 139, 244);
        ForeColor = Color.White;
        Cursor = Cursors.Hand;
        Font = new Font("Microsoft YaHei UI", 9F, FontStyle.Bold);
        Height = 36;
        DoubleBuffered = true;
        UseVisualStyleBackColor = false;
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer, true);
    }

    protected override void OnMouseEnter(EventArgs e) { hovered = true; Invalidate(); base.OnMouseEnter(e); }
    protected override void OnMouseLeave(EventArgs e) { hovered = false; pressed = false; Invalidate(); base.OnMouseLeave(e); }
    protected override void OnMouseDown(MouseEventArgs e) { pressed = true; Invalidate(); base.OnMouseDown(e); }
    protected override void OnMouseUp(MouseEventArgs e) { pressed = false; Invalidate(); base.OnMouseUp(e); }

    protected override void OnPaint(PaintEventArgs e)
    {
        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
        Color surface = Parent == null ? Color.FromArgb(22, 31, 43) : Parent.BackColor;
        RoundPanel parentCard = Parent as RoundPanel;
        if (parentCard != null) surface = parentCard.FillColor;
        if (surface.A < 255) surface = Color.FromArgb(surface.R, surface.G, surface.B);
        e.Graphics.Clear(surface);
        Rectangle bounds = new Rectangle(1, 1, Math.Max(2, Width - 3), Math.Max(2, Height - 3));
        int radius = Math.Min(10, Math.Min(bounds.Width, bounds.Height) / 2);
        Color baseColor = Enabled ? BackColor : Color.FromArgb(80, 88, 101);
        Color top = Blend(baseColor, Color.White, hovered ? 34 : 18);
        Color bottom = pressed ? Blend(baseColor, Color.Black, 18) : Blend(baseColor, Color.Black, 5);

        using (GraphicsPath path = Rounded(bounds, radius))
        using (var fill = new LinearGradientBrush(bounds, top, bottom, LinearGradientMode.Vertical))
        using (var border = new Pen(Color.FromArgb(hovered ? 130 : 72, 255, 255, 255), hovered ? 1.1F : 0.8F))
        {
            e.Graphics.FillPath(fill, path);
            e.Graphics.DrawPath(border, path);
        }

        TextRenderer.DrawText(e.Graphics, Text, Font, ClientRectangle, Enabled ? ForeColor : Color.FromArgb(175, 185, 196),
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
    }

    static Color Blend(Color from, Color to, int amount)
    {
        int inverse = 255 - amount;
        return Color.FromArgb(from.A,
            (from.R * inverse + to.R * amount) / 255,
            (from.G * inverse + to.G * amount) / 255,
            (from.B * inverse + to.B * amount) / 255);
    }

    static GraphicsPath Rounded(Rectangle rectangle, int radius)
    {
        int d = radius * 2;
        var path = new GraphicsPath();
        path.AddArc(rectangle.Left, rectangle.Top, d, d, 180, 90);
        path.AddArc(rectangle.Right - d, rectangle.Top, d, d, 270, 90);
        path.AddArc(rectangle.Right - d, rectangle.Bottom - d, d, d, 0, 90);
        path.AddArc(rectangle.Left, rectangle.Bottom - d, d, d, 90, 90);
        path.CloseFigure();
        return path;
    }
}

sealed class MainForm : Form
{
    readonly Color TextMain = Color.FromArgb(243, 247, 252);
    readonly Color TextMuted = Color.FromArgb(169, 182, 198);
    readonly TextBox username = Input();
    readonly TextBox password = Input();
    readonly TextBox portalUrl = Input();
    readonly TextBox submitUrl = Input();
    readonly ComboBox method = new ComboBox();
    readonly TextBox usernameField = Input();
    readonly TextBox passwordField = Input();
    readonly TextBox extraFields = Input(true);
    readonly TextBox connectivityUrl = Input();
    readonly TextBox connectivityExpected = Input();
    readonly TextBox successKeywords = Input();
    readonly NumericUpDown interval = new NumericUpDown();
    readonly CheckBox discoverRedirect = new CheckBox();
    readonly CheckBox autoDetect = new CheckBox();
    readonly Label status = new Label();
    readonly TabControl tabs = new TabControl();
    readonly List<GlassButton> navigationButtons = new List<GlassButton>();
    readonly RichTextBox log = new RichTextBox();
    GlassButton themeButton;
    bool nightMode = true;

    internal MainForm()
    {
        TrySetIcon();
        Text = "CampusFlow";
        ClientSize = new Size(900, 650);
        MinimumSize = new Size(820, 610);
        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(20, 26, 35);
        Font = new Font("Microsoft YaHei UI", 9F);
        DoubleBuffered = true;
        Padding = new Padding(1);

        BuildHeader();
        BuildTabs();
        LoadValues();
        UpdateStatus();
    }

    void TrySetIcon()
    {
        try
        {
            string iconPath = Path.Combine(Application.StartupPath, "assets", "CampusFlow.ico");
            if (File.Exists(iconPath)) Icon = new Icon(iconPath);
        }
        catch { }
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        NativeWindow.ApplyBackdrop(Handle);
    }

    protected override void OnPaintBackground(PaintEventArgs e)
    {
        Color top = nightMode ? Color.FromArgb(19, 29, 42) : Color.FromArgb(239, 244, 249);
        Color bottom = nightMode ? Color.FromArgb(15, 22, 31) : Color.FromArgb(218, 228, 238);
        using (var gradient = new LinearGradientBrush(ClientRectangle, top, bottom, 32F))
            e.Graphics.FillRectangle(gradient, ClientRectangle);
        using (var pen = new Pen(nightMode ? Color.FromArgb(24, 114, 199, 229) : Color.FromArgb(24, 64, 133, 180), 80F))
        using (var greenPen = new Pen(nightMode ? Color.FromArgb(18, 86, 214, 151) : Color.FromArgb(22, 49, 164, 132), 64F))
        {
            e.Graphics.DrawLine(pen, -100, Height - 50, Width / 2, -80);
            e.Graphics.DrawLine(greenPen, Width / 3, Height + 60, Width + 80, 80);
        }
    }

    void BuildHeader()
    {
        var header = new Panel { Dock = DockStyle.Top, Height = 84, BackColor = Color.Transparent };
        header.MouseDown += DragWindow;
        var brand = new Label { Text = "CampusFlow", ForeColor = TextMain, Font = new Font("Microsoft YaHei UI", 19F, FontStyle.Bold), AutoSize = true, Location = new Point(28, 18) };
        brand.MouseDown += DragWindow;
        var subtitle = new Label { Text = "校园网静默认证", ForeColor = TextMuted, AutoSize = true, Location = new Point(31, 54) };
        subtitle.MouseDown += DragWindow;
        header.Controls.Add(brand);
        header.Controls.Add(subtitle);

        status.AutoSize = false;
        status.TextAlign = ContentAlignment.MiddleCenter;
        status.SetBounds(655, 25, 145, 32);
        status.ForeColor = TextMain;
        status.BackColor = Color.FromArgb(55, 255, 255, 255);
        header.Controls.Add(status);

        var minimize = HeaderButton("−", 812);
        minimize.Click += delegate { WindowState = FormWindowState.Minimized; };
        var close = HeaderButton("×", 854);
        close.Click += delegate { Close(); };
        header.Controls.Add(minimize);
        header.Controls.Add(close);
        themeButton = new GlassButton { Text = "☀ 日间模式", Location = new Point(505, 23), Size = new Size(135, 36), BackColor = Color.FromArgb(48, 61, 78), ForeColor = TextMain };
        themeButton.Click += delegate { ToggleTheme(); };
        header.Controls.Add(themeButton);
        Controls.Add(header);
    }

    Button HeaderButton(string text, int x)
    {
        var button = new Button { Text = text, Location = new Point(x, 18), Size = new Size(34, 34), ForeColor = TextMain, BackColor = Color.Transparent, FlatStyle = FlatStyle.Flat, Cursor = Cursors.Hand, Font = new Font("Segoe UI", 13F) };
        button.FlatAppearance.BorderSize = 0;
        button.FlatAppearance.MouseOverBackColor = Color.FromArgb(45, 255, 255, 255);
        return button;
    }

    void DragWindow(object sender, MouseEventArgs e)
    {
        if (e.Button != MouseButtons.Left) return;
        NativeWindow.ReleaseCapture();
        NativeWindow.SendMessage(Handle, 0xA1, new IntPtr(2), IntPtr.Zero);
    }

    void BuildTabs()
    {
        var workspace = new Panel { Dock = DockStyle.Fill, BackColor = Color.FromArgb(18, 25, 35) };
        var navigation = new Panel { Dock = DockStyle.Top, Height = 58, Padding = new Padding(24, 10, 24, 10), BackColor = Color.FromArgb(22, 31, 43) };

        tabs.Dock = DockStyle.Fill;
        tabs.ItemSize = new Size(0, 1);
        tabs.SizeMode = TabSizeMode.Fixed;
        tabs.Appearance = TabAppearance.FlatButtons;
        tabs.Controls.Add(BuildBasicPage());
        tabs.Controls.Add(BuildAdvancedPage());
        tabs.Controls.Add(BuildLogPage());
        tabs.Controls.Add(BuildAboutPage());

        string[] titles = { "基础设置", "高级设置", "运行日志", "关于" };
        for (int i = 0; i < titles.Length; i++)
        {
            int index = i;
            var button = new GlassButton
            {
                Text = titles[i],
                Location = new Point(24 + i * 142, 10),
                Size = new Size(130, 38),
                BackColor = i == 0 ? Color.FromArgb(42, 139, 236) : Color.FromArgb(48, 61, 78),
                ForeColor = TextMain
            };
            button.Click += delegate { SelectPage(index); };
            navigationButtons.Add(button);
            navigation.Controls.Add(button);
        }

        workspace.Controls.Add(tabs);
        workspace.Controls.Add(navigation);
        Controls.Add(workspace);
        workspace.BringToFront();
    }

    void SelectPage(int index)
    {
        tabs.SelectedIndex = index;
        for (int i = 0; i < navigationButtons.Count; i++)
            navigationButtons[i].BackColor = i == index ? Color.FromArgb(42, 139, 236) : Color.FromArgb(48, 61, 78);
    }

    TabPage BuildBasicPage()
    {
        var page = Page("基础设置");
        var card = Card(28, 25, 825, 445);
        page.Controls.Add(card);
        AddField(card, "校园网账号", username, 28, 28, 360);
        AddField(card, "密码", password, 428, 28, 360);
        password.UseSystemPasswordChar = true;
        AddField(card, "登录页地址", portalUrl, 28, 105, 760);
        AddField(card, "表单提交地址", submitUrl, 28, 182, 760);

        var note = new Label { Text = "地址中可使用 {local_ip}，程序会替换为当前网络的 IPv4 地址。", ForeColor = TextMuted, AutoSize = true, Location = new Point(28, 250) };
        card.Controls.Add(note);

        autoDetect.Text = "自动识别登录表单（推荐，适用于移动/联通/电信）";
        autoDetect.ForeColor = TextMain;
        autoDetect.BackColor = Color.Transparent;
        autoDetect.AutoSize = true;
        autoDetect.Location = new Point(28, 276);
        card.Controls.Add(autoDetect);

        var detect = new GlassButton { Text = "识别表单", Location = new Point(28, 310), Width = 120, BackColor = Color.FromArgb(68, 134, 204) };
        detect.Click += delegate { DetectLoginForm(detect); };
        card.Controls.Add(detect);
        var save = new GlassButton { Text = "保存并启用", Location = new Point(158, 310), Width = 145 };
        save.Click += delegate { SaveAndEnable(); };
        var test = new GlassButton { Text = "测试登录", Location = new Point(315, 310), Width = 125, BackColor = Color.FromArgb(50, 185, 143) };
        test.Click += delegate { TestLogin(test); };
        var disable = new GlassButton { Text = "停止后台", Location = new Point(450, 310), Width = 125, BackColor = Color.FromArgb(73, 84, 102) };
        disable.Click += delegate { StartupManager.Disable(); UpdateStatus(); MessageBox.Show("后台运行和开机启动已停止。", "CampusFlow"); };
        card.Controls.Add(save);
        card.Controls.Add(test);
        card.Controls.Add(disable);

        var stateText = new Label { Text = "程序只在网络变化或定时检查时工作，平时处于等待状态。", ForeColor = TextMuted, AutoSize = true, Location = new Point(28, 382) };
        card.Controls.Add(stateText);
        return page;
    }

    TabPage BuildAdvancedPage()
    {
        var page = Page("高级设置");
        var card = Card(28, 25, 825, 455);
        page.Controls.Add(card);

        method.DropDownStyle = ComboBoxStyle.DropDownList;
        method.Items.AddRange(new object[] { "POST", "GET" });
        StyleCombo(method);
        AddField(card, "提交方式", method, 28, 24, 180);
        AddField(card, "账号字段名", usernameField, 228, 24, 260);
        AddField(card, "密码字段名", passwordField, 508, 24, 280);
        AddField(card, "附加字段（每行 key=value）", extraFields, 28, 101, 360);
        extraFields.Height = 92;
        AddField(card, "联网检测地址", connectivityUrl, 408, 101, 380);
        AddField(card, "检测成功内容", connectivityExpected, 408, 178, 380);
        AddField(card, "登录成功关键字（用 | 分隔）", successKeywords, 28, 232, 500);

        interval.Minimum = 20;
        interval.Maximum = 3600;
        interval.BackColor = Color.FromArgb(31, 41, 54);
        interval.ForeColor = TextMain;
        AddField(card, "检查间隔（秒）", interval, 548, 232, 240);

        discoverRedirect.Text = "自动采用网络重定向给出的登录页";
        discoverRedirect.ForeColor = TextMain;
        discoverRedirect.BackColor = Color.Transparent;
        discoverRedirect.AutoSize = true;
        discoverRedirect.Location = new Point(28, 318);
        card.Controls.Add(discoverRedirect);

        var restore = new GlassButton { Text = "恢复河北移动模板", Location = new Point(28, 365), Width = 175, BackColor = Color.FromArgb(73, 84, 102) };
        restore.Click += delegate { PutSettings(PortalSettings.ChinaMobileTemplate()); };
        var save = new GlassButton { Text = "保存设置", Location = new Point(218, 365), Width = 125 };
        save.Click += delegate { SaveSettingsOnly(); };
        card.Controls.Add(restore);
        card.Controls.Add(save);
        return page;
    }

    TabPage BuildLogPage()
    {
        var page = Page("运行日志");
        var card = Card(28, 25, 825, 455);
        page.Controls.Add(card);
        log.SetBounds(24, 24, 777, 345);
        log.ReadOnly = true;
        log.BorderStyle = BorderStyle.None;
        log.BackColor = Color.FromArgb(23, 31, 42);
        log.ForeColor = Color.FromArgb(199, 211, 226);
        log.Font = new Font("Consolas", 9F);
        card.Controls.Add(log);
        var refresh = new GlassButton { Text = "刷新", Location = new Point(24, 392), Width = 100 };
        refresh.Click += delegate { LoadLog(); };
        var folder = new GlassButton { Text = "打开日志目录", Location = new Point(139, 392), Width = 140, BackColor = Color.FromArgb(73, 84, 102) };
        folder.Click += delegate { Directory.CreateDirectory(AppData.DirectoryPath); Process.Start("explorer.exe", AppData.DirectoryPath); };
        card.Controls.Add(refresh);
        card.Controls.Add(folder);
        page.Enter += delegate { LoadLog(); };
        return page;
    }

    TabPage BuildAboutPage()
    {
        var page = Page("关于");
        var card = Card(52, 42, 775, 390);
        page.Controls.Add(card);

        var mark = new Label
        {
            Text = "C",
            Font = new Font("Segoe UI", 25F, FontStyle.Bold),
            ForeColor = Color.FromArgb(221, 239, 255),
            BackColor = Color.FromArgb(45, 139, 236),
            TextAlign = ContentAlignment.MiddleCenter,
            Location = new Point(38, 42),
            Size = new Size(62, 62)
        };
        var title = new Label { Text = "CampusFlow", ForeColor = TextMain, Font = new Font("Microsoft YaHei UI", 20F, FontStyle.Bold), AutoSize = true, Location = new Point(122, 43) };
        var version = new Label { Text = "Version 1314.5.2.0  ·  Windows 11", ForeColor = TextMuted, AutoSize = true, Location = new Point(125, 82) };
        var description = new Label
        {
            Text = "CampusFlow 是一个面向 Windows 11 的校园网后台认证工具。\r\n它在网络连接后静默检查认证状态，并按配置向校园网门户提交表单，\r\n不打开 Edge，也不显示终端窗口。",
            ForeColor = Color.FromArgb(218, 228, 239),
            Font = new Font("Microsoft YaHei UI", 10.5F),
            Location = new Point(40, 145),
            Size = new Size(690, 92),
            AutoEllipsis = false
        };
        var divider = new Panel { Location = new Point(40, 258), Size = new Size(690, 1), BackColor = Color.FromArgb(65, 255, 255, 255) };
        var creditLabel = new Label { Text = "制作信息", ForeColor = TextMuted, AutoSize = true, Location = new Point(40, 284) };
        var credit = new Label
        {
            Text = "由河北水利电力学院经济与金融专业的一名学生制作",
            ForeColor = TextMain,
            Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Bold),
            AutoSize = true,
            Location = new Point(40, 313)
        };
        card.Controls.Add(mark);
        card.Controls.Add(title);
        card.Controls.Add(version);
        card.Controls.Add(description);
        card.Controls.Add(divider);
        card.Controls.Add(creditLabel);
        card.Controls.Add(credit);
        return page;
    }

    static TabPage Page(string title)
    {
        return new TabPage(title) { BackColor = Color.FromArgb(18, 25, 35), Padding = new Padding(0) };
    }

    RoundPanel Card(int x, int y, int width, int height)
    {
        return new RoundPanel { Location = new Point(x, y), Size = new Size(width, height), Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
    }

    void AddField(Control parent, string labelText, Control field, int x, int y, int width)
    {
        var label = new Label { Text = labelText, ForeColor = TextMuted, AutoSize = true, Location = new Point(x, y) };
        field.SetBounds(x, y + 25, width, field.Height > 30 ? field.Height : 30);
        parent.Controls.Add(label);
        parent.Controls.Add(field);
    }

    static TextBox Input(bool multiline = false)
    {
        return new TextBox
        {
            BorderStyle = BorderStyle.FixedSingle,
            BackColor = Color.FromArgb(31, 41, 54),
            ForeColor = Color.FromArgb(243, 247, 252),
            Multiline = multiline,
            Font = new Font("Microsoft YaHei UI", 9F)
        };
    }

    void StyleCombo(ComboBox combo)
    {
        combo.BackColor = Color.FromArgb(31, 41, 54);
        combo.ForeColor = TextMain;
        combo.FlatStyle = FlatStyle.Flat;
        combo.Height = 30;
    }

    void LoadValues()
    {
        PortalSettings settings = AppData.LoadSettings();
        PutSettings(settings);
        nightMode = settings.NightMode;
        ApplyTheme();
        string[] credentials = AppData.LoadCredential();
        if (credentials != null) username.Text = credentials[0];
        password.Text = "";
    }

    void PutSettings(PortalSettings settings)
    {
        portalUrl.Text = settings.PortalUrl;
        submitUrl.Text = settings.SubmitUrl;
        method.SelectedItem = String.IsNullOrEmpty(settings.Method) ? "POST" : settings.Method.ToUpperInvariant();
        usernameField.Text = settings.UsernameField;
        passwordField.Text = settings.PasswordField;
        extraFields.Text = settings.ExtraFields;
        connectivityUrl.Text = settings.ConnectivityUrl;
        connectivityExpected.Text = settings.ConnectivityExpected;
        successKeywords.Text = settings.SuccessKeywords;
        interval.Value = Math.Max(interval.Minimum, Math.Min(interval.Maximum, settings.CheckIntervalSeconds));
        discoverRedirect.Checked = settings.DiscoverRedirect;
        autoDetect.Checked = settings.AutoDetect;
    }

    PortalSettings ReadSettings()
    {
        return new PortalSettings
        {
            PortalUrl = portalUrl.Text.Trim(),
            SubmitUrl = submitUrl.Text.Trim(),
            Method = method.SelectedItem == null ? "POST" : method.SelectedItem.ToString(),
            UsernameField = usernameField.Text.Trim(),
            PasswordField = passwordField.Text.Trim(),
            ExtraFields = extraFields.Text,
            ConnectivityUrl = connectivityUrl.Text.Trim(),
            ConnectivityExpected = connectivityExpected.Text,
            SuccessKeywords = successKeywords.Text,
            CheckIntervalSeconds = (int)interval.Value,
            DiscoverRedirect = discoverRedirect.Checked,
            NightMode = nightMode,
            AutoDetect = autoDetect.Checked
        };
    }

    bool ValidateValues(bool requirePassword)
    {
        bool missingManualFields = !autoDetect.Checked && (String.IsNullOrWhiteSpace(submitUrl.Text) ||
            String.IsNullOrWhiteSpace(usernameField.Text) || String.IsNullOrWhiteSpace(passwordField.Text));
        if (String.IsNullOrWhiteSpace(portalUrl.Text) || missingManualFields || String.IsNullOrWhiteSpace(connectivityUrl.Text))
        {
            MessageBox.Show(autoDetect.Checked ? "登录页地址和联网检测地址不能为空。" : "登录地址、提交地址、字段名和联网检测地址不能为空。", "CampusFlow");
            return false;
        }
        if (requirePassword && (String.IsNullOrWhiteSpace(username.Text) || (password.Text.Length == 0 && AppData.LoadCredential() == null)))
        {
            MessageBox.Show("请输入校园网账号和密码。", "CampusFlow");
            return false;
        }
        return true;
    }

    void DetectLoginForm(Control button)
    {
        if (String.IsNullOrWhiteSpace(portalUrl.Text))
        {
            MessageBox.Show("请先填写登录页地址。", "CampusFlow");
            return;
        }
        button.Enabled = false;
        ThreadPool.QueueUserWorkItem(delegate
        {
            try
            {
                PortalClient.DetectedForm detected = PortalClient.DetectForm(portalUrl.Text.Trim());
                BeginInvoke((MethodInvoker)delegate
                {
                    button.Enabled = true;
                    if (detected == null)
                    {
                        MessageBox.Show("没有识别到普通登录表单。请打开高级设置手动填写，或确认该页面不是验证码/统一认证页面。", "CampusFlow");
                        return;
                    }
                    submitUrl.Text = detected.SubmitUrl;
                    method.SelectedItem = detected.Method;
                    usernameField.Text = detected.UsernameField;
                    passwordField.Text = detected.PasswordField;
                    extraFields.Text = detected.ExtraFields;
                    autoDetect.Checked = true;
                    MessageBox.Show("已识别登录表单。点击“保存并启用”即可。", "CampusFlow");
                });
            }
            catch (Exception ex)
            {
                BeginInvoke((MethodInvoker)delegate
                {
                    button.Enabled = true;
                    MessageBox.Show("识别失败：" + ex.Message, "CampusFlow");
                });
            }
        });
    }

    void SaveAndEnable()
    {
        if (!ValidateValues(true)) return;
        AppData.SaveSettings(ReadSettings());
        if (password.Text.Length > 0) AppData.SaveCredential(username.Text.Trim(), password.Text);
        StartupManager.Enable();
        UpdateStatus();
        MessageBox.Show("已保存并启用。连接校园网后会在后台自动认证。", "CampusFlow");
    }

    void SaveSettingsOnly()
    {
        if (!ValidateValues(false)) return;
        AppData.SaveSettings(ReadSettings());
        StartupManager.Restart();
        MessageBox.Show("设置已保存。", "CampusFlow");
    }

    void TestLogin(Control button)
    {
        if (!ValidateValues(true)) return;
        AppData.SaveSettings(ReadSettings());
        if (password.Text.Length > 0) AppData.SaveCredential(username.Text.Trim(), password.Text);
        button.Enabled = false;
        status.Text = "正在测试…";
        ThreadPool.QueueUserWorkItem(delegate
        {
            string result = PortalClient.TryLogin(AppData.LoadSettings());
            BeginInvoke((MethodInvoker)delegate
            {
                button.Enabled = true;
                UpdateStatus();
                MessageBox.Show(result, "CampusFlow");
            });
        });
    }

    void ToggleTheme()
    {
        nightMode = !nightMode;
        ApplyTheme();
        try { AppData.SaveSettings(ReadSettings()); } catch { }
    }

    void ApplyTheme()
    {
        Color pageColor = nightMode ? Color.FromArgb(18, 25, 35) : Color.FromArgb(244, 247, 251);
        Color panelColor = nightMode ? Color.FromArgb(22, 31, 43) : Color.FromArgb(232, 239, 246);
        Color inputColor = nightMode ? Color.FromArgb(31, 41, 54) : Color.FromArgb(255, 255, 255);
        Color mainText = nightMode ? Color.FromArgb(243, 247, 252) : Color.FromArgb(31, 41, 55);
        Color mutedText = nightMode ? Color.FromArgb(169, 182, 198) : Color.FromArgb(91, 105, 122);

        BackColor = pageColor;
        ApplyThemeToControls(Controls, pageColor, panelColor, inputColor, mainText, mutedText);
        for (int i = 0; i < navigationButtons.Count; i++)
            navigationButtons[i].BackColor = i == tabs.SelectedIndex ? Color.FromArgb(42, 139, 236) : (nightMode ? Color.FromArgb(48, 61, 78) : Color.FromArgb(214, 226, 239));
        if (themeButton != null)
        {
            themeButton.Text = nightMode ? "☀ 日间模式" : "☾ 夜间模式";
            themeButton.BackColor = nightMode ? Color.FromArgb(48, 61, 78) : Color.FromArgb(214, 226, 239);
            themeButton.ForeColor = mainText;
        }
        Invalidate(true);
    }

    void ApplyThemeToControls(Control.ControlCollection controls, Color pageColor, Color panelColor, Color inputColor, Color mainText, Color mutedText)
    {
        foreach (Control control in controls)
        {
            RoundPanel roundPanel = control as RoundPanel;
            GlassButton glassButton = control as GlassButton;
            if (roundPanel != null)
            {
                roundPanel.FillColor = nightMode ? Color.FromArgb(196, 31, 40, 52) : Color.FromArgb(205, 255, 255, 255);
                roundPanel.BorderColor = nightMode ? Color.FromArgb(70, 255, 255, 255) : Color.FromArgb(120, 116, 137, 157);
            }
            else if (glassButton != null)
            {
                glassButton.ForeColor = mainText;
            }
            else if (control is Button)
            {
                control.ForeColor = mainText;
                control.BackColor = Color.Transparent;
            }
            else if (control is TextBox || control is RichTextBox || control is ComboBox || control is NumericUpDown)
            {
                control.BackColor = inputColor;
                control.ForeColor = mainText;
            }
            else if (control is Label)
            {
                control.ForeColor = mainText;
            }
            else if (control is CheckBox)
            {
                control.ForeColor = mainText;
                control.BackColor = Color.Transparent;
            }
            else if (control is TabPage)
            {
                control.BackColor = pageColor;
            }
            else if (control is Panel)
            {
                control.BackColor = panelColor;
            }
            if (control == status)
            {
                status.BackColor = nightMode ? Color.FromArgb(55, 255, 255, 255) : Color.FromArgb(180, 255, 255, 255);
                status.ForeColor = nightMode ? Color.FromArgb(243, 247, 252) : Color.FromArgb(31, 41, 55);
            }
            ApplyThemeToControls(control.Controls, pageColor, panelColor, inputColor, mainText, mutedText);
        }
    }

    void UpdateStatus()
    {
        status.Text = StartupManager.IsEnabled ? "● 后台已启用" : "○ 后台未启用";
        status.ForeColor = StartupManager.IsEnabled ? Color.FromArgb(134, 239, 172) : TextMuted;
    }

    void LoadLog()
    {
        try { log.Text = File.Exists(AppData.LogPath) ? File.ReadAllText(AppData.LogPath, Encoding.UTF8) : "暂无日志"; }
        catch (Exception ex) { log.Text = "读取日志失败：" + ex.Message; }
        log.SelectionStart = log.TextLength;
        log.ScrollToCaret();
    }
}

static class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        if (args.Length > 0 && args[0] == "--background")
        {
            BackgroundHost.Run();
            return;
        }
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new MainForm());
    }
}
