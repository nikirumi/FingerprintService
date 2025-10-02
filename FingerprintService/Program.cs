using Microsoft.AspNetCore.Mvc;
using SecuGen.FDxSDKPro.Windows;
using System.Text.Json;
using System.Threading.Tasks;
using System;
using System.Linq;
using System.Threading;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddControllers();
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

var app = builder.Build();

// Configure pipeline - CORS must be before routing!
app.UseCors();
app.UseRouting();
app.MapControllers();

app.Run("http://localhost:5000");

[ApiController]
[Route("")]
public class FingerprintController : ControllerBase
{
    public class EnrollRequest
    {
        public List<string>? ExistingTemplates { get; set; }
    }

    [HttpPost("enroll")]
    public async Task<IActionResult> EnrollFingerprint([FromBody] EnrollRequest? request)
    {
        SGFingerPrintManager fpm = new SGFingerPrintManager();
        var ct = HttpContext.RequestAborted;                 // <-- cancellation token from client
        try
        {
            int error = fpm.EnumerateDevice();
            if (error != 0) return Ok(new { success = false, error = $"Failed to enumerate devices: {error}" });
            if (fpm.NumberOfDevice == 0) return Ok(new { success = false, error = "No fingerprint scanner detected" });

            error = fpm.Init((SGFPMDeviceName)0);
            if (error != 0)
            {
                for (int deviceId = 1; deviceId <= 10 && error != 0; deviceId++)
                {
                    if (ct.IsCancellationRequested) return Ok(new { success = false, cancelled = true, message = "Capture cancelled." });
                    error = fpm.Init((SGFPMDeviceName)deviceId);
                }
            }
            if (error != 0) return Ok(new { success = false, error = $"Failed to initialize device: {error}" });

            error = fpm.OpenDevice(0);
            if (error != 0)
            {
                error = fpm.OpenDevice(-1);
                for (int port = 1; error != 0 && port <= 4; port++)
                {
                    if (ct.IsCancellationRequested) { fpm.CloseDevice(); return Ok(new { success = false, cancelled = true, message = "Capture cancelled." }); }
                    error = fpm.OpenDevice(port);
                }
            }
            if (error != 0) return Ok(new { success = false, error = $"Failed to open device: {error}" });

            SGFPMDeviceInfoParam info = new SGFPMDeviceInfoParam();
            error = fpm.GetDeviceInfo(info);
            if (error != 0) return Ok(new { success = false, error = $"Failed to get device info: {error}" });

            byte[] fpImage = new byte[info.ImageWidth * info.ImageHeight];
            var start = DateTime.UtcNow;
            var timeout = TimeSpan.FromSeconds(30);

            while (DateTime.UtcNow - start < timeout)
            {
                if (ct.IsCancellationRequested)
                {
                    fpm.CloseDevice();
                    return Ok(new { success = false, cancelled = true, message = "Capture cancelled." });
                }

                error = fpm.GetImage(fpImage);
                if (error == 0)
                {
                    if (fpImage.Take(100).Any(b => b != 0)) break;
                }
                try
                {
                    await Task.Delay(100, ct);
                }
                catch (TaskCanceledException)
                {
                    fpm.CloseDevice();
                    return Ok(new { success = false, cancelled = true, message = "Capture cancelled." });
                }
            }

            if (ct.IsCancellationRequested)
            {
                fpm.CloseDevice();
                return Ok(new { success = false, cancelled = true, message = "Capture cancelled." });
            }

            if (error != 0)
            {
                fpm.CloseDevice();
                return Ok(new { success = false, error = $"Failed to capture fingerprint: {error}. Make sure finger is placed on scanner." });
            }

            byte[] template = new byte[400];
            error = fpm.CreateTemplate(fpImage, template);
            if (error != 0)
            {
                fpm.CloseDevice();
                return Ok(new { success = false, error = $"Failed to create template: {error}" });
            }

            string templateBase64 = Convert.ToBase64String(template);

            bool duplicate = false;
            int? duplicateIndex = null;
            if (request?.ExistingTemplates != null && request.ExistingTemplates.Count > 0)
            {
                for (int i = 0; i < request.ExistingTemplates.Count; i++)
                {
                    if (ct.IsCancellationRequested) { fpm.CloseDevice(); return Ok(new { success = false, cancelled = true, message = "Capture cancelled." }); }

                    var storedB64 = request.ExistingTemplates[i];
                    if (string.IsNullOrWhiteSpace(storedB64)) continue;
                    try
                    {
                        byte[] stored = Convert.FromBase64String(storedB64);
                        bool isMatch = false;
                        int matchErr = fpm.MatchTemplate(template, stored, SGFPMSecurityLevel.NORMAL, ref isMatch);
                        if (matchErr == 0 && isMatch)
                        {
                            duplicate = true;
                            duplicateIndex = i;
                            break;
                        }
                    }
                    catch { }
                }
            }

            fpm.CloseDevice();

            return Ok(new
            {
                success = true,
                templateBase64,
                duplicate,
                duplicateIndex,
                message = duplicate ? "Duplicate fingerprint found." : "Fingerprint captured successfully."
            });
        }
        catch (Exception ex)
        {
            try { fpm.CloseDevice(); } catch { }
            if (ct.IsCancellationRequested)
                return Ok(new { success = false, cancelled = true, message = "Capture cancelled (exception)." });
            return Ok(new { success = false, error = $"Exception: {ex.Message}" });
        }
    }

    [HttpGet("status")]
    public IActionResult GetStatus()
    {
        SGFingerPrintManager fpm = new SGFingerPrintManager();

        try
        {
            int error = fpm.EnumerateDevice();
            int deviceCount = error == 0 ? fpm.NumberOfDevice : 0;

            return Ok(new
            {
                success = true,
                devicesFound = deviceCount,
                scannerReady = deviceCount > 0
            });
        }
        catch (Exception ex)
        {
            return Ok(new { success = false, error = ex.Message });
        }
    }

    [HttpPost("verify")]
    public async Task<IActionResult> VerifyFingerprint([FromBody] VerifyRequest request)
    {
        var ct = HttpContext.RequestAborted;
        SGFingerPrintManager fpm = new SGFingerPrintManager();
        try {
            int error = fpm.EnumerateDevice();
            if (error != 0) return Ok(new { success = false, error = $"Failed to enumerate devices: {error}" });
            if (fpm.NumberOfDevice == 0) return Ok(new { success = false, error = "No fingerprint scanner detected" });

            error = fpm.Init((SGFPMDeviceName)0);
            if (error != 0) {
                for (int i=1; i<=10 && error!=0; i++) {
                    if (ct.IsCancellationRequested) return Ok(new { success=false, cancelled=true, message="Verification cancelled." });
                    error = fpm.Init((SGFPMDeviceName)i);
                }
            }
            if (error != 0) return Ok(new { success=false, error=$"Failed to initialize device: {error}" });

            error = fpm.OpenDevice(0);
            if (error != 0) {
                error = fpm.OpenDevice(-1);
                for (int port=1; error!=0 && port<=4; port++) {
                    if (ct.IsCancellationRequested) { fpm.CloseDevice(); return Ok(new { success=false, cancelled=true, message="Verification cancelled." }); }
                    error = fpm.OpenDevice(port);
                }
            }
            if (error != 0) return Ok(new { success=false, error=$"Failed to open device: {error}" });

            SGFPMDeviceInfoParam info = new SGFPMDeviceInfoParam();
            error = fpm.GetDeviceInfo(info);
            if (error != 0) { fpm.CloseDevice(); return Ok(new { success=false, error=$"Failed to get device info: {error}" }); }

            byte[] img = new byte[info.ImageWidth * info.ImageHeight];
            var start = DateTime.UtcNow;
            var timeout = TimeSpan.FromSeconds(30);
            while (DateTime.UtcNow - start < timeout) {
                if (ct.IsCancellationRequested) { fpm.CloseDevice(); return Ok(new { success=false, cancelled=true, message="Verification cancelled." }); }
                error = fpm.GetImage(img);
                if (error == 0 && img.Take(80).Any(b => b != 0)) break;
                try { await Task.Delay(80, ct); } catch (TaskCanceledException) {
                    fpm.CloseDevice(); return Ok(new { success=false, cancelled=true, message="Verification cancelled." });
                }
            }
            if (ct.IsCancellationRequested) { fpm.CloseDevice(); return Ok(new { success=false, cancelled=true, message="Verification cancelled." }); }
            if (error != 0) { fpm.CloseDevice(); return Ok(new { success=false, error=$"Failed to capture fingerprint: {error}" }); }

            byte[] captured = new byte[400];
            error = fpm.CreateTemplate(img, captured);
            if (error != 0) { fpm.CloseDevice(); return Ok(new { success=false, error=$"Failed to create template: {error}" }); }

            byte[] stored;
            try { stored = Convert.FromBase64String(request.StoredTemplate); }
            catch { fpm.CloseDevice(); return Ok(new { success=false, error="Invalid stored template format" }); }

            bool isMatch = false;
            error = fpm.MatchTemplate(captured, stored, SGFPMSecurityLevel.NORMAL, ref isMatch);
            fpm.CloseDevice();
            if (error != 0) return Ok(new { success=false, error=$"Matching failed: {error}" });
            return Ok(new { success=true, isMatch, message=isMatch ? "Fingerprint matches!" : "Fingerprint does not match." });
        }
        catch (Exception ex) {
            try { fpm.CloseDevice(); } catch {}
            if (ct.IsCancellationRequested)
                return Ok(new { success=false, cancelled=true, message="Verification cancelled (exception)." });
            return Ok(new { success=false, error=$"Exception: {ex.Message}" });
        }
    }

    [HttpPost("search")]
    public async Task<IActionResult> SearchFingerprint([FromBody] SearchRequest request)
    {
        var ct = HttpContext.RequestAborted;
        SGFingerPrintManager fpm = new SGFingerPrintManager();
        try {
            int error = fpm.EnumerateDevice();
            if (error != 0) return Ok(new { success=false, error=$"Failed to enumerate devices: {error}" });
            if (fpm.NumberOfDevice == 0) return Ok(new { success=false, error="No fingerprint scanner detected" });

            error = fpm.Init((SGFPMDeviceName)0);
            if (error != 0) {
                for (int i=1; i<=10 && error!=0; i++) {
                    if (ct.IsCancellationRequested) return Ok(new { success=false, cancelled=true, message="Search cancelled." });
                    error = fpm.Init((SGFPMDeviceName)i);
                }
            }
            if (error != 0) return Ok(new { success=false, error=$"Failed to initialize device: {error}" });

            error = fpm.OpenDevice(0);
            if (error != 0) {
                error = fpm.OpenDevice(-1);
                for (int port=1; error!=0 && port<=4; port++) {
                    if (ct.IsCancellationRequested) { fpm.CloseDevice(); return Ok(new { success=false, cancelled=true, message="Search cancelled." }); }
                    error = fpm.OpenDevice(port);
                }
            }
            if (error != 0) return Ok(new { success=false, error=$"Failed to open device: {error}" });

            SGFPMDeviceInfoParam info = new SGFPMDeviceInfoParam();
            error = fpm.GetDeviceInfo(info);
            if (error != 0) { fpm.CloseDevice(); return Ok(new { success=false, error=$"Failed to get device info: {error}" }); }

            byte[] img = new byte[info.ImageWidth * info.ImageHeight];
            var start = DateTime.UtcNow;
            var timeout = TimeSpan.FromSeconds(30);
            while (DateTime.UtcNow - start < timeout) {
                if (ct.IsCancellationRequested) { fpm.CloseDevice(); return Ok(new { success=false, cancelled=true, message="Search cancelled." }); }
                error = fpm.GetImage(img);
                if (error == 0 && img.Take(80).Any(b => b != 0)) break;
                try { await Task.Delay(80, ct); } catch (TaskCanceledException) {
                    fpm.CloseDevice(); return Ok(new { success=false, cancelled=true, message="Search cancelled." });
                }
            }
            if (ct.IsCancellationRequested) { fpm.CloseDevice(); return Ok(new { success=false, cancelled=true, message="Search cancelled." }); }
            if (error != 0) { fpm.CloseDevice(); return Ok(new { success=false, error=$"Failed to capture fingerprint: {error}" }); }

            byte[] captured = new byte[400];
            error = fpm.CreateTemplate(img, captured);
            if (error != 0) { fpm.CloseDevice(); return Ok(new { success=false, error=$"Failed to create template: {error}" }); }

            var matches = new List<object>();
            var matchErrors = 0;
            foreach (var t in request.Templates ?? new List<TemplateData>()) {
                if (ct.IsCancellationRequested) {
                    fpm.CloseDevice();
                    return Ok(new { success=false, cancelled=true, message="Search cancelled (matching)." });
                }
                if (string.IsNullOrWhiteSpace(t.Template)) continue;
                try {
                    byte[] stored = Convert.FromBase64String(t.Template);
                    bool isMatch = false;
                    int mErr = fpm.MatchTemplate(captured, stored, SGFPMSecurityLevel.NORMAL, ref isMatch);
                    if (mErr == 0 && isMatch) {
                        matches.Add(new { userId = t.UserId, isMatch = true });
                    } else if (mErr != 0) {
                        matchErrors++;
                    }
                } catch {
                    matchErrors++;
                }
            }

            fpm.CloseDevice();

            return Ok(new {
                success = true,
                matches,
                totalTested = (request.Templates?.Count) ?? 0,
                matchesFound = matches.Count,
                matchErrors
            });
        }
        catch (Exception ex) {
            try { fpm.CloseDevice(); } catch {}
            if (ct.IsCancellationRequested)
                return Ok(new { success=false, cancelled=true, message="Search cancelled (exception)." });
            return Ok(new { success=false, error=$"Exception: {ex.Message}" });
        }
    }

    // Request models
    public class VerifyRequest
    {
        public string StoredTemplate { get; set; } = "";
    }

    public class SearchRequest
    {
        public List<TemplateData> Templates { get; set; } = new();
    }

    public class TemplateData
    {
        public int UserId { get; set; }
        public string Template { get; set; } = "";
    }
}