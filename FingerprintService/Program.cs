using Microsoft.AspNetCore.Mvc;
using SecuGen.FDxSDKPro.Windows;
using System.Text.Json;
using System.Threading.Tasks;
using System;
using System.Linq;

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

        try
        {
            // Enumerate devices
            int error = fpm.EnumerateDevice();
            if (error != 0)
                return Ok(new { success = false, error = $"Failed to enumerate devices: {error}" });

            if (fpm.NumberOfDevice == 0)
                return Ok(new { success = false, error = "No fingerprint scanner detected" });

            // Init (try multiple IDs)
            error = fpm.Init((SGFPMDeviceName)0);
            if (error != 0)
            {
                for (int deviceId = 1; deviceId <= 10; deviceId++)
                {
                    error = fpm.Init((SGFPMDeviceName)deviceId);
                    if (error == 0) break;
                }
            }
            if (error != 0)
                return Ok(new { success = false, error = $"Failed to initialize device: {error}" });

            // Open device (try ports)
            error = fpm.OpenDevice(0);
            if (error != 0)
            {
                error = fpm.OpenDevice(-1);
                if (error != 0)
                {
                    for (int port = 1; port <= 4; port++)
                    {
                        error = fpm.OpenDevice(port);
                        if (error == 0) break;
                    }
                }
            }
            if (error != 0)
                return Ok(new { success = false, error = $"Failed to open device: {error}" });

            // Device info
            SGFPMDeviceInfoParam info = new SGFPMDeviceInfoParam();
            error = fpm.GetDeviceInfo(info);
            if (error != 0)
                return Ok(new { success = false, error = $"Failed to get device info: {error}" });

            // Capture loop (timeout 30s)
            byte[] fpImage = new byte[info.ImageWidth * info.ImageHeight];
            var start = DateTime.Now;
            var timeout = TimeSpan.FromSeconds(30);

            while (DateTime.Now - start < timeout)
            {
                error = fpm.GetImage(fpImage);
                if (error == 0)
                {
                    bool hasData = fpImage.Take(100).Any(b => b != 0);
                    if (hasData) break;
                }
                await Task.Delay(100);
            }

            if (error != 0)
            {
                fpm.CloseDevice();
                return Ok(new { success = false, error = $"Failed to capture fingerprint: {error}. Make sure finger is placed on scanner." });
            }

            // Build template (400 bytes)
            byte[] template = new byte[400];
            error = fpm.CreateTemplate(fpImage, template);
            if (error != 0)
            {
                fpm.CloseDevice();
                return Ok(new { success = false, error = $"Failed to create template: {error}" });
            }

            string templateBase64 = Convert.ToBase64String(template);

            // Duplicate matching (optional)
            bool duplicate = false;
            int? duplicateIndex = null;

            if (request?.ExistingTemplates != null && request.ExistingTemplates.Count > 0)
            {
                for (int i = 0; i < request.ExistingTemplates.Count; i++)
                {
                    var storedB64 = request.ExistingTemplates[i];
                    if (string.IsNullOrWhiteSpace(storedB64))
                        continue;

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
                    catch
                    {
                        // Skip invalid base64
                    }
                }
            }

            fpm.CloseDevice();

            return Ok(new
            {
                success = true,
                templateBase64 = templateBase64,
                templateSize = template.Length,
                imageSize = fpImage.Length,
                duplicate = duplicate,
                duplicateIndex = duplicateIndex,
                message = duplicate ? "Duplicate fingerprint found." : "Fingerprint captured successfully."
            });
        }
        catch (Exception ex)
        {
            try { fpm.CloseDevice(); } catch { }
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
        SGFingerPrintManager fpm = new SGFingerPrintManager();
        
        try
        {
            // Initialize and open device (same as enroll)
            int error = fpm.EnumerateDevice();
            if (error != 0)
                return Ok(new { success = false, error = $"Failed to enumerate devices: {error}" });

            if (fpm.NumberOfDevice == 0)
                return Ok(new { success = false, error = "No fingerprint scanner detected" });

            // Initialize device
            error = fpm.Init((SGFPMDeviceName)0);
            if (error != 0)
            {
                for (int deviceId = 1; deviceId <= 10; deviceId++)
                {
                    error = fpm.Init((SGFPMDeviceName)deviceId);
                    if (error == 0) break;
                }
            }

            if (error != 0)
                return Ok(new { success = false, error = $"Failed to initialize device: {error}" });

            // Open device
            error = fpm.OpenDevice(0);
            if (error != 0)
            {
                error = fpm.OpenDevice(-1);
                if (error != 0)
                {
                    for (int port = 1; port <= 4; port++)
                    {
                        error = fpm.OpenDevice(port);
                        if (error == 0) break;
                    }
                }
            }

            if (error != 0)
                return Ok(new { success = false, error = $"Failed to open device: {error}" });

            // Get device info
            SGFPMDeviceInfoParam info = new SGFPMDeviceInfoParam();
            error = fpm.GetDeviceInfo(info);
            if (error != 0)
                return Ok(new { success = false, error = $"Failed to get device info: {error}" });

            // Capture fingerprint for verification
            byte[] fpImage = new byte[info.ImageWidth * info.ImageHeight];
            
            var startTime = DateTime.Now;
            var timeout = TimeSpan.FromSeconds(30);
            
            while (DateTime.Now - startTime < timeout)
            {
                error = fpm.GetImage(fpImage);
                if (error == 0)
                {
                    bool hasData = fpImage.Take(100).Any(b => b != 0);
                    if (hasData)
                        break;
                }
                
                await Task.Delay(100);
            }

            if (error != 0)
                return Ok(new { success = false, error = $"Failed to capture fingerprint: {error}. Make sure finger is placed on scanner." });

            // Create template from captured image
            byte[] capturedTemplate = new byte[400];
            error = fpm.CreateTemplate(fpImage, capturedTemplate);
            
            if (error != 0)
                return Ok(new { success = false, error = $"Failed to create template: {error}" });

            // Convert stored template from base64
            byte[] storedTemplate;
            try
            {
                storedTemplate = Convert.FromBase64String(request.StoredTemplate);
            }
            catch
            {
                return Ok(new { success = false, error = "Invalid stored template format" });
            }

            // Perform matching - Fixed to use bool instead of int
            bool isMatch = false;
            error = fpm.MatchTemplate(capturedTemplate, storedTemplate, SGFPMSecurityLevel.NORMAL, ref isMatch);
            
            // Close device
            fpm.CloseDevice();

            if (error != 0)
                return Ok(new { success = false, error = $"Matching failed: {error}" });

            return Ok(new { 
                success = true, 
                isMatch = isMatch,
                message = isMatch ? "Fingerprint matches!" : "Fingerprint does not match."
            });
        }
        catch (Exception ex)
        {
            try { fpm.CloseDevice(); } catch { }
            return Ok(new { success = false, error = $"Exception: {ex.Message}" });
        }
    }

    [HttpPost("search")]
    public async Task<IActionResult> SearchFingerprint([FromBody] SearchRequest request)
    {
        SGFingerPrintManager fpm = new SGFingerPrintManager();
        
        try
        {
            // Initialize and open device (same as enroll)
            int error = fpm.EnumerateDevice();
            if (error != 0)
                return Ok(new { success = false, error = $"Failed to enumerate devices: {error}" });

            if (fpm.NumberOfDevice == 0)
                return Ok(new { success = false, error = "No fingerprint scanner detected" });

            // Initialize device
            error = fpm.Init((SGFPMDeviceName)0);
            if (error != 0)
            {
                for (int deviceId = 1; deviceId <= 10; deviceId++)
                {
                    error = fpm.Init((SGFPMDeviceName)deviceId);
                    if (error == 0) break;
                }
            }

            if (error != 0)
                return Ok(new { success = false, error = $"Failed to initialize device: {error}" });

            // Open device
            error = fpm.OpenDevice(0);
            if (error != 0)
            {
                error = fpm.OpenDevice(-1);
                if (error != 0)
                {
                    for (int port = 1; port <= 4; port++)
                    {
                        error = fpm.OpenDevice(port);
                        if (error == 0) break;
                    }
                }
            }

            if (error != 0)
                return Ok(new { success = false, error = $"Failed to open device: {error}" });

            // Get device info
            SGFPMDeviceInfoParam info = new SGFPMDeviceInfoParam();
            error = fpm.GetDeviceInfo(info);
            if (error != 0)
                return Ok(new { success = false, error = $"Failed to get device info: {error}" });

            // Capture fingerprint ONCE for searching
            byte[] fpImage = new byte[info.ImageWidth * info.ImageHeight];
            
            var startTime = DateTime.Now;
            var timeout = TimeSpan.FromSeconds(30);
            
            while (DateTime.Now - startTime < timeout)
            {
                error = fpm.GetImage(fpImage);
                if (error == 0)
                {
                    bool hasData = fpImage.Take(100).Any(b => b != 0);
                    if (hasData)
                        break;
                }
                
                await Task.Delay(100);
            }

            if (error != 0)
                return Ok(new { success = false, error = $"Failed to capture fingerprint: {error}. Make sure finger is placed on scanner." });

            // Create template from captured image
            byte[] capturedTemplate = new byte[400];
            error = fpm.CreateTemplate(fpImage, capturedTemplate);
            
            if (error != 0)
                return Ok(new { success = false, error = $"Failed to create template: {error}" });

            // Close device (we're done with the scanner)
            fpm.CloseDevice();

            // Now compare against all provided templates
            var matches = new List<object>();
            
            foreach (var templateData in request.Templates)
            {
                try
                {
                    // Convert stored template from base64
                    byte[] storedTemplate = Convert.FromBase64String(templateData.Template);
                    
                    // Perform matching
                    bool isMatch = false;
                    error = fpm.MatchTemplate(capturedTemplate, storedTemplate, SGFPMSecurityLevel.NORMAL, ref isMatch);
                    
                    if (error == 0 && isMatch)
                    {
                        matches.Add(new
                        {
                            userId = templateData.UserId,
                            isMatch = true
                        });
                    }
                }
                catch
                {
                    // Skip invalid templates
                    continue;
                }
            }

            return Ok(new { 
                success = true, 
                matches = matches,
                totalTested = request.Templates.Count,
                matchesFound = matches.Count
            });
        }
        catch (Exception ex)
        {
            try { fpm.CloseDevice(); } catch { }
            return Ok(new { success = false, error = $"Exception: {ex.Message}" });
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