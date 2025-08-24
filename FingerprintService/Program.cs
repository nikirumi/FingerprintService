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
    [HttpPost("enroll")]
    public async Task<IActionResult> EnrollFingerprint()
    {
        SGFingerPrintManager fpm = new SGFingerPrintManager();
        
        try
        {
            // Initialize and open device
            int error = fpm.EnumerateDevice();
            if (error != 0)
                return Ok(new { success = false, error = $"Failed to enumerate devices: {error}" });

            if (fpm.NumberOfDevice == 0)
                return Ok(new { success = false, error = "No fingerprint scanner detected" });

            // Try to initialize device
            error = fpm.Init((SGFPMDeviceName)0);
            if (error != 0)
            {
                // Try other device IDs
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

            // Capture fingerprint with timeout
            byte[] fpImage = new byte[info.ImageWidth * info.ImageHeight];
            
            // Wait for finger placement (with timeout)
            var startTime = DateTime.Now;
            var timeout = TimeSpan.FromSeconds(30); // 30 second timeout
            
            while (DateTime.Now - startTime < timeout)
            {
                error = fpm.GetImage(fpImage);
                if (error == 0)
                {
                    // Check if image has actual data
                    bool hasData = fpImage.Take(100).Any(b => b != 0);
                    if (hasData)
                        break;
                }
                
                // Small delay before retry
                await Task.Delay(100);
            }

            if (error != 0)
                return Ok(new { success = false, error = $"Failed to capture fingerprint: {error}. Make sure finger is placed on scanner." });

            // Create template
            byte[] template = new byte[400]; // Standard SecuGen template size
            error = fpm.CreateTemplate(fpImage, template);
            
            if (error != 0)
                return Ok(new { success = false, error = $"Failed to create template: {error}" });

            // Convert to base64
            string templateBase64 = Convert.ToBase64String(template);

            // Close device
            fpm.CloseDevice();

            return Ok(new { 
                success = true, 
                templateBase64 = templateBase64,
                imageSize = fpImage.Length,
                templateSize = template.Length
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
            
            return Ok(new { 
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
}