using System;
using System.Reflection;
using SecuGen.FDxSDKPro.Windows;

namespace FingerprintService
{
    class Program
    {
        static void Main(string[] args)
        {
            SGFingerPrintManager fpm = new SGFingerPrintManager();

            try
            {
                Console.WriteLine("Starting SecuGen Fingerprint Scanner...");

                // First, let's discover what's available in the SDK
                DiscoverAvailableConstants();

                // Enumerate devices - simplest approach
                int error = fpm.EnumerateDevice();
                Console.WriteLine("EnumerateDevice result: " + error + " (0 = success)");

                if (error != 0)
                {
                    Console.WriteLine("Failed to enumerate devices. Error: " + error);
                    return;
                }

                // Get number of devices
                int deviceCount = fpm.NumberOfDevice;
                Console.WriteLine("Devices Found: " + deviceCount);

                if (deviceCount == 0)
                {
                    Console.WriteLine("No fingerprint devices detected.");
                    Console.WriteLine("Make sure:");
                    Console.WriteLine("1. Device is connected via USB");
                    Console.WriteLine("2. SecuGen drivers are installed");
                    Console.WriteLine("3. Device is not being used by another application");
                    return;
                }

                // Try to get device list info
                try
                {
                    SGFPMDeviceList deviceList = new SGFPMDeviceList();
                    error = fpm.GetEnumDeviceInfo(0, deviceList);
                    if (error == 0)
                    {
                        Console.WriteLine("Found device in slot 0");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("GetEnumDeviceInfo failed: " + ex.Message);
                }

                // Initialize device - try different approaches
                Console.WriteLine("\nTrying to initialize device...");
                
                // Try with 0 (often means auto-detect)
                error = fpm.Init((SGFPMDeviceName)0);
                Console.WriteLine("Init (0 - auto) result: " + error);

                if (error != 0)
                {
                    // Try with different device IDs (1-10 are common)
                    for (int deviceId = 1; deviceId <= 10; deviceId++)
                    {
                        error = fpm.Init((SGFPMDeviceName)deviceId);
                        Console.WriteLine($"Init ({deviceId}) result: " + error);
                        if (error == 0) break;
                    }
                }

                if (error != 0)
                {
                    Console.WriteLine("Failed to initialize device with any ID. Error: " + error);
                    return;
                }

                Console.WriteLine("✓ Device initialized successfully!");

                // Open the device - try different port approaches
                Console.WriteLine("Opening device...");
                
                // Try auto-detect first (usually 0 or -1)
                error = fpm.OpenDevice(0);
                Console.WriteLine("OpenDevice (0) result: " + error);

                if (error != 0)
                {
                    error = fpm.OpenDevice(-1);
                    Console.WriteLine("OpenDevice (-1) result: " + error);
                }

                if (error != 0)
                {
                    // Try different USB port numbers
                    for (int port = 1; port <= 4; port++)
                    {
                        error = fpm.OpenDevice(port);
                        Console.WriteLine($"OpenDevice ({port}) result: " + error);
                        if (error == 0) break;
                    }
                }

                if (error != 0)
                {
                    Console.WriteLine("Failed to open device. Error: " + error);
                    return;
                }

                Console.WriteLine("✓ Device opened successfully!");

                // Get device info
                SGFPMDeviceInfoParam info = new SGFPMDeviceInfoParam();
                error = fpm.GetDeviceInfo(info);
                
                if (error == 0)
                {
                    Console.WriteLine("\n=== Device Information ===");
                    Console.WriteLine("Device serial: " + info.DeviceSN);
                    Console.WriteLine("Image DPI: " + info.ImageDPI);
                    Console.WriteLine("Image size: " + info.ImageWidth + "x" + info.ImageHeight);
                    Console.WriteLine("Device ID: " + info.DeviceID);
                    Console.WriteLine("Firmware: " + info.FWVersion);
                    Console.WriteLine("=========================\n");

                    // Capture a fingerprint image
                    Console.WriteLine("Ready to capture fingerprint!");
                    Console.WriteLine("Place your finger on the scanner and press any key...");
                    Console.ReadKey();

                    Console.WriteLine("Capturing image...");
                    byte[] fpImage = new byte[info.ImageWidth * info.ImageHeight];
                    error = fpm.GetImage(fpImage);

                    Console.WriteLine("GetImage result: " + error);
                    
                    if (error == 0)
                    {
                        Console.WriteLine("✓ Fingerprint image captured successfully!");
                        Console.WriteLine("Image size: " + fpImage.Length + " bytes");
                        
                        // Check if we actually got image data
                        bool hasData = false;
                        for (int i = 0; i < Math.Min(fpImage.Length, 100); i++)
                        {
                            if (fpImage[i] != 0)
                            {
                                hasData = true;
                                break;
                            }
                        }
                        
                        if (hasData)
                        {
                            Console.WriteLine("✓ Image contains valid data!");
                            
                            // Save the image
                            try
                            {
                                System.IO.File.WriteAllBytes("fingerprint.raw", fpImage);
                                Console.WriteLine("✓ Image saved as fingerprint.raw");
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine("Failed to save image: " + ex.Message);
                            }
                        }
                        else
                        {
                            Console.WriteLine("⚠ Image appears to be empty (all zeros)");
                        }
                    }
                    else
                    {
                        Console.WriteLine("Failed to capture fingerprint. Error: " + error);
                        Console.WriteLine("Make sure finger is properly placed on scanner.");
                    }
                }
                else
                {
                    Console.WriteLine("Failed to get device info. Error: " + error);
                }

                // Close device
                fpm.CloseDevice();
                Console.WriteLine("\n✓ Device closed successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception: " + ex.Message);
                Console.WriteLine("Stack trace: " + ex.StackTrace);
            }
            finally
            {
                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
            }
        }

        static void DiscoverAvailableConstants()
        {
            Console.WriteLine("\n=== Discovering SDK Constants ===");
            
            try
            {
                // Check SGFPMError enum
                Type errorType = typeof(SGFPMError);
                Console.WriteLine("SGFPMError values:");
                foreach (var value in Enum.GetValues(errorType))
                {
                    Console.WriteLine($"  {value} = {(int)value}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Could not enumerate SGFPMError: " + ex.Message);
            }

            try
            {
                // Check SGFPMDeviceName enum
                Type deviceType = typeof(SGFPMDeviceName);
                Console.WriteLine("\nSGFPMDeviceName values:");
                foreach (var value in Enum.GetValues(deviceType))
                {
                    Console.WriteLine($"  {value} = {(int)value}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Could not enumerate SGFPMDeviceName: " + ex.Message);
            }

            try
            {
                // Check SGFPMPortAddr enum
                Type portType = typeof(SGFPMPortAddr);
                Console.WriteLine("\nSGFPMPortAddr values:");
                foreach (var value in Enum.GetValues(portType))
                {
                    Console.WriteLine($"  {value} = {(int)value}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Could not enumerate SGFPMPortAddr: " + ex.Message);
            }

            Console.WriteLine("=================================\n");
        }
    }
}