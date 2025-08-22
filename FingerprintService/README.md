# FingerprintService

A C# .NET 6 Windows console application for capturing fingerprints using the **SecuGen Hamster Plus** fingerprint scanner. The application interacts with the SecuGen FDxSDK Pro SDK to capture fingerprint images and templates, returning them in **Base64** format for use in biometric systems or authentication workflows.  

---

## Features

- Detects connected SecuGen fingerprint devices  
- Captures fingerprint images and saves as `.raw`  
- Generates fingerprint templates compatible with SecuGen WebAPI  
- Returns fingerprint templates as Base64 strings for easy storage and verification  
- Supports multiple SecuGen devices and auto-detection  

---

## Requirements

- Windows 10/11 (x64)  
- SecuGen Hamster Plus device  
- SecuGen FDxSDK Pro for Windows  
- [.NET 6.0 SDK (Desktop development)](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-desktop-6.0.36-windows-x64-installer)  
- [.NET 6.0 Windows Desktop Runtime](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-desktop-6.0.36-windows-x64-installer)  

---

## Setup Instructions

```bash
git clone https://github.com/yourusername/FingerprintService.git
cd FingerprintService

dotnet build
dotnet run
