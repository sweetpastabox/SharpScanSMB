# SharpScanSMB

This repo contains a modified version of the SMBLibrary-Client* ported into an SMBScanner that can be ran in memory.
*https://github.com/SonnyX/SMB-Client/tree/master/SMBLibrary

Eventually this will end up into some CME C# port... 

![sc](https://github.com/sweetpastabox/SharpScanSmb/assets/66618339/df606785-1a94-4a44-9381-5d47a0bc3050)


## Build

Compile the library, add the .dll as reference to the scanner, compile the scanner. 

## Release

Release available

## Usage

```
.\SharpScanSmb.exe -target 1.2.3.4
.\SharpScanSmb.exe -target 192.168.1.0/24
.\SharpScanSmb.exe -list kekw.txt

.\SharpScanSmb.exe -target 1.2.3.4 -verbose
.\SharpScanSmb.exe -target 192.168.1.0/24 -verbose
.\SharpScanSmb.exe -list kekw.txt -verbose

.\SharpScanSmb.exe -target 1.2.3.4 -csv corpo.csv
.\SharpScanSmb.exe -target 192.168.1.0/24 -csv corpo.csv
.\SharpScanSmb.exe -list kekw.txt -csv corpo.csv

.\SharpScanSmb.exe -target 1.2.3.4 -csv corpo.csv -verbose
.\SharpScanSmb.exe -target 192.168.1.0/24 -csv corpo.csv -verbose
.\SharpScanSmb.exe -list kekw.txt -csv corpo.csv -verbose
```

## Run from mem

```
# Get latest release
$url = "https://github.com/sweetpastabox/SharpScanSmb/releases/download/1.0/SharpScanSMB-x64.exe"

# One liner to download and execute from memory in a PS shell
$sss =[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "$url" -UseBasicParsing | Select-Object -ExpandProperty Content)); [SharpScanSmb.Program]::Main("")

# Before cmd in 3 lines
$sss =[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "$url" -UseBasicParsing | Select-Object -ExpandProperty Content));
[SharpScanSmb.Program]::Main("") #Put inside the quotes the parameters you want to use

# Load from disk in memory and execute:
$sss = [System.Reflection.Assembly]::Load([byte[]]([IO.File]::ReadAllBytes("D:\Users\victim\SharpScanSmb.exe")));
[SharpScanSmb.Program]::Main("") #Put inside the quotes the winpeas parameters you want to use
```

## Findings

The scanner checks: SMB1\CIFS, SMB2, SMB2 Security Mode
