using SMBLibrary;
using SMBLibrary.Client;
using SMBLibrary.SMB2;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace SmbScanner
{
    class Program
    {
        static void Main(string[] args)
        {
            //
            // Banner to brrrr
            //

            Console.WriteLine("");
            Console.WriteLine("                                                                                            ");
            Console.WriteLine("   .dMMMb  dMMMMMMMMb  dMMMMb        .dMMMb  .aMMMb  .aMMMb  dMMMMb  dMMMMb  dMMMMMP dMMMMb ");
            Console.WriteLine("  dMP\" VP dMP\"dMP\"dMP dMP\"dMP       dMP\" VP dMP\"VMP dMP\"dMP dMP dMP dMP dMP dMP     dMP.dMP ");
            Console.WriteLine("  VMMMb  dMP dMP dMP dMMMMK\"        VMMMb  dMP     dMMMMMP dMP dMP dMP dMP dMMMP   dMMMMK\"  ");
            Console.WriteLine("dP .dMP dMP dMP dMP dMP.aMF       dP .dMP dMP.aMP dMP dMP dMP dMP dMP dMP dMP     dMP\"AMF   ");
            Console.WriteLine("VMMMP\" dMP dMP dMP dMMMMP\"        VMMMP\"  VMMMP\" dMP dMP dMP dMP dMP dMP dMMMMMP dMP dMP    ");
            Console.WriteLine("                                                                                            ");
            Console.WriteLine("                                                                           Version: 1.0     ");
            Console.WriteLine("");
            Console.WriteLine("");
            ConsoleColor originalColor = Console.ForegroundColor;
            Console.WriteLine("\n[========================================================================]\n");


            //
            // parse command args
            //

            if (args.Length < 2 || (args[0] != "-target" && args[0] != "-list") || (args.Length == 4 && args[2] != "-csv"))
            {
                Console.WriteLine("[+] Usage: \n");
                Console.WriteLine("\tSharpScanSmb.exe -target <IP or CIDR> | -list <ip list (one per line) -csv <output file>\n");
                Console.WriteLine("[+] Example: \n\n\tSharpScanSmb.exe -target 192.168.10.0/24 -csv myScan.csv\n\tSharpScanSmb.exe -list kekw.txt -csv myScan.csv\n\tSharpScanSmb.exe -list kekw.txt\n");
                Console.WriteLine("[+] Mandatory:\n\n\t -list | target\n\n[+] Optional: \n\n\t-csv, -verbose");
                return;
            }

            List<IPAddress> ipAddresses = new List<IPAddress>();
            string outputFileName = null;
            bool verbose = false;

            if (args[0] == "-target")
            {
                ipAddresses = ParseNetworkInput(args[1]);
            }
            else if (args[0] == "-list")
            {
                ipAddresses = ParseListInput(args[1]);
            }

            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "-csv" && i + 1 < args.Length)
                {
                    outputFileName = args[i + 1];
                    i++;
                }
                else if (args[i] == "-verbose")
                {
                    verbose = true;
                }
            }

            List<ScanResult> results = new List<ScanResult>();

            Parallel.ForEach(ipAddresses, ipAddress =>
            {
                ScanResult result = ScanIPAddress(ipAddress, verbose);
                lock (results)
                {
                    results.Add(result);
                }
            });

            if (outputFileName != null)
            {
                WriteResultsToCsv(results, outputFileName);
                Console.WriteLine("\n[========================================================================]\n");
                Console.WriteLine($"[+] Scan completed. Results saved to {outputFileName}");
                Console.WriteLine($"[+] Bye !\n");
            }
            else
            {
                PrintResults(results);
            }
        }

        //
        // Parse CIDR
        //

        static List<IPAddress> ParseNetworkInput(string input)
        {
            List<IPAddress> ipAddresses = new List<IPAddress>();
            if (input.Contains("/"))
            {
                string[] parts = input.Split('/');
                string baseAddress = parts[0];
                int cidr = int.Parse(parts[1]);

                IPAddress baseIP = IPAddress.Parse(baseAddress);
                uint baseIPUint = BitConverter.ToUInt32(baseIP.GetAddressBytes().Reverse().ToArray(), 0);
                uint mask = uint.MaxValue << (32 - cidr);

                for (uint i = 1; i < ~mask; i++)
                {
                    uint ipUint = (baseIPUint & mask) | i;
                    byte[] ipBytes = BitConverter.GetBytes(ipUint);
                    Array.Reverse(ipBytes);
                    ipAddresses.Add(new IPAddress(ipBytes));
                }
            }
            else
            {
                ipAddresses.Add(IPAddress.Parse(input));
            }
            return ipAddresses;
        }

        static List<IPAddress> ParseListInput(string filePath)
        {
            List<IPAddress> ipAddresses = new List<IPAddress>();
            foreach (var line in File.ReadLines(filePath))
            {
                if (IPAddress.TryParse(line, out IPAddress ipAddress))
                {
                    ipAddresses.Add(ipAddress);
                }
            }
            return ipAddresses;
        }

        //
        // Main Scanner function
        //

        static ScanResult ScanIPAddress(IPAddress ipAddress, bool verbose)
        {
            Console.WriteLine($"[i] Scanning {ipAddress}...");

            bool smb1Ok = false;
            bool smb2Ok = false;
            bool smb2SigningOk = false;

            //
            // Pretty print
            //

            ConsoleColor originalColor = Console.ForegroundColor;

            //
            // Try connecting using SMBv1
            //

            Smb1Client client = new Smb1Client();
            try
            {
                bool Smb1Connected = client.Connect(ipAddress, SMBTransportType.DirectTcpTransport);
                if (Smb1Connected)
                {
                    smb1Ok = true;
                    if (verbose)
                    {
                        Console.WriteLine($"[+] {ipAddress} accepts SMBv1 !");
                    }
                    client.Disconnect();
                }
                else if (verbose)
                {
                    Console.WriteLine($"[!] {ipAddress} does not accept SMBv1 !");
                }
            }
            catch (Exception e)
            {
                if (verbose)
                {
                    Console.WriteLine($"[!] Could not reach {ipAddress}: {e.Message}");
                }
            }

            if (verbose)
            {
                Console.WriteLine($"[i] Now switching to SMB2 for {ipAddress}...");
            }

            //
            // Try connecting using SMBv2
            //

            Smb2Client client2 = new Smb2Client();
            try
            {
                bool Smb2Connected = client2.Connect(ipAddress, SMBTransportType.DirectTcpTransport);
                if (Smb2Connected)
                {
                    smb2Ok = true;
                    if (verbose)
                    {
                        Console.WriteLine($"[+] {ipAddress} accepts SMBv2 !");
                    }

                    bool smb2Signing = client2.IsSigningRequired();
                    smb2SigningOk = smb2Signing;
                    if (smb2Signing && verbose)
                    {
                        Console.WriteLine($"[+] {ipAddress} requires signature !");
                    }
                    else if (!smb2Signing && verbose)
                    {
                        Console.WriteLine($"[+] {ipAddress} does not require signature !");
                    }
                    client2.Disconnect();
                }
                else if (verbose)
                {
                    Console.WriteLine($"[!] {ipAddress} does not accept SMBv2 !");
                }
            }
            catch (Exception e)
            {
                if (verbose)
                {
                    Console.WriteLine($"[!] Could not reach {ipAddress}: {e.Message}");
                }
            }

            //
            // Format results for CSV
            //

            return new ScanResult
            {
                IPAddress = ipAddress.ToString(),
                SMB1Status = smb1Ok ? "ENABLED" : "DISABLED",
                SMB2Status = smb2Ok ? "ENABLED" : "DISABLED",
                SMB2SigningStatus = smb2Ok ? (smb2SigningOk ? "REQUIRED" : "NOT REQUIRED") : "N/A"
            };
        }

        //
        // Create CSV
        // 

        static void WriteResultsToCsv(List<ScanResult> results, string filePath)
        {
            using (var writer = new StreamWriter(filePath))
            {
                writer.WriteLine("IP Address,SMBv1 Status,SMBv2 Status,SMBv2 Signing Status");
                foreach (var result in results)
                {
                    writer.WriteLine($"{result.IPAddress},{result.SMB1Status},{result.SMB2Status},{result.SMB2SigningStatus}");
                }
            }
        }

        //
        // stdout
        //
        static void PrintResults(List<ScanResult> results)
        {
            ConsoleColor originalColor = Console.ForegroundColor;

            Console.WriteLine("\n[========================================================================]\n");

            Console.WriteLine($"{"<IP Address>",-20} {"SMBv1 Status",-15} {"SMBv2 Status",-15} {"SMBv2 Signing Status",-20}");
            

            foreach (var result in results)
            {
                if (result.SMB1Status == "ENABLED")
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                }
                else if (result.SMB1Status == "DISABLED" && result.SMB2SigningStatus == "NOT REQUIRED")
                {
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                }
                else if (result.SMB1Status == "DISABLED" && result.SMB2SigningStatus == "REQUIRED")
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                }
                else
                {
                    Console.ForegroundColor = originalColor; 
                }

                Console.WriteLine($"{result.IPAddress,-20} {result.SMB1Status,-15} {result.SMB2Status,-15} {result.SMB2SigningStatus,-20}");
            }

            Console.ForegroundColor = originalColor;
            Console.WriteLine("\n[========================================================================]\n");
            Console.WriteLine($"[+] Scan completed.");
            Console.WriteLine($"[+] Bye !\n");
            
        }

        //
        // Data structure
        //

        class ScanResult
        {
            public string IPAddress { get; set; }
            public string SMB1Status { get; set; }
            public string SMB2Status { get; set; }
            public string SMB2SigningStatus { get; set; }
        }
    }
}
