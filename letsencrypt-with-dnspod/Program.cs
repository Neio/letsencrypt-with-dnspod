using io.nulldata.letsencrypt_with_dnspod.Dnspod;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Security.Cryptography.X509Certificates;
using System.Net;
using System.Security.Principal;
using CommandLine;
using System.Reflection;
using ACMESharp;
using ACMESharp.HTTP;
using ACMESharp.JOSE;
using ACMESharp.PKI;
using System.Security.Cryptography;
using ACMESharp.ACME;
using System.Text;
using System.Threading.Tasks;
using Amazon.Runtime.Internal;
using log4net;

namespace io.nulldata.letsencrypt_with_dnspod
{
    class Program
    {
        private static readonly ILog log = LogManager.GetLogger("/");
        private const string ClientName = "letsencrypt-with-dnspod";
        private static string _certificateStore = "WebHosting";
        public static float RenewalPeriod = 60;
        public static bool CentralSsl = false;
        public static string BaseUri { get; set; }
        private static string _configPath;
        private static string _certificatePath;
        private static AcmeClient _client;
        public static Options Options;
        
        private static void Main(string[] args)
        {
            try
            {
                CertificateProvider.GetProvider();
            }
            catch (Exception ex)
            {
                log.ErrorFormat("Failed when trying to load certificate provider, exception: {0}", ex);
            }
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;

            var commandLineParseResult = Parser.Default.ParseArguments<Options>(args);
            var parsed = commandLineParseResult as Parsed<Options>;
            if (parsed == null)
            {
                log.Debug("Failed to parse options.");
                Console.WriteLine("Press enter to continue.");
                Console.ReadLine();
                return; 
            }

            Options = parsed.Value;
            log.Debug($"{Options}");
            Console.WriteLine("Let's Encrypt (Simple Windows ACME Client)");
            BaseUri = Options.BaseUri;
            if (Options.Test)
            {
                BaseUri = "https://acme-staging.api.letsencrypt.org/";
                log.Debug($"Test paramater set: {BaseUri}");
            }
            if (Options.San)
            {
                log.Debug("San Option Enabled: Running per site and not per host");
            }

            try
            {
                RenewalPeriod = 60;//Properties.Settings.Default.RenewalDays;
                log.Info($"Renewal Period: {RenewalPeriod}");
            }
            catch (Exception ex)
            {
                log.Warn($"Error reading RenewalDays from app config, defaulting to {RenewalPeriod} Error: {ex}");
            }
            try
            {
                _certificateStore = "WebHosting";// Properties.Settings.Default.CertificateStore;
                log.Info($"Certificate Store: {_certificateStore}");
            }
            catch (Exception ex)
            {
                log.Warn($"Error reading CertificateStore from app config, defaulting to {_certificateStore} Error: {ex}");
            }

            Console.WriteLine($"\nACME Server: {BaseUri}");
            log.Info("ACME Server: {BaseUri}");

            if (!string.IsNullOrWhiteSpace(Options.CentralSslStore))
            {
                log.Info($"Using Centralized SSL Path: {Options.CentralSslStore}");
                CentralSsl = true;
            }
            
            _configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), ClientName, CleanFileName(BaseUri));
            log.Info($"Config Folder: {_configPath}");
            Directory.CreateDirectory(_configPath);

            _certificatePath = null;// Properties.Settings.Default.CertificatePath;

            if (string.IsNullOrWhiteSpace(_certificatePath))
            {
                _certificatePath = _configPath;
            }
            else
            {
                try
                {
                    Directory.CreateDirectory(_certificatePath);
                }
                catch (Exception ex)
                {
                    log.Warn($"Error creating the certificate directory, {_certificatePath}. Defaulting to config path. Error: {ex}");
                    _certificatePath = _configPath;
                }
            }

            log.Info("Certificate Folder: " + _certificatePath);

            try
            {
                using (var signer = new RS256Signer())
                {
                    signer.Init();

                    var signerPath = Path.Combine(_configPath, "Signer");
                    if (File.Exists(signerPath))
                    {
                        log.Info($"Loading Signer from {signerPath}");
                        using (var signerStream = File.OpenRead(signerPath))
                            signer.Load(signerStream);
                    }

                    using (_client = new AcmeClient(new Uri(BaseUri), new AcmeServerDirectory(), signer))
                    {
                        _client.Init();
                        log.Info("Getting AcmeServerDirectory");
                        _client.GetDirectory(true);

                        var registrationPath = Path.Combine(_configPath, "Registration");

                        if (File.Exists(registrationPath))
                        {
                            log.Info($"Loading Registration from {registrationPath}");
                            using (var registrationStream = File.OpenRead(registrationPath))
                            {
                                _client.Registration = AcmeRegistration.Load(registrationStream);
                            }
                        }
                        else
                        {
                            Console.Write("Enter an email address (not public, used for renewal fail notices): ");
                            var readLine = Console.ReadLine();
                            if (readLine != null)
                            {
                                var email = readLine.Trim();

                                var contacts = new string[] { };
                                if (!String.IsNullOrEmpty(email))
                                {
                                    log.Info($"Registration email: {email}");
                                    email = "mailto:" + email;
                                    contacts = new string[] { email };
                                }

                                log.Info("Calling Register");
                                var registration = _client.Register(contacts);

                                if (!Options.AcceptTos && !Options.Renew)
                                {
                                    Console.WriteLine($"Do you agree to {registration.TosLinkUri}? (Y/N) ");
                                    if (!PromptYesNo())
                                    {
                                        return;
                                    }
                                }
                            }

                            log.Info("Updating Registration");
                            _client.UpdateRegistration(true, true);

                            log.Info("Saving Registration");
                            using (var registrationStream = File.OpenWrite(registrationPath))
                            {
                                _client.Registration.Save(registrationStream);
                            }

                            log.Info("Saving Signer");
                            using (var signerStream = File.OpenWrite(signerPath))
                            {
                                signer.Save(signerStream);
                            }
                        }

                        if (Options.Renew)
                        {
                            //CheckRenewals();
#if DEBUG
                            Console.WriteLine("Press enter to continue.");
                            Console.ReadLine();
#endif
                            return;
                        }

                        var targets = new List<Target>();
                        var domain = System.Configuration.ConfigurationManager.AppSettings["DefaultDomain"];
                        var subDomains = System.Configuration.ConfigurationManager.AppSettings["DefaultSecondaryDomains"];
                        if (!string.IsNullOrEmpty(subDomains) && !string.IsNullOrEmpty(domain))
                        {
                            targets.Add(new Target
                            {
                                Host = domain,
                                AlternativeNames = subDomains.Split('|').ToList()
                            });
                        }
                        targets.ForEach(o => o.AlternativeNames = o.AlternativeNames.Select(x => x + "." + o.Host).ToList());

                        if (!targets.Any() && string.IsNullOrEmpty(Options.ManualHost))
                        {
                            Console.WriteLine("No targets found.");
                            log.Error("No targets found.");
                        }
                        else
                        {
                            var count = 1;
                            
                            foreach (var binding in targets)
                            {
                                if (!Options.San)
                                {
                                    Console.WriteLine($" {count}: {binding}");
                                }
                                else
                                {
                                    Console.WriteLine($" {binding.Host}: SAN - {binding}");
                                }
                                count++;
                            }
                        }


                        Console.WriteLine();

                        if (targets.Any() && string.IsNullOrEmpty(Options.ManualHost))
                        {
                            Console.WriteLine(" A: Get certificates for all hosts");
                            Console.WriteLine(" Q: Quit");
                            Console.Write("Which host do you want to get a certificate for: ");
                            var response = Console.ReadLine().ToLowerInvariant();
                            switch (response)
                            {
                                case "a":
                                    foreach (var target in targets)
                                    {
                                        Auto(target).Wait();
                                    }
                                    break;
                                case "q":
                                    return;
                                default:
                                    break;
                            }
                        }
                        else
                        {
                            Console.Write("Please input the FQDN which you want to request a certificate:");
                            var response = Console.ReadLine().ToLowerInvariant();
                            if (!response.Contains('.'))
                            {
                                log.WarnFormat("Invalid domain name");
                            }
                            else
                            {
                                var parts = response.Split('.');
                                if (parts.Length <= 2)
                                {
                                    log.WarnFormat("Please specify secondary domain.");
                                }
                                else
                                {
                                    var domainName = string.Join(".", parts.Skip(parts.Length - 2));
                                    log.DebugFormat($"Domain is {domainName}");
                                    Auto(new Target() { Host = domainName, AlternativeNames = new AutoConstructedList<string>() { response } }).Wait();
                                }
                            }
                            
                        }
                    }
                }
            }
            catch (Exception e)
            {
                log.Error("Error {@e}", e);
                Console.ForegroundColor = ConsoleColor.Red;
                var acmeWebException = e as AcmeClient.AcmeWebException;
                if (acmeWebException != null)
                {
                    Console.WriteLine(acmeWebException.Message);
                    Console.WriteLine("ACME Server Returned:");
                    Console.WriteLine(acmeWebException.Response.ContentAsString);
                }
                else
                {
                    Console.WriteLine(e);
                }
                Console.ResetColor();
            }

            Console.WriteLine("Press enter to continue.");
            Console.ReadLine();
        }

        private static string CleanFileName(string fileName) => Path.GetInvalidFileNameChars().Aggregate(fileName, (current, c) => current.Replace(c.ToString(), string.Empty));

        public static bool PromptYesNo()
        {
            while (true)
            {
                var response = Console.ReadKey(true);
                if (response.Key == ConsoleKey.Y) return true;
                if (response.Key == ConsoleKey.N) return false;
                Console.WriteLine("Please press Y or N.");
            }
        }

        private static async Task Auto(Target binding)
        {
            var auth = await Authorize(binding);
            if (auth?.Status == "valid")
            {
                var pfxFilename = GetCertificate(binding);

                if (Options.Test && !Options.Renew)
                {
                    Console.WriteLine($"\nDo you want to install the .pfx into the Certificate Store/ Central SSL Store? (Y/N) ");

                    if (!PromptYesNo()) return;
                }

                if (!CentralSsl)
                {
                    X509Store store;
                    X509Certificate2 certificate;
                    log.Info("Installing Non-Central SSL Certificate in the certificate store");
                    InstallCertificate(binding, pfxFilename, out store, out certificate);
                    if (Options.Test && !Options.Renew)
                    {
                        Console.WriteLine($"\nDo you want to add/update the certificate to your server software? (Y/N) ");
                        if (!PromptYesNo()) return;
                    }
                    log.Info("Installing Non-Central SSL Certificate in server software");
                    //binding.Plugin.Install(binding, pfxFilename, store, certificate);
                    if (!Options.KeepExisting)
                    {
                        UninstallCertificate(binding.Host, out store, certificate);
                    }
                }
                else if (!Options.Renew || !Options.KeepExisting)
                {
                    //If it is using centralized SSL, renewing, and replacing existing it needs to replace the existing binding.
                    log.Info("Updating new Central SSL Certificate");
                    //binding.Plugin.Install(binding);
                }

                if (Options.Test && !Options.Renew)
                {
                    Console.WriteLine($"\nDo you want to automatically renew this certificate in {RenewalPeriod} days? This will add a task scheduler task. (Y/N) ");
                    if (!PromptYesNo())return;
                }

                if (!Options.Renew)
                {
                    log.Info($"Adding renewal for {binding}");
                    //ScheduleRenewal(binding);
                }
            }
        }

        public static void InstallCertificate(Target binding, string pfxFilename, out X509Store store, out X509Certificate2 certificate)
        {
            try
            {
                store = new X509Store(_certificateStore, StoreLocation.LocalMachine);
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
            }
            catch (CryptographicException)
            {
                store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
            }
            catch (Exception ex)
            {
                log.Error("Error encountered while opening certificate store. Error: {@ex}", ex);
                throw new Exception(ex.Message);
            }

            log.Info($" Opened Certificate Store \"{store.Name}\"");
            certificate = null;
            try
            {
                // See http://paulstovell.com/blog/x509certificate2
                certificate = new X509Certificate2(pfxFilename, "hello",
                    X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet |
                    X509KeyStorageFlags.Exportable);

                certificate.FriendlyName =
                    $"{binding.Host} {DateTime.Now.ToString("yyyy-MM-dd HHmmss")}";
                log.Debug($"{certificate.FriendlyName}");

                log.Info($" Adding Certificate to Store");
                store.Add(certificate);

                log.Info($" Closing Certificate Store");
            }
            catch (Exception ex)
            {
                log.Error($"Error saving certificate {ex}");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error saving certificate: {ex.Message.ToString()}");
                Console.ResetColor();
            }
            store.Close();
        }

        public static void UninstallCertificate(string host, out X509Store store, X509Certificate2 certificate)
        {
            try
            {
                store = new X509Store(_certificateStore, StoreLocation.LocalMachine);
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
            }
            catch (CryptographicException)
            {
                store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
            }
            catch (Exception ex)
            {
                log.Error("Error encountered while opening certificate store. Error: {@ex}", ex);
                throw new Exception(ex.Message);
            }

            log.Info($" Opened Certificate Store \"{store.Name}\"");
            try
            {
                X509Certificate2Collection col = store.Certificates.Find(X509FindType.FindBySubjectName, host, false);

                foreach (var cert in col)
                {
                    var subjectName = cert.Subject.Split(',');

                    if (cert.FriendlyName != certificate.FriendlyName && subjectName[1] == " CN=" + host)
                    {
                        log.Info($" Removing Certificate from Store {cert.FriendlyName}");
                        store.Remove(cert);
                    }
                }

                log.Info($" Closing Certificate Store");
            }
            catch (Exception ex)
            {
                log.Error($"Error removing certificate: {ex.Message.ToString()}");
                Console.ResetColor();
            }
            store.Close();
        }

        public static string GetCertificate(Target binding)
        {
            var dnsIdentifier = binding.Host;
            var sanList = binding.AlternativeNames;
            List<string> allDnsIdentifiers = new List<string>();

            //if (!Options.San)
            //{
            //    allDnsIdentifiers.Add(binding.Host);
            //}
            if (binding.AlternativeNames != null)
            {
                allDnsIdentifiers.AddRange(binding.AlternativeNames);
            }

            var cp = CertificateProvider.GetProvider();
            var rsaPkp = new RsaPrivateKeyParams();
            try
            {

                rsaPkp.NumBits = 2048;
                log.Debug($"RSAKeyBits: { rsaPkp.NumBits}");
            }
            catch (Exception ex)
            {
                log.Warn($"Unable to set RSA Key Bits, Letting ACMESharp default key bits, Error: {ex}");
            }

            var rsaKeys = cp.GeneratePrivateKey(rsaPkp);
            var csrDetails = new CsrDetails
            {
                CommonName = allDnsIdentifiers[0],
            };
            if (sanList != null)
            {
                if (sanList.Count > 0)
                {
                    csrDetails.AlternativeNames = sanList;
                }
            }
            var csrParams = new CsrParams
            {
                Details = csrDetails,
            };
            var csr = cp.GenerateCsr(csrParams, rsaKeys, Crt.MessageDigest.SHA256);

            byte[] derRaw;
            using (var bs = new MemoryStream())
            {
                cp.ExportCsr(csr, EncodingFormat.DER, bs);
                derRaw = bs.ToArray();
            }
            var derB64U = JwsHelper.Base64UrlEncode(derRaw);

            log.Info("Requesting Certificate");
            var certRequ = _client.RequestCertificate(derB64U);

            log.Debug($"certRequ {certRequ}");

            log.Info($" Request Status: {certRequ.StatusCode}");

            if (certRequ.StatusCode == System.Net.HttpStatusCode.Created)
            {
                var keyGenFile = Path.Combine(_certificatePath, $"{dnsIdentifier}-gen-key.json");
                var keyPemFile = Path.Combine(_certificatePath, $"{dnsIdentifier}-key.pem");
                var csrGenFile = Path.Combine(_certificatePath, $"{dnsIdentifier}-gen-csr.json");
                var csrPemFile = Path.Combine(_certificatePath, $"{dnsIdentifier}-csr.pem");
                var crtDerFile = Path.Combine(_certificatePath, $"{dnsIdentifier}-crt.der");
                var crtPemFile = Path.Combine(_certificatePath, $"{dnsIdentifier}-crt.pem");
                string crtPfxFile = null;
                if (!CentralSsl)
                {
                    crtPfxFile = Path.Combine(_certificatePath, $"{dnsIdentifier}-all.pfx");
                }
                else
                {
                    crtPfxFile = Path.Combine(Options.CentralSslStore, $"{dnsIdentifier}.pfx");
                }

                using (var fs = new FileStream(keyGenFile, FileMode.Create))
                    cp.SavePrivateKey(rsaKeys, fs);
                using (var fs = new FileStream(keyPemFile, FileMode.Create))
                    cp.ExportPrivateKey(rsaKeys, EncodingFormat.PEM, fs);
                using (var fs = new FileStream(csrGenFile, FileMode.Create))
                    cp.SaveCsr(csr, fs);
                using (var fs = new FileStream(csrPemFile, FileMode.Create))
                    cp.ExportCsr(csr, EncodingFormat.PEM, fs);

                log.Info($" Saving Certificate to {crtDerFile}");
                using (var file = File.Create(crtDerFile))
                    certRequ.SaveCertificate(file);

                Crt crt;
                using (FileStream source = new FileStream(crtDerFile, FileMode.Open),
                    target = new FileStream(crtPemFile, FileMode.Create))
                {
                    crt = cp.ImportCertificate(EncodingFormat.DER, source);
                    cp.ExportCertificate(crt, EncodingFormat.PEM, target);
                }

                // To generate a PKCS#12 (.PFX) file, we need the issuer's public certificate
                var isuPemFile = GetIssuerCertificate(certRequ, cp);

                log.Debug($"CentralSsl {CentralSsl} San {Options.San}");

                if (CentralSsl && Options.San)
                {
                    foreach (var host in allDnsIdentifiers)
                    {
                        Console.WriteLine($"Host: {host}");
                        crtPfxFile = Path.Combine(Options.CentralSslStore, $"{host}.pfx");

                        log.Info($" Saving Certificate to {crtPfxFile}");
                        using (FileStream source = new FileStream(isuPemFile, FileMode.Open),
                            target = new FileStream(crtPfxFile, FileMode.Create))
                        {
                            try
                            {
                                var isuCrt = cp.ImportCertificate(EncodingFormat.PEM, source);
                                cp.ExportArchive(rsaKeys, new[] { crt, isuCrt }, ArchiveFormat.PKCS12, target,
                                    "hello");
                            }
                            catch (Exception ex)
                            {
                                log.Error("Error exporting archive {@ex}", ex);
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine($"Error exporting archive: {ex.Message.ToString()}");
                                Console.ResetColor();
                            }
                        }
                    }
                }
                else //Central SSL and San need to save the cert for each hostname
                {
                    log.Info($" Saving Certificate to {crtPfxFile}");
                    using (FileStream source = new FileStream(isuPemFile, FileMode.Open),
                        target = new FileStream(crtPfxFile, FileMode.Create))
                    {
                        try
                        {
                            var isuCrt = cp.ImportCertificate(EncodingFormat.PEM, source);
                            cp.ExportArchive(rsaKeys, new[] { crt, isuCrt }, ArchiveFormat.PKCS12, target,
                               "hello");
                        }
                        catch (Exception ex)
                        {
                            log.Error("Error exporting archive {@ex}", ex);
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"Error exporting archive: {ex.Message.ToString()}");
                            Console.ResetColor();
                        }
                    }
                }

                cp.Dispose();

                return crtPfxFile;
            }
            log.Error($"Request status = {certRequ.StatusCode}");
            throw new Exception($"Request status = {certRequ.StatusCode}");
        }


        public static string GetIssuerCertificate(CertificateRequest certificate, CertificateProvider cp)
        {
            var linksEnum = certificate.Links;
            if (linksEnum != null)
            {
                var links = new LinkCollection(linksEnum);
                var upLink = links.GetFirstOrDefault("up");
                if (upLink != null)
                {
                    var tmp = Path.GetTempFileName();
                    try
                    {
                        using (var web = new WebClient())
                        {
                            var uri = new Uri(new Uri(BaseUri), upLink.Uri);
                            web.DownloadFile(uri, tmp);
                        }

                        var cacert = new X509Certificate2(tmp);
                        var sernum = cacert.GetSerialNumberString();

                        var cacertDerFile = Path.Combine(_certificatePath, $"ca-{sernum}-crt.der");
                        var cacertPemFile = Path.Combine(_certificatePath, $"ca-{sernum}-crt.pem");

                        if (!File.Exists(cacertDerFile))
                            File.Copy(tmp, cacertDerFile, true);

                        log.Info($" Saving Issuer Certificate to {cacertPemFile}");
                        if (!File.Exists(cacertPemFile))
                            using (FileStream source = new FileStream(cacertDerFile, FileMode.Open),
                                target = new FileStream(cacertPemFile, FileMode.Create))
                            {
                                var caCrt = cp.ImportCertificate(EncodingFormat.DER, source);
                                cp.ExportCertificate(caCrt, EncodingFormat.PEM, target);
                            }

                        return cacertPemFile;
                    }
                    finally
                    {
                        if (File.Exists(tmp))
                            File.Delete(tmp);
                    }
                }
            }

            return null;
        }

        public static async Task<AuthorizationState> Authorize(Target target)
        {
            DnspodApi api = new DnspodApi(Options.DnspodToken);
            var domainList = await api.Domain.List();
            var domains = domainList?.domains;
            if (domains == null)
            {
                log.Error("dnspod token error");
                return null;
            }

            var domain = domains.FirstOrDefault(o => o.name.ToLower() == target.Host.ToLower());
            if (domain == null)
            {
                log.Error($"can't found: {target.Host}");
                return null;
            }

            var records = (await api.Record.List(domain.id))?.records;
            
            List<string> dnsIdentifiers = new List<string>();
            if (!Options.San)
            {
                dnsIdentifiers.Add(target.Host);
            }
            if (target.AlternativeNames != null)
            {
                dnsIdentifiers.AddRange(target.AlternativeNames);
            }
            var authStatus = new List<Tuple<AuthorizationState, DnsChallenge, AuthorizeChallenge, int>>();
            var authResult = new List<AuthorizationState>();
            
            foreach (var dnsIdentifier in dnsIdentifiers)
            {
                log.Info($"\nAuthorizing Identifier {dnsIdentifier} Using Challenge Type {AcmeProtocol.CHALLENGE_TYPE_DNS}");

                var authzState = _client.AuthorizeIdentifier(dnsIdentifier);
                var challenge = _client.DecodeChallenge(authzState, AcmeProtocol.CHALLENGE_TYPE_DNS);
                var dnsChallenge = challenge.Challenge as DnsChallenge;

                // We need to strip off any leading '/' in the path
                var name = dnsChallenge.RecordName.Substring(0, dnsChallenge.RecordName.Length - 1 - target.Host.Length);
                var record = records?.FirstOrDefault(o => o.name.ToLower() == name.ToLower());
                int rid;
                if (record == null)
                {
                    var r = await api.Record.Create(domain.id, name, dnsChallenge.RecordValue);
                    rid = r.record.id;
                }
                else
                {
                    var r = await api.Record.Modify(domain.id, record.id, name, dnsChallenge.RecordValue);
                    rid = r.record.id;
                }
                authStatus.Add(Tuple.Create(authzState, dnsChallenge, challenge, rid));
            }
            foreach (var item in authStatus.ToList())
            {
                var dnsChallenge = item.Item2;
                var authzState = item.Item1;
                var challenge = item.Item3;
                var rid = item.Item4;

                while (DnspodApi.DnsGetTxtRecord(dnsChallenge.RecordName) != dnsChallenge.RecordValue)
                {
                    log.Info($" Waiting Txt Record {dnsChallenge.RecordName}...");
                    await Task.Delay(10000);
                }

                log.Info($" Answer should now be browsable at {dnsChallenge.RecordName}");

                try
                {
                    log.Info(" Submitting answer");
                    authzState.Challenges = new AuthorizeChallenge[] { challenge };
                    _client.SubmitChallengeAnswer(authzState, AcmeProtocol.CHALLENGE_TYPE_DNS, true);

                    // have to loop to wait for server to stop being pending.
                    // TODO: put timeout/retry limit in this loop
                    while (authzState.Status == "pending")
                    {
                        log.Info(" Refreshing authorization");
                        await Task.Delay(4000); // this has to be here to give ACME server a chance to think
                        var newAuthzState = _client.RefreshIdentifierAuthorization(authzState);
                        if (newAuthzState.Status != "pending")
                        {
                            authzState = newAuthzState;
                        }
                    }
                    authResult.Add(authzState);
                    log.Info($" Authorization Result: {authzState.Status}");
                    if (authzState.Status == "invalid")
                    {
                        log.Error($"Authorization Failed {authzState.Status}");

                        Console.WriteLine("\n******************************************************************************");
                        Console.ResetColor();
                    }
                }
                finally
                {
                    if (authzState.Status == "valid")
                    {
                        //api.Record.Modify()
                    }
                    await api.Record.Remove(domain.id, rid);
                }
            }

            foreach (var authState in authResult)
            {
                if (authState.Status != "valid")
                {
                    return authState;
                }
            }
            return new AuthorizationState { Status = "valid" };
        }

        // Replaces the characters of the typed in password with asterisks
        // More info: http://rajeshbailwal.blogspot.com/2012/03/password-in-c-console-application.html
        private static String ReadPassword()
        {
            var password = new StringBuilder();
            try
            {
                ConsoleKeyInfo info = Console.ReadKey(true);
                while (info.Key != ConsoleKey.Enter)
                {
                    if (info.Key != ConsoleKey.Backspace)
                    {
                        Console.Write("*");
                        password.Append(info.KeyChar);
                    }
                    else if (info.Key == ConsoleKey.Backspace)
                    {
                        if (password != null)
                        {
                            // remove one character from the list of password characters
                            password.Remove(password.Length - 1, 1);
                            // get the location of the cursor
                            int pos = Console.CursorLeft;
                            // move the cursor to the left by one character
                            Console.SetCursorPosition(pos - 1, Console.CursorTop);
                            // replace it with space
                            Console.Write(" ");
                            // move the cursor to the left by one character again
                            Console.SetCursorPosition(pos - 1, Console.CursorTop);
                        }
                    }
                    info = Console.ReadKey(true);
                }
                // add a new line because user pressed enter at the end of their password
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error Reading Password {ex.Message}");
                log.Error("Error Reading Password: {@ex}", ex);
            }

            return password.ToString();
        }
    }
}
