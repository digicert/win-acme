﻿using Microsoft.Extensions.Configuration;
using PKISharp.WACS.Extensions;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

namespace PKISharp.WACS.Services
{
    public class SettingsService : ISettingsService
    {
        private readonly ILogService _log;
        private readonly IArgumentsService _arguments;

        public bool Valid { get; private set; } = false;
        public ClientSettings Client { get; private set; } = new ClientSettings();
        public UiSettings UI { get; private set; } = new UiSettings();
        public AcmeSettings Acme { get; private set; } = new AcmeSettings();
        public ProxySettings Proxy { get; private set; } = new ProxySettings();
        public CacheSettings Cache { get; private set; } = new CacheSettings();
        public ScheduledTaskSettings ScheduledTask { get; private set; } = new ScheduledTaskSettings();
        public NotificationSettings Notification { get; private set; } = new NotificationSettings();
        public SecuritySettings Security { get; private set; } = new SecuritySettings();
        public ScriptSettings Script { get; private set; } = new ScriptSettings();
        public ValidationSettings Validation { get; private set; } = new ValidationSettings();
        public StoreSettings Store { get; private set; } = new StoreSettings();
        public string ExePath { get; private set; } = Process.GetCurrentProcess().MainModule.FileName;

        public SettingsService(ILogService log, IArgumentsService arguments)
        {
            _log = log;
            _arguments = arguments;

            var installDir = new FileInfo(ExePath).DirectoryName;
            _log.Verbose($"Looking for settings.json in {installDir}");
            var settings = new FileInfo(Path.Combine(installDir, "settings.json"));
            var settingsTemplate = new FileInfo(Path.Combine(installDir, "settings_default.json"));
            if (!settings.Exists && settingsTemplate.Exists)
            {
                _log.Verbose($"Copying settings_default.json to settings.json");
                settingsTemplate.CopyTo(settings.FullName);
            }

            try
            {
                new ConfigurationBuilder()
                    .AddJsonFile(Path.Combine(installDir, "settings.json"), true, true)
                    .Build()
                    .Bind(this);
            }
            catch (Exception ex)
            {
                _log.Error(new Exception("Invalid settings.json", ex), "Unable to start program");
                return;
            }

            CreateConfigPath();
            CreateLogPath();
            CreateCachePath();
            Valid = true;
        }

        public Uri BaseUri
        {
            get
            {
                if (_arguments.MainArguments == null)
                {
                    return Acme.DefaultBaseUri;
                }
                return !string.IsNullOrEmpty(_arguments.MainArguments.BaseUri) ? 
                    new Uri(_arguments.MainArguments.BaseUri) :
                        _arguments.MainArguments.Test ? 
                            Acme.DefaultBaseUriTest : 
                            Acme.DefaultBaseUri;
            }
        }

        public Uri DirectoryUri
        {
            get
            {
                if (_arguments.MainArguments == null)
                {
                    return Acme.DefaultDirectoryUri;
                }
                return !string.IsNullOrEmpty(_arguments.MainArguments.DirectoryUri) ?
                    new Uri(_arguments.MainArguments.DirectoryUri) :
                        _arguments.MainArguments.Test ?
                            Acme.DefaultDirectoryUriTest :
                            Acme.DefaultDirectoryUri;
            }
        }

        /// <summary>
        /// Find and/or create path of the configuration files
        /// </summary>
        /// <param name="arguments"></param>
        private void CreateConfigPath()
        {
            var configRoot = "";
            var userRoot = Client.ConfigurationPath;

            if (!string.IsNullOrEmpty(userRoot))
            {
                configRoot = userRoot;
                // Path configured in settings always wins, but
                // check for possible sub directories with client name
                // to keep bug-compatible with older releases that
                // created a subfolder inside of the users chosen config path
                var configRootWithClient = Path.Combine(userRoot, Client.ClientName);
                if (Directory.Exists(configRootWithClient))
                {
                    configRoot = configRootWithClient;
                }
            }
            else
            {
                // When using a system folder, we have to create a sub folder
                // with the most preferred client name, but we should check first
                // if there is an older folder with an less preferred (older)
                // client name.

                // Stop looking if the directory has been found
                if (!Directory.Exists(configRoot))
                {
                    var appData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                    configRoot = Path.Combine(appData, Client.ClientName);
                }
            }

            // This only happens when invalid options are provided 
            if (!string.IsNullOrEmpty(DirectoryUri.ToString()))
            {
                _log.Debug("Setting config directory path:{}", DirectoryUri.ToString().CleanBaseUri());
                Client.ConfigurationPath = Path.Combine(configRoot, DirectoryUri.ToString().CleanBaseUri());
            }
            else
            {
                Client.ConfigurationPath = Path.Combine(configRoot, BaseUri.ToString().CleanBaseUri());
            }




            // Create folder if it doesn't exist yet
            var di = Directory.CreateDirectory(Client.ConfigurationPath);
            if (!di.Exists)
            {
                try
                {
                    Directory.CreateDirectory(Client.ConfigurationPath);
                } 
                catch (Exception ex)
                {
                    throw new Exception($"Unable to create configuration path {Client.ConfigurationPath}", ex);
                }
            }

            _log.Debug("Config folder: {_configPath}", Client.ConfigurationPath);
        }

        /// <summary>
        /// Find and/or created path of the certificate cache
        /// </summary>
        private void CreateLogPath()
        {
            if (string.IsNullOrWhiteSpace(Client.LogPath))
            {
                Client.LogPath = Path.Combine(Client.ConfigurationPath, "Log");
            }
            if (!Directory.Exists(Client.LogPath))
            {
                try
                {
                    Directory.CreateDirectory(Client.LogPath);
                }
                catch (Exception ex)
                {
                    _log.Error(ex, "Unable to create log directory {_logPath}", Client.LogPath);
                    throw;
                }
            }
            _log.Debug("Log path: {_logPath}", Client.LogPath);
        }

        /// <summary>
        /// Find and/or created path of the certificate cache
        /// </summary>
        private void CreateCachePath()
        {
            if (string.IsNullOrWhiteSpace(Cache.Path))
            {
                Cache.Path = Path.Combine(Client.ConfigurationPath, "Certificates");
            }
            if (!Directory.Exists(Cache.Path))
            {
                try
                {
                    Directory.CreateDirectory(Cache.Path);
                }
                catch (Exception ex)
                {
                    _log.Error(ex, "Unable to create cache path {_certificatePath}", Cache.Path);
                    throw;
                }
            }
            _log.Debug("Cache path: {_certificatePath}", Cache.Path);
        }

        public class ClientSettings
        {
            public string ClientName { get; set; } = "win-acme";
            public string ConfigurationPath { get; set; }
            public string LogPath { get; set; }
        }

        public class UiSettings
        {
            /// <summary>
            /// The number of hosts to display per page.
            /// </summary>
            public int PageSize { get; set; }
            /// <summary>
            /// A string that is used to format the date of the 
            /// pfx file friendly name. Documentation for 
            /// possibilities is available from Microsoft.
            /// </summary>
            public string DateFormat { get; set; }
            /// <summary>
            /// How console tekst should be encoded
            /// </summary>
            public string TextEncoding { get; set; }
        }

        public class AcmeSettings
        {
            /// <summary>
            /// Default ACMEv2 endpoint to use when none 
            /// is specified with the command line.
            /// </summary>
            public Uri DefaultBaseUri { get; set; }
            /// <summary>
            /// Default ACMEv2 endpoint to use when none is specified 
            /// with the command line and the --test switch is
            /// activated.
            /// </summary>
            public Uri DefaultBaseUriTest { get; set; }
            /// <summary>
            /// Default ACMEv1 endpoint to import renewal settings from.
            /// </summary>
            public Uri DefaultBaseUriImport { get; set; }
            /// <summary>
            /// Use POST-as-GET request mode
            /// </summary>
            public bool PostAsGet { get; set; }
            /// <summary>
            /// Number of times wait for the ACME server to 
            /// handle validation and order processing
            /// </summary>
            public int RetryCount { get; set; } = 4;
            /// <summary>
            /// Amount of time (in seconds) to wait each 
            /// retry for the validation handling and order
            /// processing
            /// </summary>
            public int RetryInterval { get; set; } = 2;

            public Uri DefaultDirectoryUri { get; set; }

            public Uri DefaultDirectoryUriTest { get; set; }
        }

        public class ProxySettings
        {
            /// <summary>
            /// Configures a proxy server to use for 
            /// communication with the ACME server. The 
            /// default setting uses the system proxy.
            /// Passing an empty string will bypass the 
            /// system proxy.
            /// </summary>
            public string Url { get; set; }
            /// <summary>
            /// Username used to access the proxy server.
            /// </summary>
            public string Username { get; set; }
            /// <summary>
            /// Password used to access the proxy server.
            /// </summary>
            public string Password { get; set; }
        }

        public class CacheSettings
        {
            /// <summary>
            /// The path where certificates and request files are 
            /// stored. If not specified or invalid, this defaults 
            /// to (ConfigurationPath)\Certificates. All directories
            /// and subdirectories in the specified path are created 
            /// unless they already exist. If you are using a 
            /// [[Central SSL Store|Store-Plugins#centralssl]], this
            /// can not be set to the same path.
            /// </summary>
            public string Path { get; set; }
            /// <summary>
            /// When renewing or re-creating a previously
            /// requested certificate that has the exact 
            /// same set of domain names, the program will 
            /// used a cached version for this many days,
            /// to prevent users from running into rate 
            /// limits while experimenting. Set this to 
            /// a high value if you regularly re-request 
            /// the same certificates, e.g. for a Continuous 
            /// Deployment scenario.
            /// </summary>
            public int ReuseDays { get; set; }
            /// <summary>
            /// Automatically delete files older than 120 days 
            /// from the CertificatePath folder. Running with 
            /// default settings, these should only be long-
            /// expired certificates, generated for abandoned
            /// renewals. However we do advise caution.
            /// </summary>
            public bool DeleteStaleFiles { get; set; }

        }

        public class ScheduledTaskSettings
        {
            /// <summary>
            /// The number of days to renew a certificate 
            /// after. Let’s Encrypt certificates are 
            /// currently for a max of 90 days so it is 
            /// advised to not increase the days much.
            /// If you increase the days, please note
            /// that you will have less time to fix any
            /// issues if the certificate doesn’t renew 
            /// correctly.
            /// </summary>
            public int RenewalDays { get; set; }
            /// <summary>
            /// Configures random time to wait for starting 
            /// the scheduled task.
            /// </summary>
            public TimeSpan RandomDelay { get; set; }
            /// <summary>
            /// Configures start time for the scheduled task.
            /// </summary>
            public TimeSpan StartBoundary { get; set; }
            /// <summary>
            /// Configures time after which the scheduled 
            /// task will be terminated if it hangs for
            /// whatever reason.
            /// </summary>
            public TimeSpan ExecutionTimeLimit { get; set; }
        }

        public class NotificationSettings
        {
            /// <summary>
            /// SMTP server to use for sending email notifications. 
            /// Required to receive renewal failure notifications.
            /// </summary>
            public string SmtpServer { get; set; }
            /// <summary>
            /// SMTP server port number.
            /// </summary>
            public int SmtpPort { get; set; }
            /// <summary>
            /// User name for the SMTP server, in case 
            /// of authenticated SMTP.
            /// </summary>
            public string SmtpUser { get; set; }
            /// <summary>
            /// Password for the SMTP server, in case 
            /// of authenticated SMTP.
            /// </summary>
            public string SmtpPassword { get; set; }
            /// <summary>
            /// Change to True to enable SMTPS.
            /// </summary>
            public bool SmtpSecure { get; set; }
            /// <summary>
            /// Display name to use as the sender of 
            /// notification emails. Defaults to the 
            /// ClientName setting when empty.
            /// </summary>
            public string SenderName { get; set; }
            /// <summary>
            /// Email address to use as the sender 
            /// of notification emails. Required to 
            /// receive renewal failure notifications.
            /// </summary>
            public string SenderAddress { get; set; }
            /// <summary>
            /// Email addresses to receive notification emails. 
            /// Required to receive renewal failure 
            /// notifications.
            /// </summary>
            public List<string> ReceiverAddresses { get; set; }
            /// <summary>
            /// Send an email notification when a certificate 
            /// has been successfully renewed, as opposed to 
            /// the default behavior that only send failure
            /// notifications. Only works if at least 
            /// SmtpServer, SmtpSenderAddressand 
            /// SmtpReceiverAddress have been configured.
            /// </summary>
            public bool EmailOnSuccess { get; set; }
        }

        public class SecuritySettings
        {
            /// <summary>
            /// The key size to sign the certificate with. 
            /// Minimum is 2048.
            /// </summary>
            public int RSAKeyBits { get; set; }
            /// <summary>
            /// The curve to use for EC certificates.
            /// </summary>
            public string ECCurve { get; set; }
            /// <summary>
            /// If set to True, it will be possible to export 
            /// the generated certificates from the certificate 
            /// store, for example to move them to another 
            /// server.
            /// </summary>
            public bool PrivateKeyExportable { get; set; }
            /// <summary>
            /// Uses Microsoft Data Protection API to encrypt 
            /// sensitive parts of the configuration, e.g. 
            /// passwords. This may be disabled to share 
            /// the configuration across a cluster of machines.
            /// </summary>
            public bool EncryptConfig { get; set; }
        }

        /// <summary>
        /// Options for installation and DNS scripts
        /// </summary>
        public class ScriptSettings
        {
            public int Timeout { get; set; } = 600;
        }

        public class ValidationSettings
        {
            /// <summary>
            /// If set to True, it will cleanup the folder structure
            /// and files it creates under the site for authorization.
            /// </summary>
            public bool CleanupFolders { get; set; }
            /// <summary>
            /// If set to `true`, it will wait until it can verify that the 
            /// validation record has been created and is available before 
            /// beginning DNS validation.
            /// </summary>
            public bool PreValidateDns { get; set; } = true;
            /// <summary>
            /// Maximum numbers of times to retry DNS pre-validation, while
            /// waiting for the name servers to start providing the expected
            /// answer.
            /// </summary>
            public int PreValidateDnsRetryCount { get; set; } = 5;
            /// <summary>
            /// Amount of time in seconds to wait between each retry.
            /// </summary>
            public int PreValidateDnsRetryInterval { get; set; } = 30;
            /// <summary>
            /// A comma seperated list of servers to query during DNS 
            /// prevalidation checks to verify whether or not the validation 
            /// record has been properly created and is visible for the world.
            /// These servers will be used to located the actual authoritative 
            /// name servers for the domain. You can use the string [System] to
            /// have the program query your servers default, but note that this 
            /// can lead to prevalidation failures when your Active Directory is 
            /// hosting a private version of the DNS zone for internal use.
            /// </summary>
            public List<string> DnsServers { get; set; }
        }

        public class StoreSettings
        {
            /// <summary>
            /// The certificate store to save the certificates in. If left empty, 
            /// certificates will be installed either in the WebHosting store, 
            /// or if that is not available, the My store (better known as Personal).
            /// </summary>
            public string DefaultCertificateStore { get; set; }
            /// <summary>
            /// When using --store centralssl this path is used by default, saving you
            /// the effort from providing it manually. Filling this out makes the 
            /// --centralsslstore parameter unnecessary in most cases. Renewals 
            /// created with the default path will automatically change to any 
            /// future default value, meaning this is also a good practice for 
            /// maintainability.
            /// </summary>
            public string DefaultCentralSslStore { get; set; }
            /// <summary>
            /// When using --store centralssl this password is used by default for 
            /// the pfx files, saving you the effort from providing it manually. 
            /// Filling this out makes the --pfxpassword parameter unnecessary in 
            /// most cases. Renewals created with the default password will 
            /// automatically change to any future default value, meaning this
            /// is also a good practice for maintainability.
            /// </summary>
            public string DefaultCentralSslPfxPassword { get; set; }
            /// <summary>
            /// When using --store pemfiles this path is used by default, saving 
            /// you the effort from providing it manually. Filling this out makes 
            /// the --pemfilespath parameter unnecessary in most cases. Renewals 
            /// created with the default path will automatically change to any 
            /// future default value, meaning this is also a good practice for 
            /// maintainability.
            /// </summary>
            public string DefaultPemFilesPath { get; set; }
        }
    }
}