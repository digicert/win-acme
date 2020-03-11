﻿using PKISharp.WACS.DomainObjects;
using PKISharp.WACS.Extensions;
using PKISharp.WACS.Plugins.Interfaces;
using PKISharp.WACS.Services;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace PKISharp.WACS.Plugins.StorePlugins
{
    internal class CentralSsl : IStorePlugin
    {
        private readonly ILogService _log;
        private readonly string _path;
        private readonly string? _password;

        public CentralSsl(ILogService log, ISettingsService settings, CentralSslOptions options)
        {
            _log = log;

            _password = !string.IsNullOrWhiteSpace(options.PfxPassword?.Value) ? 
                options.PfxPassword.Value : 
                settings.Store.DefaultCentralSslPfxPassword;

            var path = !string.IsNullOrWhiteSpace(options.Path) ? 
                options.Path :
                settings.Store.DefaultCentralSslStore;

            if (path != null && path.ValidPath(log))
            {
                _path = path;
                _log.Debug("Using Centralized SSL path: {_path}", _path);
            }
            else
            {
                throw new Exception($"Specified CentralSsl path {path} is not valid.");
            }
        }

        private string PathForIdentifier(string identifier) => Path.Combine(_path, $"{identifier.Replace("*", "_")}.pfx");

        public Task Save(CertificateInfo input)
        {
            _log.Information("Copying certificate to the Central SSL store");
            foreach (var identifier in input.HostNames)
            {
                var dest = PathForIdentifier(identifier);
                _log.Information("Saving certificate to Central SSL location {dest}", dest);
                try
                {
                    var collection = new X509Certificate2Collection();
                    collection.Add(input.Certificate);
                    collection.AddRange(input.Chain.ToArray());
                    File.WriteAllBytes(dest, collection.Export(X509ContentType.Pfx, _password));
                }
                catch (Exception ex)
                {
                    _log.Error(ex, "Error copying certificate to Central SSL store");
                }
            }
            input.StoreInfo.Add(GetType(),
                new StoreInfo()
                {
                    Name = CentralSslOptions.PluginName,
                    Path = _path
                });
            return Task.CompletedTask;
        }

        public Task Delete(CertificateInfo input)
        {
            _log.Information("Removing certificate from the Central SSL store");
            foreach (var identifier in input.HostNames)
            {
                var dest = PathForIdentifier(identifier);
                var fi = new FileInfo(dest);
                var cert = LoadCertificate(fi);
                if (cert != null)
                {
                    if (string.Equals(cert.Thumbprint, input.Certificate.Thumbprint, StringComparison.InvariantCultureIgnoreCase))
                    {
                        fi.Delete();
                    }
                    cert.Dispose();
                }               
            }
            return Task.CompletedTask;
        }

        /// <summary>
        /// Load certificate from disk
        /// </summary>
        /// <param name="fi"></param>
        /// <returns></returns>
        private X509Certificate2? LoadCertificate(FileInfo fi)
        {
            X509Certificate2? cert = null;
            if (!fi.Exists)
            {
                return cert;
            }
            try
            {
                cert = new X509Certificate2(fi.FullName, _password);
            }
            catch (CryptographicException)
            {
                try
                {
                    cert = new X509Certificate2(fi.FullName, "");
                }
                catch
                {
                    _log.Warning("Unable to scan certificate {name}", fi.FullName);
                }
            }
            return cert;
        }

        (bool, string?) IPlugin.Disabled => (false, null);
    }
}
