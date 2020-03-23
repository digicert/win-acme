using System;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;

namespace PKISharp.WACS.Services
{
    public class ProxyService
    {
        private readonly ILogService _log;
        private IWebProxy? _proxy;
        private readonly ISettingsService _settings;
        public SslProtocols SslProtocols { get; set; } = SslProtocols.None;

        public ProxyService(ILogService log, ISettingsService settings)
        {
            _log = log;
            _settings = settings;
        }

        /// <summary>
        /// Is the user requesting the system proxy
        /// </summary>
        public bool UseSystemProxy => string.Equals(_settings.Proxy.Url, "[System]", StringComparison.OrdinalIgnoreCase);

        public bool useEnvVariableProxy = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("HTTP_PROXY"));

        /// <summary>
        /// Get prepared HttpClient with correct system proxy settings
        /// </summary>
        /// <returns></returns>
        public HttpClient GetHttpClient(bool checkSsl = true)
        {
            var httpClientHandler = new HttpClientHandler()
            {
                Proxy = GetWebProxy(),
                SslProtocols = SslProtocols
            };
            if (!checkSsl)
            {
                httpClientHandler.ServerCertificateCustomValidationCallback = (a, b, c, d) => true;
            }
            if (UseSystemProxy)
            {
                httpClientHandler.DefaultProxyCredentials = CredentialCache.DefaultCredentials;
            }
            return new HttpClient(httpClientHandler);
        }

        /// <summary>
        /// Get proxy server to use for web requests
        /// </summary>
        /// <returns></returns>
        public IWebProxy? GetWebProxy()
        {
            if (_proxy == null)
            {
                var proxy = UseSystemProxy ? 
                                null : 
                                string.IsNullOrEmpty(_settings.Proxy.Url) ? 
                                    null : 
                                    new WebProxy(_settings.Proxy.Url);

                var httpProxy = Environment.GetEnvironmentVariable("HTTP_PROXY");
                useEnvVariableProxy = !string.IsNullOrEmpty(httpProxy);
                _log.Information("HTTP_PROXY variable is:{httpProxy} and use environment proxy:{useEnvVariableProxy}",httpProxy,useEnvVariableProxy);
                if(null==proxy && useEnvVariableProxy && !string.IsNullOrEmpty(httpProxy)){
                    bool isEnvAuthentication = httpProxy.Contains("@");
                    _log.Information("Creatingproxy using HTTP_PROXY variable");
                    proxy = new WebProxy();
                    if(isEnvAuthentication){
                        _log.Information("Setting environment authentication parameters");
                        var protocol = httpProxy.Substring(0,httpProxy.LastIndexOf("//")+2);
                        var ipAndPort = httpProxy.Substring(httpProxy.LastIndexOf("@")+1,httpProxy.Length-httpProxy.LastIndexOf("@")-1);
                        var usernamePassword = httpProxy.Substring(httpProxy.LastIndexOf("//")+2,httpProxy.LastIndexOf("@")-httpProxy.LastIndexOf("//")-2);
                        var username = usernamePassword.Substring(0,usernamePassword.LastIndexOf(":"));
                        var password = usernamePassword.Substring(usernamePassword.LastIndexOf(":")+1,usernamePassword.Length-usernamePassword.LastIndexOf(":")-1);
                        httpProxy = String.Format("{0}{1}",protocol,ipAndPort);
                        _log.Information("Setting proxy {httpProxy}",httpProxy);
                        if (!string.IsNullOrWhiteSpace(username)){
                            proxy.Credentials = new NetworkCredential(username,password);
                        }                      
                                            
                    }
                    proxy.Address = new Uri(httpProxy);
                    
                }                                    ;
                if (proxy != null && !useEnvVariableProxy)
                {
                    var testUrl = new Uri("http://proxy.example.com");
                    var proxyUrl = proxy.GetProxy(testUrl);

                    if (!string.IsNullOrWhiteSpace(_settings.Proxy.Username))
                    {
                        proxy.Credentials = new NetworkCredential(
                            _settings.Proxy.Username,
                            _settings.Proxy.Password);
                    }

                    var useProxy = !string.Equals(testUrl.Host, proxyUrl.Host);
                    if (useProxy)
                    {
                        _log.Warning("Proxying via {proxy}:{port}", proxyUrl.Host, proxyUrl.Port);
                    }
                }
                if(proxy !=null){
                    _log.Information("Proxy set to:{httpProxy}",proxy.Address.ToString());
                }
                _proxy = proxy;
                                
            }
            return _proxy;
        }

    }
}
