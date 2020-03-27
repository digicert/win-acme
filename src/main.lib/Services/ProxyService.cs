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
            if (UseSystemProxy && !useEnvVariableProxy)
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
            _log.Information("SystemProxyStatus:{UseSystemProxy} Envproxystatus:{useEnvVariableProxy}",UseSystemProxy,useEnvVariableProxy);
            if (_proxy == null)
            {
                var proxy = useEnvVariableProxy ? getEnvProxy()
                            :UseSystemProxy ? null :
                                string.IsNullOrEmpty(_settings.Proxy.Url) ? 
                                    new WebProxy() : 
                                    new WebProxy(_settings.Proxy.Url);
                if (proxy != null)
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
                        _log.Information("Proxying via {proxy}:{port}", proxyUrl.Host, proxyUrl.Port);
                    }
                }
                _proxy = proxy;
            }

            return _proxy;
        }

        private IWebProxy getEnvProxy(){
            IWebProxy proxy = new WebProxy(); 
            var httpProxy = Environment.GetEnvironmentVariable("HTTP_PROXY");
                useEnvVariableProxy = !string.IsNullOrEmpty(httpProxy);
                _log.Information("HTTP_PROXY variable is:{httpProxy} and use environment proxy:{useEnvVariableProxy}",httpProxy,useEnvVariableProxy);
                if(useEnvVariableProxy && !string.IsNullOrEmpty(httpProxy)){
                    bool isEnvAuthentication = httpProxy.Contains("@");
                    _log.Information("Creating proxy using HTTP_PROXY variable");
                    var protocol = httpProxy.Substring(0,httpProxy.IndexOf("//")+2);
                    if(isEnvAuthentication){
                        _log.Information("Setting environment authentication parameters");
                        var usernamePassword = httpProxy.Substring(httpProxy.LastIndexOf("//")+2,httpProxy.LastIndexOf("@")-httpProxy.LastIndexOf("//")-2);
                        var username = usernamePassword.Substring(0,usernamePassword.LastIndexOf(":"));
                        var password = usernamePassword.Substring(usernamePassword.LastIndexOf(":")+1,usernamePassword.Length-usernamePassword.LastIndexOf(":")-1);
                        var ipAndPort = httpProxy.Substring(httpProxy.LastIndexOf("@")+1,httpProxy.Length-httpProxy.LastIndexOf("@")-1);
                        proxy = new WebProxy(new Uri(String.Format("{0}{1}",protocol,ipAndPort)));
                        if (!string.IsNullOrWhiteSpace(username)){
                            proxy.Credentials = new NetworkCredential(username,password);
                        }                                              
                    }else{
                        var ipAndPort = httpProxy.Substring(httpProxy.IndexOf("//")+2,httpProxy.Length-httpProxy.IndexOf("//")-2);
                        proxy = new WebProxy(new Uri(String.Format("{0}{1}",protocol,ipAndPort)));
                    
                    }
                }
                return proxy;
        }

    }
}