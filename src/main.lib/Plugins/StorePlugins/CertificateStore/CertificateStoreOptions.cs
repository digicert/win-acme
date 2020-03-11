﻿using PKISharp.WACS.Plugins.Base;
using PKISharp.WACS.Plugins.Base.Options;
using PKISharp.WACS.Services;
using System.Collections.Generic;

namespace PKISharp.WACS.Plugins.StorePlugins
{
    [Plugin("e30adc8e-d756-4e16-a6f2-450f784b1a97")]
    internal class CertificateStoreOptions : StorePluginOptions<CertificateStore>
    {
        internal const string PluginName = "CertificateStore";
        public override string Name => PluginName;
        public override string Description => "Windows Certificate Store";

        /// <summary>
        /// Name of the certificate store to use
        /// </summary>
        public string? StoreName { get; set; }

        /// <summary>
        /// Name of the certificate store to use
        /// </summary>
        public List<string>? AclFullControl { get; set; }

        public override void Show(IInputService input)
        {
            base.Show(input);
            if (!string.IsNullOrEmpty(StoreName))
            {
                input.Show("Store", StoreName, level: 1);
            }
            if (AclFullControl != null)
            {
                input.Show("AclFullControl", string.Join(",", AclFullControl), level: 1);
            }
        }
    }
}
