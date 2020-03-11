﻿using PKISharp.WACS.Plugins.Base.Options;
using PKISharp.WACS.Services;
using System.Threading.Tasks;

namespace PKISharp.WACS.Plugins.Interfaces
{
    public interface ICsrPluginOptionsFactory : IPluginOptionsFactory
    {
        /// <summary>
        /// Check or get information needed for store (interactive)
        /// </summary>
        /// <param name="target"></param>
        Task<CsrPluginOptions?> Aquire(IInputService inputService, RunLevel runLevel);

        /// <summary>
        /// Check information needed for store (unattended)
        /// </summary>
        /// <param name="target"></param>
        Task<CsrPluginOptions?> Default();
    }
}
