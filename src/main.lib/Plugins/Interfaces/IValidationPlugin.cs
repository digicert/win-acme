﻿using ACMESharp.Authorizations;
using System;
using System.Threading.Tasks;

namespace PKISharp.WACS.Plugins.Interfaces
{
    /// <summary>
    /// Instance interface
    /// </summary>
    public interface IValidationPlugin : IPlugin
    {
        /// <summary>
        /// Prepare challenge
        /// </summary>
        /// <param name="options"></param>
        /// <param name="target"></param>
        /// <param name="challenge"></param>
        /// <returns></returns>
        Task PrepareChallenge(IChallengeValidationDetails challengeDetails);

        /// <summary>
        /// Clean up after validation attempt
        /// </summary>
       Task CleanUp();
    }
}
