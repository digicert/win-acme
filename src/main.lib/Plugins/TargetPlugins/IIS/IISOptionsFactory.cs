﻿using PKISharp.WACS.Clients.IIS;
using PKISharp.WACS.Extensions;
using PKISharp.WACS.Plugins.Base.Factories;
using PKISharp.WACS.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace PKISharp.WACS.Plugins.TargetPlugins
{
    internal class IISOptionsFactory : TargetPluginOptionsFactory<IIS, IISOptions>
    {
        private readonly IISHelper _iisHelper;
        private readonly ILogService _log;
        private readonly IArgumentsService _arguments;

        public IISOptionsFactory(
            ILogService log,
            IIISClient iisClient,
            IISHelper iisHelper,
            IArgumentsService arguments,
            UserRoleService userRoleService)
        {
            _iisHelper = iisHelper;
            _log = log;
            _arguments = arguments;
            Hidden = !(iisClient.Version.Major > 6);
            Disabled = IIS.Disabled(userRoleService);
        }

        public override int Order => 2;

        /// <summary>
        /// Match with the legacy target plugin names
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public override bool Match(string name)
        {
            switch (name.ToLowerInvariant())
            {
                case "iisbinding":
                case "iissite":
                case "iissites":
                    return true;
                default:
                    return base.Match(name);
            }
        }

        /// <summary>
        /// Get settings in interactive mode
        /// </summary>
        /// <param name="input"></param>
        /// <param name="runLevel"></param>
        /// <returns></returns>
        public override async Task<IISOptions?> Aquire(IInputService input, RunLevel runLevel)
        {
            var allSites = _iisHelper.GetSites(true).Where(x => x.Hosts.Any()).ToList();
            if (!allSites.Any())
            {
                _log.Error($"No sites with host bindings have been configured in IIS. " +
                    $"Add one in the IIS Manager or choose the plugin '{ManualOptions.DescriptionText}' " +
                    $"instead.");
                return null;
            }

            var visibleSites = allSites.Where(x => !_arguments.MainArguments.HideHttps || x.Https == false).ToList();
            if (!visibleSites.Any())
            {
                _log.Error("No sites with host bindings remain after applying the --{hidehttps} filter. " +
                    "It looks like all your websites are already configured for https!", "hidehttps");
                return null;
            }

            // Remove sites with only wildcard bindings because they cannot be validated in simple mode
            if (!runLevel.HasFlag(RunLevel.Advanced))
            {
                visibleSites = visibleSites.Where(x => x.Hosts.Any(h => !h.StartsWith("*"))).ToList();
                if (!visibleSites.Any())
                {
                    _log.Error("No sites with host bindings remain after discarding wildcard domains. To " +
                        "create certificates including wildcards, please use the 'Full options' mode, as " +
                        "this requires DNS validation.");
                    return null;
                }
            }

            // Repeat the process until the user is happy with their settings
            do
            {
                var allBindings = _iisHelper.GetBindings();
                var visibleBindings = allBindings.Where(x => !_arguments.MainArguments.HideHttps || x.Https == false).ToList();
                if (!runLevel.HasFlag(RunLevel.Advanced))
                {
                    // Hide bindings with wildcards because they cannot be validated in simple mode
                    visibleBindings = visibleBindings.Where(x => !x.Wildcard).ToList();
                }
                var ret = await TryAquireSettings(input, allBindings, visibleBindings, allSites, visibleSites, runLevel);
                if (ret != null)
                {
                    var filtered = _iisHelper.FilterBindings(allBindings, ret);
                    await ListBindings(input, runLevel, filtered, ret.CommonName);
                    if (await input.PromptYesNo("Continue with this selection?", true))
                    {
                        return ret;
                    }
                }
                if (!await input.PromptYesNo("Restart?", true))
                {
                    return null;
                }
            } 
            while (true);
        }

        /// <summary>
        /// Single round of aquiring settings
        /// </summary>
        /// <param name="input"></param>
        /// <param name="allBindings"></param>
        /// <param name="visibleBindings"></param>
        /// <param name="allSites"></param>
        /// <param name="visibleSites"></param>
        /// <param name="runLevel"></param>
        /// <returns></returns>
        private async Task<IISOptions?> TryAquireSettings(
            IInputService input, 
            List<IISHelper.IISBindingOption> allBindings,
            List<IISHelper.IISBindingOption> visibleBindings,
            List<IISHelper.IISSiteOption> allSites,
            List<IISHelper.IISSiteOption> visibleSites,
            RunLevel runLevel)
        {
            input.Show(null, "Please select which website(s) should be scanned for host names. " +
                "You may input one or more site identifiers (comma separated) to filter by those sites, " +
                "or alternatively leave the input empty to scan *all* websites.", true);

            var options = new IISOptions();
            await input.WritePagedList(
                visibleSites.Select(x => Choice.Create(
                    item: x,
                    description: $"{x.Name} ({x.Hosts.Count()} binding{(x.Hosts.Count() == 1 ? "" : "s")})",
                    command: x.Id.ToString(),
                    color: x.Https ? ConsoleColor.DarkGray : (ConsoleColor?)null)));
            var raw = await input.RequestString("Site identifier(s) or <ENTER> to choose all");
            if (!ParseSiteOptions(raw, allSites, options))
            {
                return null;
            }

            var filtered = _iisHelper.FilterBindings(visibleBindings, options);
            await ListBindings(input, runLevel, filtered);
            input.Show(null, 
                "You may either choose to include all listed bindings as host names in your certificate, " +
                "or apply an additional filter. Different types of filters are available.", true);
            var askExclude = true;
            var filters = new List<Choice<Func<Task>>>
            {
                Choice.Create<Func<Task>>(() => {
                    askExclude = false;
                    return InputHosts(
                        "Include bindings", input, allBindings, filtered, options,
                        () => options.IncludeHosts, x => options.IncludeHosts = x);
                }, "Pick specific bindings from the list"),
                Choice.Create<Func<Task>>(() => {
                    return InputPattern(input, options); 
                }, "Pick bindings based on a search pattern"),
                Choice.Create<Func<Task>>(() => { 
                    askExclude = false; 
                    return Task.CompletedTask; 
                }, "Pick *all* bindings", @default: true)
            };
            if (runLevel.HasFlag(RunLevel.Advanced))
            {
                filters.Insert(2, Choice.Create<Func<Task>>(() => { 
                    askExclude = true; 
                    return InputRegex(input, options);
                }, "Pick bindings based on a regular expression"));
            }
            var chosen = await input.ChooseFromMenu("How do you want to pick the bindings?", filters);
            await chosen.Invoke();
            filtered = _iisHelper.FilterBindings(allBindings, options);

            // Check for wildcards in simple mode
            if (!runLevel.HasFlag(RunLevel.Advanced) && filtered.Any(x => x.Wildcard))
            {
                await ListBindings(input, runLevel, filtered);
                input.Show(null, "The pattern that you've chosen matches a wildcard binding, which " +
                    "is not supported by the 'simple' mode of this program because it requires DNS " +
                    "validation. Please try again with a different pattern or use the 'full options' " +
                    "mode instead.", true);
                return null;
            }

            // Exclude specific bindings
            var listForCommon = false;
            if (askExclude && filtered.Count > 1 && runLevel.HasFlag(RunLevel.Advanced))
            {
                await ListBindings(input, runLevel, filtered);
                input.Show(null, "The listed bindings match your current filter settings. " +
                    "If you wish to exclude one or more of them from the certificate, please " +
                    "input those bindings now. Press <Enter> to include all listed bindings.", true);
                await InputHosts("Exclude bindings", 
                    input, allBindings, filtered, options, 
                    () => options.ExcludeHosts, x => options.ExcludeHosts = x);
                if (options.ExcludeHosts != null)
                {
                    filtered = _iisHelper.FilterBindings(allBindings, options);
                    listForCommon = true;
                }
            } 
            else
            {
                listForCommon = true;
            }

            // Now the common name
            if (filtered.Select(x => x.HostUnicode).Distinct().Count() > 1)
            {
                // If no bindings have been excluded, we can re-use
                // the previously printed list
                if (listForCommon)
                {
                    await ListBindings(input, runLevel, filtered);
                }
                await InputCommonName(input, filtered, options);
            }
            return options;
        }

        /// <summary>
        /// Allows users to input both the full host name, or the number that
        /// it's referred to by in the displayed list
        /// </summary>
        /// <param name="label"></param>
        /// <param name="input"></param>
        /// <param name="allBindings"></param>
        /// <param name="filtered"></param>
        /// <param name="options"></param>
        /// <param name="get"></param>
        /// <param name="set"></param>
        /// <returns></returns>
        async Task InputHosts(
            string label,
            IInputService input,
            List<IISHelper.IISBindingOption> allBindings,
            List<IISHelper.IISBindingOption> filtered, 
            IISOptions options,
            Func<List<string>?> get,
            Action<List<string>> set)
        {
            var sorted = SortBindings(filtered).ToList();
            var raw = default(string);
            do
            {
                raw = await input.RequestString(label);
                if (!string.IsNullOrEmpty(raw))
                {
                    // Magically replace binding identifiers by their proper host names
                    raw = string.Join(",", raw.ParseCsv().Select(x =>
                    {
                        if (int.TryParse(x, out var id))
                        {
                            if (id > 0 && id <= sorted.Count())
                            {
                                return sorted[id - 1].HostUnicode;
                            }
                        }
                        return x;
                    }));
                }
            }
            while (!ParseHostOptions(raw, allBindings, options, get, set));
        }

        async Task InputCommonName(IInputService input, List<IISHelper.IISBindingOption> filtered, IISOptions options)
        {
            var sorted = SortBindings(filtered).ToList();
            string raw;
            do
            {
                input.Show(null, "Please pick the most important host name from the list. " +
                    "This will be displayed to your users as the subject of the certificate.", 
                    true);
                raw = await input.RequestString("Common name");
                if (!string.IsNullOrEmpty(raw))
                {
                    // Magically replace binding identifiers by their proper host names
                    if (int.TryParse(raw, out var id))
                    {
                        if (id > 0 && id <= sorted.Count())
                        {
                            raw = sorted[id - 1].HostUnicode;
                        }
                    }
                }
            }
            while (!ParseCommonName(raw, filtered.Select(x => x.HostUnicode), options));
        }

        /// <summary>
        /// Interactive input of a search pattern
        /// </summary>
        /// <param name="input"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        async Task InputPattern(IInputService input, IISOptions options)
        {
            input.Show(null, IISArgumentsProvider.PatternExamples, true);
            string raw;
            do
            {
                raw = await input.RequestString("Pattern");
            }
            while (!ParsePattern(raw, options));
        }

        async Task InputRegex(IInputService input, IISOptions options)
        {
            string raw;
            do
            {
                raw = await input.RequestString("Regex");
            }
            while (!ParseRegex(raw, options));
        }

        private bool ParsePattern(string? pattern, IISOptions ret)
        {
            if (string.IsNullOrWhiteSpace(pattern))
            {
                _log.Error("Invalid input");
                return false;
            }
            try
            {
                var regexString = pattern.PatternToRegex();
                var actualRegex = new Regex(regexString);
                ret.IncludePattern = pattern;
                return true;
            } 
            catch (Exception ex)
            {
                _log.Error(ex, "Unable to convert pattern to regex");
                return false;
            }
        }


        private bool ParseRegex(string? regex, IISOptions options)
        {
            if (string.IsNullOrWhiteSpace(regex))
            {
                _log.Error("Invalid input");
                return false;
            }
            try
            {
                var actualRegex = new Regex(regex);
                options.IncludeRegex = actualRegex;
                return true;
            }
            catch (Exception ex)
            {
                _log.Error(ex, "Unable to convert pattern to regex");
                return false;
            }
        }

        /// <summary>
        /// We need to use consistent sorting in both listing the bindings and parsing
        /// user input for includes, excludes and common name picking
        /// </summary>
        /// <param name="bindings"></param>
        /// <returns></returns>
        private IEnumerable<IISHelper.IISBindingOption> SortBindings(IEnumerable<IISHelper.IISBindingOption> bindings) => bindings.OrderBy(x => x.HostUnicode).ThenBy(x => x.SiteId);

        /// <summary>
        /// List bindings for the user to pick from
        /// </summary>
        /// <param name="input"></param>
        /// <param name="bindings"></param>
        /// <param name="highlight"></param>
        /// <returns></returns>
        private async Task ListBindings(IInputService input, RunLevel runLevel, List<IISHelper.IISBindingOption> bindings, string? highlight = null)
        {
            var sortedBindings = SortBindings(bindings);
            await input.WritePagedList(
               sortedBindings.Select(x => Choice.Create(
                   item: x,
                   color: BindingColor(x, runLevel, highlight))));
        }

        private ConsoleColor? BindingColor(IISHelper.IISBindingOption binding, RunLevel runLevel, string? highlight = null)
        {
            if (!runLevel.HasFlag(RunLevel.Advanced) && binding.Wildcard)
            {
                return ConsoleColor.Red;
            } 
            else if (binding.HostUnicode == highlight) 
            {
                return ConsoleColor.Green;
            }
            else if (binding.Https)
            {
                return ConsoleColor.DarkGray;
            }
            else
            {
                return default;
            }
        }

        public override async Task<IISOptions?> Default()
        {
            var options = new IISOptions();
            var args = _arguments.GetArguments<IISArguments>();
            if (args == null)
            {
                return null;
            }
            if (string.IsNullOrWhiteSpace(args.Host) && 
                string.IsNullOrWhiteSpace(args.Pattern) &&
                string.IsNullOrWhiteSpace(args.Regex) &&
                string.IsNullOrWhiteSpace(args.SiteId))
            {
                // Logically this would be a no-filter run: all 
                // bindings for all websites. Because the impact
                // of that can be so high, we want the user to
                // be explicit about it.
                _log.Error("You have not specified any filters. If you are sure that you want " +
                    "to create a certificate for *all* bindings on the server, please specific " +
                    "-siteid s");
                return null;
            }

            var allSites = _iisHelper.GetSites(false);
            if (!ParseSiteOptions(args.SiteId, allSites, options))
            {
                return null;
            }

            var allBindings = _iisHelper.GetBindings();
            if (!ParseHostOptions(args.Host, allBindings, options, () => options.IncludeHosts, x => options.IncludeHosts = x))
            {
                return null;
            }

            // Pattern
            if (args.Pattern != null)
            {
                if (options.IncludeHosts != null)
                {
                    _log.Error("Parameters --host and --host-pattern cannot be combined");
                    return null;
                }
                if (!ParsePattern(args.Pattern, options))
                {
                    return null;
                }
            }

            // Regex
            if (args.Regex != null)
            {
                if (options.IncludeHosts != null)
                {
                    _log.Error("Parameters --host and --host-regex cannot be combined");
                    return null;
                }
                if (options.IncludePattern != null)
                {
                    _log.Error("Parameters --host-pattern and --host-regex cannot be combined");
                    return null;
                }
                if (!ParseRegex(args.Regex, options))
                {
                    return null;
                }
            }

            // Excludes
            var filtered = _iisHelper.FilterBindings(allBindings, options);
            if (options.IncludeHosts == null && !string.IsNullOrEmpty(args.ExcludeBindings))
            {
                if (!ParseHostOptions(args.ExcludeBindings, filtered, options, () => options.ExcludeHosts, x => options.ExcludeHosts = x))
                {
                    return null;
                }
                filtered = _iisHelper.FilterBindings(allBindings, options);
            }

            // Common name
            if (args.CommonName != null)
            {
                if (!ParseCommonName(args.CommonName, filtered.Select(x => x.HostUnicode), options))
                {
                    return null;
                }
            }

            return options;
        }

        /// <summary>
        /// Host filtering options in unattended mode
        /// </summary>
        /// <param name="args"></param>
        /// <param name="bindings"></param>
        /// <param name="options"></param>
        private bool ParseHostOptions(
            string? input,
            List<IISHelper.IISBindingOption> allBindings, 
            IISOptions options,
            Func<List<string>?> get,
            Action<List<string>> set)
        {
            var specifiedHosts = input.ParseCsv();
            if (specifiedHosts != null)
            {
                var filteredBindings = _iisHelper.FilterBindings(allBindings, options);
                foreach (var specifiedHost in specifiedHosts)
                {
                    var filteredBinding = filteredBindings.FirstOrDefault(x => x.HostUnicode == specifiedHost || x.HostPunycode == specifiedHost);
                    var binding = allBindings.FirstOrDefault(x => x.HostUnicode == specifiedHost || x.HostPunycode == specifiedHost);
                    if (filteredBinding != null)
                    {
                        var list = get();
                        if (list == null)
                        {
                            list = new List<string>();
                            set(list);
                        }
                        list.Add(filteredBinding.HostUnicode);
                    }
                    else if (binding != null)
                    {
                        _log.Error("Binding {specifiedHost} is excluded by another filter", specifiedHost);
                        return false;
                    }
                    else
                    {
                        _log.Error("Binding {specifiedHost} not found", specifiedHost);
                        return false;
                    }
                }
            }
            return true;
        }

        /// <summary>
        /// Advanced options in unattended mode
        /// </summary>
        /// <param name="args"></param>
        /// <param name="chosen"></param>
        /// <param name="ret"></param>
        /// <returns></returns>
        private bool ParseCommonName(string commonName, IEnumerable<string> chosen, IISOptions ret)
        {
            if (string.IsNullOrWhiteSpace(commonName))
            {
                return false;
            }
            commonName = commonName.ToLower().Trim().ConvertPunycode();
            if (chosen.Contains(commonName))
            {
                ret.CommonName = commonName;
                return true;
            }
            else
            {
                _log.Error("Common name {commonName} not found or excluded", commonName);
                return false;
            }
        }

        /// <summary>
        /// SiteId filter in unattended mode
        /// </summary>
        /// <param name="args"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        private bool ParseSiteOptions(string? input, List<IISHelper.IISSiteOption> sites, IISOptions options)
        {
            if (string.IsNullOrEmpty(input))
            {
                return true;
            }
            if (string.Equals(input, "s", StringComparison.CurrentCultureIgnoreCase))
            {
                return true;
            }

            var identifiers = input.ParseCsv();
            if (identifiers == null)
            {
                throw new InvalidOperationException();
            }

            var ret = new List<long>();
            foreach (var identifierString in identifiers)
            {
                if (long.TryParse(identifierString, out var id))
                {
                    var site = sites.Where(t => t.Id == id).FirstOrDefault();
                    if (site != null)
                    {
                        ret.Add(site.Id);
                    }
                    else
                    {
                        _log.Error("Site identifier '{id}' not found", id);
                        return false;
                    }
                }
                else
                {
                    _log.Error("Invalid site identifier '{identifierString}', should be a number", identifierString);
                    return false;
                }
            }
            options.IncludeSiteIds = ret;
            return true;
        }
    }
}