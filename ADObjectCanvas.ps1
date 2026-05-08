<#
================================================================================
  ADObjectCanvas -- The Complete Picture of Every Object in Your AD
  Version: 1.5
  Author : Santhosh Sivarajan, Microsoft MVP
  Email  : santhosh@sivarajan.com

  Purpose: Generates a single self-contained HTML inventory report of every
           object class in an Active Directory forest. Answers the question
           "What is actually in my AD?" with a per-domain object class
           census, drill-downs for users / computers / groups / OUs / GPOs /
           service accounts / containers / DNS zones / password policies /
           trusts, and forest-wide charts.

  License: MIT -- Free to use, modify, and distribute.
  GitHub : https://github.com/SanthoshSivarajan/ADObjectCanvas
================================================================================
#>

#Requires -Modules ActiveDirectory

param(
    [Parameter(Mandatory=$false, HelpMessage="Folder where the HTML report will be written. Defaults to the script directory.")]
    [string]$OutputPath
)

# Resolve default OutputPath. $PSScriptRoot can occasionally be empty at
# param-default-binding time (notably in Windows PowerShell 5.1 when the
# script path contains spaces), so we resolve here in the script body
# rather than as a param default.
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $OutputPath = $PSScriptRoot
    } elseif ($MyInvocation.MyCommand -and $MyInvocation.MyCommand.Path) {
        $OutputPath = Split-Path -LiteralPath $MyInvocation.MyCommand.Path -Parent
    } else {
        $OutputPath = (Get-Location).Path
    }
}

if (-not (Test-Path -LiteralPath $OutputPath)) {
    try {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    } catch {
        Write-Host "  [!] Could not create output directory '$OutputPath': $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

$ReportDate = Get-Date -Format "yyyy-MM-dd_HHmmss"
$OutputFile = Join-Path -Path $OutputPath -ChildPath "ADObjectCanvas_$ReportDate.html"

Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host "  |                                                            |" -ForegroundColor Cyan
Write-Host "  |   ADObjectCanvas -- AD Object Inventory Tool v1.5          |" -ForegroundColor Cyan
Write-Host "  |                                                            |" -ForegroundColor Cyan
Write-Host "  |   Author : Santhosh Sivarajan, Microsoft MVP               |" -ForegroundColor Cyan
Write-Host "  |   Email  : santhosh@sivarajan.com                          |" -ForegroundColor Cyan
Write-Host "  |   Web    : github.com/SanthoshSivarajan/ADObjectCanvas     |" -ForegroundColor Cyan
Write-Host "  |                                                            |" -ForegroundColor Cyan
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host ""
Write-Host "  [*] Target Domain : $((Get-ADDomain).DNSRoot)" -ForegroundColor White
Write-Host "  [*] Running As    : $($env:USERDOMAIN)\$($env:USERNAME)" -ForegroundColor White
Write-Host "  [*] Timestamp     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host ""
Write-Host "  Collecting AD object inventory ..." -ForegroundColor Yellow
Write-Host ""

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================
Add-Type -AssemblyName System.Web
function HtmlEncode($s) { if ($null -eq $s) { return "--" }; return [System.Web.HttpUtility]::HtmlEncode([string]$s) }

function ConvertTo-HtmlTable {
    param([Parameter(Mandatory)]$Data,[string[]]$Properties)
    if (-not $Data -or @($Data).Count -eq 0) { return '<p class="empty-note">No data found.</p>' }
    $rows = @($Data)
    if (-not $Properties) { $Properties = ($rows[0].PSObject.Properties).Name }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<div class="table-wrap"><table><thead><tr>')
    foreach ($p in $Properties) { [void]$sb.Append("<th>$(HtmlEncode $p)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $rows) {
        [void]$sb.Append('<tr>')
        foreach ($p in $Properties) {
            $v = $r.$p
            if ($v -is [array]) { $v = ($v | ForEach-Object { [string]$_ }) -join ', ' }
            [void]$sb.Append("<td>$(HtmlEncode $v)</td>")
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    return $sb.ToString()
}

function Get-FriendlyClassName($cls) {
    $map = @{
        # ----- Identity -----
        'user'                                  = 'User'
        'computer'                              = 'Computer'
        'group'                                 = 'Group'
        'inetOrgPerson'                         = 'inetOrgPerson'
        'contact'                               = 'Contact'
        'foreignSecurityPrincipal'              = 'Foreign Security Principal'
        # ----- Service Accounts -----
        'msDS-GroupManagedServiceAccount'       = 'gMSA'
        'msDS-ManagedServiceAccount'            = 'sMSA'
        'msDS-DelegatedManagedServiceAccount'   = 'dMSA'
        # ----- Structure -----
        'organizationalUnit'                    = 'Organizational Unit'
        'container'                             = 'Container'
        'builtinDomain'                         = 'Builtin Container'
        'domainDNS'                             = 'Domain Root'
        'lostAndFound'                          = 'Lost And Found'
        'msDS-QuotaContainer'                   = 'Quota Container'
        # ----- Policy -----
        'groupPolicyContainer'                  = 'Group Policy Object'
        'msDS-PasswordSettings'                 = 'Fine-Grained Password Policy'
        'msDS-PasswordSettingsContainer'        = 'Password Settings Container'
        'domainPolicy'                          = 'Domain Policy (Legacy)'
        # ----- Resources -----
        'printQueue'                            = 'Printer (Print Queue)'
        'serviceConnectionPoint'                = 'Service Connection Point'
        'volume'                                = 'Volume / Shared Folder'
        # ----- PKI -----
        'pKICertificateTemplate'                = 'PKI Certificate Template'
        'pKIEnrollmentService'                  = 'Certificate Authority'
        'msPKI-Enterprise-Oid'                  = 'PKI Enterprise OID'
        # ----- Security -----
        'msFVE-RecoveryInformation'             = 'BitLocker Recovery Object'
        'secret'                                = 'LSA Secret'
        # ----- Trust -----
        'trustedDomain'                         = 'Trusted Domain'
        # ----- DNS -----
        'dnsNode'                               = 'DNS Record'
        'dnsZone'                               = 'DNS Zone'
        # ----- Replication (DFSR + DFS + NTFRS) -----
        'msDFSR-LocalSettings'                  = 'DFSR Local Settings'
        'msDFSR-Subscriber'                     = 'DFSR Subscriber'
        'msDFSR-Subscription'                   = 'DFSR Subscription'
        'msDFSR-Member'                         = 'DFSR Member'
        'msDFSR-ContentSet'                     = 'DFSR Content Set'
        'msDFSR-Content'                        = 'DFSR Content'
        'msDFSR-Topology'                       = 'DFSR Topology'
        'msDFSR-ReplicationGroup'               = 'DFSR Replication Group'
        'msDFSR-GlobalSettings'                 = 'DFSR Global Settings'
        'dfsConfiguration'                      = 'DFS Configuration'
        'nTFRSSettings'                         = 'NTFRS Settings (Legacy)'
        'nTFRSReplicaSet'                       = 'NTFRS Replica Set (Legacy)'
        'nTFRSSubscriber'                       = 'NTFRS Subscriber (Legacy)'
        'nTFRSSubscriptions'                    = 'NTFRS Subscriptions (Legacy)'
        'nTFRSMember'                           = 'NTFRS Member (Legacy)'
        # ----- IPSec -----
        'ipsecPolicy'                           = 'IPSec Policy'
        'ipsecNegotiationPolicy'                = 'IPSec Negotiation Policy'
        'ipsecISAKMPPolicy'                     = 'IPSec ISAKMP Policy'
        'ipsecFilter'                           = 'IPSec Filter'
        'ipsecNFA'                              = 'IPSec NFA Policy'
        # ----- Exchange -----
        'msExchSystemObjectsContainer'          = 'Exchange System Objects'
        'msExchActiveSyncDevice'                = 'Exchange ActiveSync Device'
        # ----- System / Plumbing -----
        'rIDSet'                                = 'RID Set'
        'rIDManager'                            = 'RID Manager'
        'samServer'                             = 'SAM Server'
        'linkTrackVolumeTable'                  = 'Link Tracking Volume Table'
        'linkTrackObjectMoveTable'              = 'Link Tracking Move Table'
        'fileLinkTracking'                      = 'File Link Tracking'
        'rpcContainer'                          = 'RPC Container'
        'classStore'                            = 'Class Store'
        'infrastructureUpdate'                  = 'Infrastructure Object'
        'msTPM-InformationObjectsContainer'     = 'TPM Information Container'
        'msTPM-InformationObject'               = 'TPM Information Object'
        'msImaging-PSPs'                        = 'Print Service Provider'
        'msWMI-Som'                             = 'WMI Scope of Management'
        'msWMI-PolicyTemplate'                  = 'WMI Policy Template'
        'msWMI-PolicyType'                      = 'WMI Policy Type'
        'msDS-AzAdminManager'                   = 'Authorization Manager Store'
        # ----- Configuration NC: replication topology -----
        'site'                                  = 'AD Site'
        'subnet'                                = 'AD Subnet'
        'siteLink'                              = 'AD Site Link'
        'siteLinkBridge'                        = 'AD Site Link Bridge'
        'sitesContainer'                        = 'Sites Container'
        'serversContainer'                      = 'Servers Container'
        'server'                                = 'Configuration Server'
        'nTDSConnection'                        = 'NTDS Connection'
        'nTDSDSA'                               = 'NTDS DSA (DC Settings)'
        'nTDSSiteSettings'                      = 'NTDS Site Settings'
        'nTDSService'                           = 'NTDS Service'
        # ----- Configuration NC: display & UI metadata -----
        'displaySpecifier'                      = 'Display Specifier'
        'displayTemplate'                       = 'Display Template'
        'addressTemplate'                       = 'Address Template'
        'addressBookContainer'                  = 'Address Book Container'
        'dSUISettings'                          = 'DS UI Settings'
        'subSchema'                             = 'Subschema'
        'addrType'                              = 'Address Type'
        # ----- Configuration NC: security / DAC -----
        'controlAccessRight'                    = 'Extended Access Right'
        'msDS-ResourceProperty'                 = 'DAC Resource Property'
        'msDS-ResourcePropertyList'             = 'DAC Resource Property List'
        'msDS-ValueType'                        = 'DAC Value Type'
        'msDS-ClaimType'                        = 'DAC Claim Type'
        'msDS-ClaimsTransformationPolicies'     = 'DAC Claims Transformation Policies'
        # ----- Configuration NC: structure / partitions -----
        'crossRef'                              = 'Partition Reference (crossRef)'
        'crossRefContainer'                     = 'Partitions Container'
        'physicalLocation'                      = 'Physical Location'
        # ----- Configuration NC: PKI service -----
        'certificationAuthority'                = 'Certification Authority Service'
        # ----- Configuration NC: Exchange (forest-wide) -----
        'msExchContainer'                       = 'Exchange Container'
        'msExchRoleAssignment'                  = 'Exchange Role Assignment'
        'msExchRole'                            = 'Exchange RBAC Role'
        'msExchMailflowPolicy'                  = 'Exchange Mail Flow Policy'
        'msExchOrganizationContainer'           = 'Exchange Organization'
        # ----- Configuration NC: DNS server config -----
        'msDNS-ServerSettings'                  = 'DNS Server Settings'
        # ----- Configuration NC: services & RPC -----
        'serviceClass'                          = 'RPC Service Class'
        'serviceInstance'                       = 'Service Instance'
        'serviceAdministrationPoint'            = 'Service Administration Point'
        'rpcServer'                             = 'RPC Server'
        'rpcServerElement'                      = 'RPC Server Element'
        'queryPolicy'                           = 'LDAP Query Policy'
        # ----- Configuration NC: legacy / heritage -----
        'mSMQEnterpriseSettings'                = 'MSMQ Enterprise Settings'
        'mSMQConfiguration'                     = 'MSMQ Configuration'
        'mSMQQueue'                             = 'MSMQ Queue'
        'intellimirrorSCP'                      = 'IntelliMirror SCP (Legacy)'
        'intellimirrorGroup'                    = 'IntelliMirror Group (Legacy)'
        'aCSPolicy'                             = 'QoS ACS Policy (Legacy)'
        'aCSResourceLimits'                     = 'QoS ACS Resource Limits (Legacy)'
        'aCSSubnet'                             = 'QoS ACS Subnet (Legacy)'
        'msTAPI-RtConference'                   = 'TAPI Realtime Conference'
        'msTAPI-RtPerson'                       = 'TAPI Realtime Person'
        'packageRegistration'                   = 'Software Package Registration'
        'categoryRegistration'                  = 'Category Registration'
        # ----- Optional features -----
        'msDS-OptionalFeature'                  = 'AD Optional Feature'
        # ----- Special / pseudo -----
        'unknown'                               = '(No objectClass returned)'
    }
    if ($map.ContainsKey($cls)) { return $map[$cls] }
    return $cls
}

function Get-ClassCategory($cls) {
    switch ($cls) {
        # Identity
        'user'                                  { 'Identity' }
        'computer'                              { 'Identity' }
        'group'                                 { 'Identity' }
        'inetOrgPerson'                         { 'Identity' }
        'contact'                               { 'Identity' }
        'foreignSecurityPrincipal'              { 'Identity' }
        # Service Account
        'msDS-GroupManagedServiceAccount'       { 'Service Account' }
        'msDS-ManagedServiceAccount'            { 'Service Account' }
        'msDS-DelegatedManagedServiceAccount'   { 'Service Account' }
        # Structure
        'organizationalUnit'                    { 'Structure' }
        'container'                             { 'Structure' }
        'builtinDomain'                         { 'Structure' }
        'domainDNS'                             { 'Structure' }
        'lostAndFound'                          { 'Structure' }
        'msDS-QuotaContainer'                   { 'Structure' }
        # Policy
        'groupPolicyContainer'                  { 'Policy' }
        'msDS-PasswordSettings'                 { 'Policy' }
        'msDS-PasswordSettingsContainer'        { 'Policy' }
        'domainPolicy'                          { 'Policy' }
        # Resource
        'printQueue'                            { 'Resource' }
        'volume'                                { 'Resource' }
        'serviceConnectionPoint'                { 'Resource' }
        # PKI
        'pKICertificateTemplate'                { 'PKI' }
        'pKIEnrollmentService'                  { 'PKI' }
        'msPKI-Enterprise-Oid'                  { 'PKI' }
        # Security
        'msFVE-RecoveryInformation'             { 'Security' }
        'secret'                                { 'Security' }
        # Trust
        'trustedDomain'                         { 'Trust' }
        # DNS
        'dnsNode'                               { 'DNS' }
        'dnsZone'                               { 'DNS' }
        # Replication
        'msDFSR-LocalSettings'                  { 'Replication' }
        'msDFSR-Subscriber'                     { 'Replication' }
        'msDFSR-Subscription'                   { 'Replication' }
        'msDFSR-Member'                         { 'Replication' }
        'msDFSR-ContentSet'                     { 'Replication' }
        'msDFSR-Content'                        { 'Replication' }
        'msDFSR-Topology'                       { 'Replication' }
        'msDFSR-ReplicationGroup'               { 'Replication' }
        'msDFSR-GlobalSettings'                 { 'Replication' }
        'dfsConfiguration'                      { 'Replication' }
        'nTFRSSettings'                         { 'Replication' }
        'nTFRSReplicaSet'                       { 'Replication' }
        'nTFRSSubscriber'                       { 'Replication' }
        'nTFRSSubscriptions'                    { 'Replication' }
        'nTFRSMember'                           { 'Replication' }
        # IPSec
        'ipsecPolicy'                           { 'IPSec' }
        'ipsecNegotiationPolicy'                { 'IPSec' }
        'ipsecISAKMPPolicy'                     { 'IPSec' }
        'ipsecFilter'                           { 'IPSec' }
        'ipsecNFA'                              { 'IPSec' }
        # Exchange
        'msExchSystemObjectsContainer'          { 'Exchange' }
        'msExchActiveSyncDevice'                { 'Exchange' }
        # System / Plumbing
        'rIDSet'                                { 'System' }
        'rIDManager'                            { 'System' }
        'samServer'                             { 'System' }
        'linkTrackVolumeTable'                  { 'System' }
        'linkTrackObjectMoveTable'              { 'System' }
        'fileLinkTracking'                      { 'System' }
        'rpcContainer'                          { 'System' }
        'classStore'                            { 'System' }
        'infrastructureUpdate'                  { 'System' }
        'msTPM-InformationObjectsContainer'     { 'System' }
        'msTPM-InformationObject'               { 'System' }
        'msImaging-PSPs'                        { 'System' }
        'msWMI-Som'                             { 'System' }
        'msWMI-PolicyTemplate'                  { 'System' }
        'msWMI-PolicyType'                      { 'System' }
        'msDS-AzAdminManager'                   { 'System' }
        # ----- Topology (replication topology in Configuration NC) -----
        'site'                                  { 'Topology' }
        'subnet'                                { 'Topology' }
        'siteLink'                              { 'Topology' }
        'siteLinkBridge'                        { 'Topology' }
        'sitesContainer'                        { 'Topology' }
        'serversContainer'                      { 'Topology' }
        'server'                                { 'Topology' }
        'nTDSConnection'                        { 'Topology' }
        'nTDSDSA'                               { 'Topology' }
        'nTDSSiteSettings'                      { 'Topology' }
        'nTDSService'                           { 'Topology' }
        # ----- Display (MMC + address book metadata) -----
        'displaySpecifier'                      { 'Display' }
        'displayTemplate'                       { 'Display' }
        'addressTemplate'                       { 'Display' }
        'addressBookContainer'                  { 'Display' }
        'dSUISettings'                          { 'Display' }
        'subSchema'                             { 'Display' }
        'addrType'                              { 'Display' }
        # ----- Security (Configuration NC additions) -----
        'controlAccessRight'                    { 'Security' }
        'msDS-ResourceProperty'                 { 'Security' }
        'msDS-ResourcePropertyList'             { 'Security' }
        'msDS-ValueType'                        { 'Security' }
        'msDS-ClaimType'                        { 'Security' }
        'msDS-ClaimsTransformationPolicies'     { 'Security' }
        # ----- Structure (forest partitions) -----
        'crossRef'                              { 'Structure' }
        'crossRefContainer'                     { 'Structure' }
        'physicalLocation'                      { 'Structure' }
        # ----- PKI service object -----
        'certificationAuthority'                { 'PKI' }
        # ----- DNS server config -----
        'msDNS-ServerSettings'                  { 'DNS' }
        # ----- Exchange (forest-wide) -----
        'msExchContainer'                       { 'Exchange' }
        'msExchRoleAssignment'                  { 'Exchange' }
        'msExchRole'                            { 'Exchange' }
        'msExchMailflowPolicy'                  { 'Exchange' }
        'msExchOrganizationContainer'           { 'Exchange' }
        # ----- System / plumbing additions -----
        'serviceClass'                          { 'System' }
        'serviceInstance'                       { 'System' }
        'serviceAdministrationPoint'            { 'System' }
        'rpcServer'                             { 'System' }
        'rpcServerElement'                      { 'System' }
        'queryPolicy'                           { 'System' }
        'msDS-OptionalFeature'                  { 'System' }
        'mSMQEnterpriseSettings'                { 'System' }
        'mSMQConfiguration'                     { 'System' }
        'mSMQQueue'                             { 'System' }
        'intellimirrorSCP'                      { 'System' }
        'intellimirrorGroup'                    { 'System' }
        'aCSPolicy'                             { 'System' }
        'aCSResourceLimits'                     { 'System' }
        'aCSSubnet'                             { 'System' }
        'msTAPI-RtConference'                   { 'System' }
        'msTAPI-RtPerson'                       { 'System' }
        'packageRegistration'                   { 'System' }
        'categoryRegistration'                  { 'System' }
        # Special
        'unknown'                               { 'System' }
        default {
            # Heuristic fallbacks before giving up to "Other".
            # Order matters: more-specific patterns must come before broader ones.
            if     ($cls -like 'msDFSR-*')          { 'Replication' }
            elseif ($cls -like 'nTFRS*')            { 'Replication' }
            elseif ($cls -like 'nTDS*')             { 'Topology' }
            elseif ($cls -like 'site*')             { 'Topology' }
            elseif ($cls -like 'ipsec*')            { 'IPSec' }
            elseif ($cls -like 'msExch*')           { 'Exchange' }
            elseif ($cls -like 'msPKI-*')           { 'PKI' }
            elseif ($cls -like 'pKI*')              { 'PKI' }
            elseif ($cls -like 'msDS-*Claim*')      { 'Security' }
            elseif ($cls -like 'msDS-*Resource*')   { 'Security' }
            elseif ($cls -like 'msDS-*Password*')   { 'Policy' }
            elseif ($cls -like 'msDS-*ManagedService*') { 'Service Account' }
            elseif ($cls -like 'msDS-*')            { 'System' }
            elseif ($cls -like 'msWMI-*')           { 'System' }
            elseif ($cls -like 'msTPM-*')           { 'System' }
            elseif ($cls -like 'msTAPI-*')          { 'System' }
            elseif ($cls -like 'mSMQ*')             { 'System' }
            elseif ($cls -like 'linkTrack*')        { 'System' }
            elseif ($cls -like 'msImaging-*')       { 'System' }
            elseif ($cls -like 'rpc*')              { 'System' }
            elseif ($cls -like 'aCS*')              { 'System' }
            elseif ($cls -like 'addr*')             { 'Display' }
            elseif ($cls -like '*display*')         { 'Display' }
            elseif ($cls -like 'msDNS-*')           { 'DNS' }
            elseif ($cls -like 'dns*')              { 'DNS' }
            else                                    { 'Other' }
        }
    }
}

# ==============================================================================
# FOREST-LEVEL DISCOVERY
# ==============================================================================
try {
    $Forest        = Get-ADForest -ErrorAction Stop
    $ForestDomains = $Forest.Domains
    $ForestMode    = $Forest.ForestMode
    $RootDomain    = $Forest.RootDomain
    $SchemaMaster  = $Forest.SchemaMaster
    $NamingMaster  = $Forest.DomainNamingMaster
    $RootDSE       = Get-ADRootDSE
    $ConfigDN      = $RootDSE.configurationNamingContext
    $SchemaDN      = $RootDSE.schemaNamingContext
    Write-Host "  [+] Forest discovered: $($Forest.Name) ($($ForestDomains.Count) domain(s))" -ForegroundColor Green
} catch {
    Write-Host "  [!] Forest discovery failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "      Ensure you are on a domain-joined machine with RSAT and run as a domain user." -ForegroundColor Red
    return
}

$SchemaVersion = 0; $SchemaClasses = 0; $SchemaAttributes = 0
try {
    $schemaObj = Get-ADObject "CN=Schema,$ConfigDN" -Properties objectVersion -ErrorAction Stop
    $SchemaVersion = [int]$schemaObj.objectVersion
    $SchemaClasses    = @(Get-ADObject -SearchBase $SchemaDN -LDAPFilter "(objectClass=classSchema)" -ResultSetSize $null -ErrorAction SilentlyContinue).Count
    $SchemaAttributes = @(Get-ADObject -SearchBase $SchemaDN -LDAPFilter "(objectClass=attributeSchema)" -ResultSetSize $null -ErrorAction SilentlyContinue).Count
    Write-Host "  [+] Schema: version $SchemaVersion, $SchemaClasses classes, $SchemaAttributes attributes" -ForegroundColor Green
} catch { Write-Host "  [i] Could not read schema metadata." -ForegroundColor Gray }

$SchemaOSMap = @{
    13='Windows 2000';30='Windows Server 2003';31='Windows Server 2003 R2';
    44='Windows Server 2008';47='Windows Server 2008 R2';56='Windows Server 2012';
    69='Windows Server 2012 R2';87='Windows Server 2016';88='Windows Server 2019';
    89='Windows Server 2022';91='Windows Server 2025'
}
$SchemaOS = if ($SchemaOSMap.ContainsKey($SchemaVersion)) { $SchemaOSMap[$SchemaVersion] } else { "Schema v$SchemaVersion" }

$FuncLevelMap = @{
    'Windows2000Forest'='Windows 2000';'Windows2003Forest'='Windows Server 2003';
    'Windows2003InterimForest'='Windows Server 2003 Interim';'Windows2008Forest'='Windows Server 2008';
    'Windows2008R2Forest'='Windows Server 2008 R2';'Windows2012Forest'='Windows Server 2012';
    'Windows2012R2Forest'='Windows Server 2012 R2';'Windows2016Forest'='Windows Server 2016';
    'Windows2000Domain'='Windows 2000';'Windows2003Domain'='Windows Server 2003';
    'Windows2008Domain'='Windows Server 2008';'Windows2008R2Domain'='Windows Server 2008 R2';
    'Windows2012Domain'='Windows Server 2012';'Windows2012R2Domain'='Windows Server 2012 R2';
    'Windows2016Domain'='Windows Server 2016'
}
function Get-FriendlyFuncLevel($lvl) { $s=[string]$lvl; if($FuncLevelMap.ContainsKey($s)){return $FuncLevelMap[$s]}; return $s }
$ForestModeDisplay = Get-FriendlyFuncLevel $ForestMode

$ADSites=@(); $ADSubnets=@(); $ADSiteLinks=@()
try {
    $ADSites     = Get-ADReplicationSite -Filter * -ErrorAction SilentlyContinue | Select-Object Name, Description
    $ADSubnets   = Get-ADReplicationSubnet -Filter * -ErrorAction SilentlyContinue | Select-Object Name, Site, Location, Description
    $ADSiteLinks = Get-ADReplicationSiteLink -Filter * -ErrorAction SilentlyContinue | Select-Object Name, Cost, ReplicationFrequencyInMinutes, SitesIncluded
    Write-Host "  [+] Sites: $($ADSites.Count)  Subnets: $($ADSubnets.Count)  SiteLinks: $($ADSiteLinks.Count)" -ForegroundColor Green
} catch { Write-Host "  [i] Could not read site / subnet info." -ForegroundColor Gray }

$RecycleBinEnabled = $false
try {
    $rb = Get-ADOptionalFeature -Filter 'name -like "Recycle*"' -ErrorAction SilentlyContinue
    if ($rb -and $rb.EnabledScopes -and @($rb.EnabledScopes).Count -gt 0) { $RecycleBinEnabled = $true }
} catch { }

$TombstoneLife = 60
try {
    $ds = Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$ConfigDN" -Properties tombstoneLifetime -ErrorAction SilentlyContinue
    if ($ds.tombstoneLifetime) { $TombstoneLife = $ds.tombstoneLifetime }
} catch { }

$DNSZones = @(); $DNSServer = $null
try {
    if (Get-Module -ListAvailable -Name DnsServer) {
        Import-Module DnsServer -ErrorAction SilentlyContinue
        $rootDom = Get-ADDomain -Identity $RootDomain -ErrorAction SilentlyContinue
        if ($rootDom) {
            try {
                $DNSZones  = Get-DnsServerZone -ComputerName $rootDom.PDCEmulator -ErrorAction Stop |
                             Select-Object ZoneName, ZoneType, IsReverseLookupZone, IsDsIntegrated, ReplicationScope, IsAutoCreated, IsSigned
                $DNSServer = $rootDom.PDCEmulator
                Write-Host "  [+] DNS zones collected from $DNSServer ($($DNSZones.Count) zones)" -ForegroundColor Green
            } catch { Write-Host "  [i] Could not read DNS zones from $($rootDom.PDCEmulator)" -ForegroundColor Gray }
        }
    } else { Write-Host "  [i] DnsServer module not available." -ForegroundColor Gray }
} catch { }

# ==============================================================================
# PER-DOMAIN COLLECTION
# ==============================================================================
$AllDomainData    = @{}
$AllForestDCs     = @()
$AllTrusts        = @()
$ForestObjectTotal= 0
$ForestClassMap   = @{}
$ForestUnknownCount = 0
$ForestTotals     = @{
    Users=0;EnabledUsers=0;DisabledUsers=0;LockedUsers=0;PwdNeverExp=0;PwdExpired=0;NeverLoggedOn=0;Inactive90=0;AdminCount=0;SmartCardReq=0
    Computers=0;EnabledComp=0;DisabledComp=0;Servers=0;Workstations=0;StaleComp90=0
    Groups=0;Security=0;Distribution=0;Global=0;DomainLocal=0;Universal=0;Empty=0;BuiltinGrp=0;Privileged=0
    OUs=0;ProtectedOUs=0
    GPOs=0;EnabledGPO=0;DisabledGPO=0;PartialGPO=0;UserSettingsDisabledGPO=0;CompSettingsDisabledGPO=0
    Containers=0;Contacts=0;Printers=0;FSPs=0;BitLockerKeys=0
    sMSAs=0;gMSAs=0;dMSAs=0
    FGPPs=0
}

foreach ($domName in $ForestDomains) {
    Write-Host "  [*] Enumerating domain: $domName" -ForegroundColor Yellow
    $dd = @{}
    try {
        $dom = Get-ADDomain -Identity $domName -Server $domName -ErrorAction Stop
        $dd.DomainName = $dom.DNSRoot
        $dd.NetBIOS    = $dom.NetBIOSName
        $dd.DomainMode = Get-FriendlyFuncLevel $dom.DomainMode
        $dd.DN         = $dom.DistinguishedName
        $dd.PDC        = $dom.PDCEmulator
        $dd.Parent     = if ($dom.ParentDomain) { $dom.ParentDomain } else { '(Forest Root)' }

        # ----- DCs -----
        $dd.DCs = @()
        try {
            $dcs = Get-ADDomainController -Filter * -Server $domName -ErrorAction Stop
            foreach ($dc in $dcs) {
                $dcObj = [PSCustomObject]@{
                    Name=$dc.Name; HostName=$dc.HostName; Domain=$domName; IPv4Address=$dc.IPv4Address;
                    OperatingSystem=$dc.OperatingSystem; OSVersion=$dc.OperatingSystemVersion; Site=$dc.Site;
                    Type=if($dc.IsReadOnly){'RODC'}else{'RWDC'}; IsGlobalCatalog=$dc.IsGlobalCatalog;
                    FSMORoles=($dc.OperationMasterRoles | ForEach-Object {[string]$_}) -join ', '; Enabled=$dc.Enabled
                }
                $dd.DCs += $dcObj
                $AllForestDCs += $dcObj
            }
        } catch { Write-Host "    [i] Could not enumerate DCs for $domName" -ForegroundColor Gray }

        # ----- Trusts -----
        try {
            $domTrusts = Get-ADTrust -Filter * -Server $domName -ErrorAction SilentlyContinue
            foreach ($tr in $domTrusts) {
                $AllTrusts += [PSCustomObject]@{
                    SourceDomain=$domName; TrustedDomain=$tr.Name; Direction=[string]$tr.Direction;
                    TrustType=[string]$tr.TrustType; Transitive=if($tr.DisallowTransivity){'No'}else{'Yes'};
                    SelectiveAuth=if($tr.SelectiveAuthentication){'Yes'}else{'No'};
                    IntraForest=if($tr.IntraForest){'Yes'}else{'No'}
                }
            }
        } catch { }

        # ----- Object Class Census (paged DirectorySearcher streaming, with fallback) -----
        $dd.ClassMap     = @{}
        $dd.TotalObjects = 0
        $dd.UnknownCount = 0
        $censusOK = $false
        try {
            Write-Host "    [.] Enumerating all objects in domain NC (paged) ..." -ForegroundColor DarkGray
            $rootEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domName/$($dom.DistinguishedName)")
            $searcher  = New-Object System.DirectoryServices.DirectorySearcher($rootEntry)
            $searcher.Filter = '(objectClass=*)'
            [void]$searcher.PropertiesToLoad.Add('objectClass')
            $searcher.PageSize    = 1000
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $searcher.SizeLimit   = 0
            $results = $searcher.FindAll()
            foreach ($r in $results) {
                $dd.TotalObjects++
                $clsAttr = $r.Properties['objectclass']
                $cls = if ($clsAttr -and $clsAttr.Count -gt 0) { [string]$clsAttr[$clsAttr.Count - 1] } else { '' }
                if (-not $cls) { $cls = 'unknown'; $dd.UnknownCount++ }
                if ($dd.ClassMap.ContainsKey($cls)) { $dd.ClassMap[$cls]++ } else { $dd.ClassMap[$cls] = 1 }
                if ($ForestClassMap.ContainsKey($cls)) { $ForestClassMap[$cls]++ } else { $ForestClassMap[$cls] = 1 }
            }
            $results.Dispose()
            $searcher.Dispose()
            $rootEntry.Dispose()
            $ForestObjectTotal  += $dd.TotalObjects
            $ForestUnknownCount += $dd.UnknownCount
            $censusOK = $true
            Write-Host "    [+] $($dd.TotalObjects) objects across $($dd.ClassMap.Count) distinct classes$(if($dd.UnknownCount -gt 0){" ($($dd.UnknownCount) with no objectClass)"})" -ForegroundColor Green
        } catch {
            Write-Host "    [!] DirectorySearcher streaming failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "        Falling back to Get-ADObject ..." -ForegroundColor Gray
        }
        if (-not $censusOK) {
            try {
                $allObj = Get-ADObject -Filter * -SearchBase $dom.DistinguishedName -Server $domName -Properties objectClass -ResultSetSize $null -ErrorAction Stop
                $dd.TotalObjects = @($allObj).Count
                foreach ($o in $allObj) {
                    $cls = if ($o.objectClass -is [System.Array]) { [string]$o.objectClass[-1] } else { [string]$o.objectClass }
                    if (-not $cls) { $cls = 'unknown'; $dd.UnknownCount++ }
                    if ($dd.ClassMap.ContainsKey($cls)) { $dd.ClassMap[$cls]++ } else { $dd.ClassMap[$cls] = 1 }
                    if ($ForestClassMap.ContainsKey($cls)) { $ForestClassMap[$cls]++ } else { $ForestClassMap[$cls] = 1 }
                }
                $ForestObjectTotal  += $dd.TotalObjects
                $ForestUnknownCount += $dd.UnknownCount
                Write-Host "    [+] $($dd.TotalObjects) objects (Get-ADObject fallback)" -ForegroundColor Yellow
            } catch {
                Write-Host "    [!] Object enumeration failed completely: $($_.Exception.Message)" -ForegroundColor Red
            }
        }

        # ----- Users -----
        $dd.TotalUsers=0;$dd.EnabledUsers=0;$dd.DisabledUsers=0;$dd.LockedUsers=0;$dd.PwdNeverExp=0;$dd.PwdExpired=0;$dd.NeverLoggedOn=0;$dd.Inactive90=0;$dd.AdminCount=0;$dd.SmartCardReq=0
        try {
            $allU = Get-ADUser -Filter * -Server $domName -Properties Enabled,LockedOut,PasswordExpired,PasswordNeverExpires,LastLogonDate,AdminCount,SmartcardLogonRequired -ErrorAction SilentlyContinue
            $dd.TotalUsers     = @($allU).Count
            $dd.EnabledUsers   = @($allU | Where-Object { $_.Enabled -eq $true }).Count
            $dd.DisabledUsers  = @($allU | Where-Object { $_.Enabled -eq $false }).Count
            $dd.LockedUsers    = @($allU | Where-Object { $_.LockedOut -eq $true }).Count
            $dd.PwdNeverExp    = @($allU | Where-Object { $_.PasswordNeverExpires -eq $true }).Count
            $dd.PwdExpired     = @($allU | Where-Object { $_.PasswordExpired -eq $true }).Count
            $dd.NeverLoggedOn  = @($allU | Where-Object { $_.Enabled -eq $true -and -not $_.LastLogonDate }).Count
            $dd.Inactive90     = @($allU | Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt (Get-Date).AddDays(-90) }).Count
            $dd.AdminCount     = @($allU | Where-Object { $_.AdminCount -eq 1 }).Count
            $dd.SmartCardReq   = @($allU | Where-Object { $_.SmartcardLogonRequired -eq $true }).Count
        } catch { }

        # ----- Computers -----
        $dd.TotalComputers=0;$dd.EnabledComp=0;$dd.DisabledComp=0;$dd.Servers=0;$dd.Workstations=0;$dd.StaleComp90=0;$dd.OSDist=@{}
        try {
            $allC = Get-ADComputer -Filter * -Server $domName -Properties Enabled,OperatingSystem,LastLogonDate,PasswordLastSet -ErrorAction SilentlyContinue
            $dd.TotalComputers = @($allC).Count
            $dd.EnabledComp    = @($allC | Where-Object { $_.Enabled -eq $true }).Count
            $dd.DisabledComp   = @($allC | Where-Object { $_.Enabled -eq $false }).Count
            $dd.Servers        = @($allC | Where-Object { $_.OperatingSystem -like '*Server*' }).Count
            $dd.Workstations   = @($allC | Where-Object { $_.OperatingSystem -and $_.OperatingSystem -notlike '*Server*' }).Count
            $dd.StaleComp90    = @($allC | Where-Object { $_.PasswordLastSet -and $_.PasswordLastSet -lt (Get-Date).AddDays(-90) }).Count
            foreach ($c in $allC) {
                if ($c.OperatingSystem) {
                    $os = $c.OperatingSystem
                    if ($dd.OSDist.ContainsKey($os)) { $dd.OSDist[$os]++ } else { $dd.OSDist[$os] = 1 }
                }
            }
        } catch { }

        # ----- Groups -----
        # NOTE: Get-ADGroup -Properties Members truncates linked-value attributes at 5000
        # by default (LDAP MaxValRange). Empty-group detection (zero vs nonzero) is unaffected;
        # exact member counts on very large groups would need range retrieval.
        $dd.TotalGroups=0;$dd.Security=0;$dd.Distribution=0;$dd.Global=0;$dd.DomainLocal=0;$dd.Universal=0;$dd.Empty=0;$dd.BuiltinGrp=0;$dd.Privileged=0
        try {
            $allG = Get-ADGroup -Filter * -Server $domName -Properties GroupScope,GroupCategory,Members,AdminCount,DistinguishedName -ErrorAction SilentlyContinue
            $dd.TotalGroups   = @($allG).Count
            $dd.Security      = @($allG | Where-Object { $_.GroupCategory -eq 'Security' }).Count
            $dd.Distribution  = @($allG | Where-Object { $_.GroupCategory -eq 'Distribution' }).Count
            $dd.Global        = @($allG | Where-Object { $_.GroupScope -eq 'Global' }).Count
            $dd.DomainLocal   = @($allG | Where-Object { $_.GroupScope -eq 'DomainLocal' }).Count
            $dd.Universal     = @($allG | Where-Object { $_.GroupScope -eq 'Universal' }).Count
            $dd.Empty         = @($allG | Where-Object { @($_.Members).Count -eq 0 }).Count
            $dd.BuiltinGrp    = @($allG | Where-Object { $_.DistinguishedName -like '*CN=Builtin,*' }).Count
            $dd.Privileged    = @($allG | Where-Object { $_.AdminCount -eq 1 }).Count
        } catch { }

        # ----- OUs -----
        $dd.TotalOUs=0;$dd.ProtectedOUs=0;$dd.OUList=@()
        try {
            $allOU = Get-ADOrganizationalUnit -Filter * -Server $domName -Properties ProtectedFromAccidentalDeletion,Description -ErrorAction SilentlyContinue
            $dd.TotalOUs       = @($allOU).Count
            $dd.ProtectedOUs   = @($allOU | Where-Object { $_.ProtectedFromAccidentalDeletion -eq $true }).Count
            $dd.OUList = @($allOU | Select-Object Name, DistinguishedName, ProtectedFromAccidentalDeletion, Description | Sort-Object DistinguishedName)
        } catch { }

        # ----- Containers / Contacts / Printers / FSPs / BitLocker -----
        $dd.ContainerCount = 0
        try { $dd.ContainerCount = @(Get-ADObject -LDAPFilter '(objectClass=container)' -SearchBase $dom.DistinguishedName -Server $domName -ResultSetSize $null -ErrorAction SilentlyContinue).Count } catch { }
        $dd.ContactCount = 0
        try { $dd.ContactCount = @(Get-ADObject -LDAPFilter '(objectClass=contact)' -SearchBase $dom.DistinguishedName -Server $domName -ResultSetSize $null -ErrorAction SilentlyContinue).Count } catch { }
        $dd.PrinterCount = 0
        try { $dd.PrinterCount = @(Get-ADObject -LDAPFilter '(objectClass=printQueue)' -SearchBase $dom.DistinguishedName -Server $domName -ResultSetSize $null -ErrorAction SilentlyContinue).Count } catch { }
        $dd.FSPCount = 0
        try { $dd.FSPCount = @(Get-ADObject -LDAPFilter '(objectClass=foreignSecurityPrincipal)' -SearchBase $dom.DistinguishedName -Server $domName -ResultSetSize $null -ErrorAction SilentlyContinue).Count } catch { }
        $dd.BitLockerKeys = 0
        try { $dd.BitLockerKeys = @(Get-ADObject -LDAPFilter '(objectClass=msFVE-RecoveryInformation)' -SearchBase $dom.DistinguishedName -Server $domName -ResultSetSize $null -ErrorAction SilentlyContinue).Count } catch { }

        # ----- GPOs -----
        $dd.TotalGPOs=0;$dd.EnabledGPO=0;$dd.DisabledGPO=0;$dd.PartialGPO=0;$dd.UserDisabledGPO=0;$dd.CompDisabledGPO=0;$dd.GPOList=@()
        try {
            $allGPO = Get-GPO -All -Domain $domName -ErrorAction Stop
            $dd.TotalGPOs       = @($allGPO).Count
            $dd.EnabledGPO      = @($allGPO | Where-Object { $_.GpoStatus -eq 'AllSettingsEnabled' }).Count
            $dd.DisabledGPO     = @($allGPO | Where-Object { $_.GpoStatus -eq 'AllSettingsDisabled' }).Count
            $dd.UserDisabledGPO = @($allGPO | Where-Object { $_.GpoStatus -eq 'UserSettingsDisabled' }).Count
            $dd.CompDisabledGPO = @($allGPO | Where-Object { $_.GpoStatus -eq 'ComputerSettingsDisabled' }).Count
            $dd.PartialGPO      = $dd.UserDisabledGPO + $dd.CompDisabledGPO
            $dd.GPOList = @($allGPO | Select-Object DisplayName, GpoStatus, CreationTime, ModificationTime, @{N='Owner';E={$_.Owner}})
        } catch { Write-Host "    [i] GPO enumeration skipped" -ForegroundColor Gray }

        # ----- Service Accounts -----
        $dd.sMSACount=0; $dd.gMSACount=0; $dd.dMSACount=0; $dd.SvcList=@()
        try {
            $msas = Get-ADServiceAccount -Filter * -Server $domName -Properties Enabled,Created,ObjectClass -ErrorAction SilentlyContinue
            foreach ($m in $msas) {
                $kind = switch ($m.ObjectClass) {
                    'msDS-GroupManagedServiceAccount' { 'gMSA' }
                    'msDS-ManagedServiceAccount'      { 'sMSA' }
                    default { $m.ObjectClass }
                }
                if ($kind -eq 'gMSA') { $dd.gMSACount++ } elseif ($kind -eq 'sMSA') { $dd.sMSACount++ }
                $dd.SvcList += [PSCustomObject]@{ Name=$m.Name; SamAccountName=$m.SamAccountName; Type=$kind; Enabled=$m.Enabled; Created=$m.Created }
            }
        } catch { }
        try {
            if ($SchemaVersion -ge 91) {
                $dmsas = Get-ADObject -Filter "objectClass -eq 'msDS-DelegatedManagedServiceAccount'" -SearchBase $dom.DistinguishedName -Server $domName -Properties Name,whenCreated -ErrorAction SilentlyContinue
                foreach ($d in $dmsas) {
                    $dd.dMSACount++
                    $dd.SvcList += [PSCustomObject]@{ Name=$d.Name; SamAccountName='--'; Type='dMSA'; Enabled='--'; Created=$d.whenCreated }
                }
            }
        } catch { }

        # ----- Default Password Policy -----
        $dd.PwdPolicy = $null
        try { $dd.PwdPolicy = Get-ADDefaultDomainPasswordPolicy -Server $domName -ErrorAction SilentlyContinue } catch { }

        # ----- FGPP -----
        $dd.FGPPs = @()
        try {
            $fgpp = Get-ADFineGrainedPasswordPolicy -Filter * -Server $domName -ErrorAction Stop
            if ($fgpp) {
                $dd.FGPPs = @($fgpp | Select-Object Name, Precedence, MinPasswordLength, ComplexityEnabled, MaxPasswordAge, MinPasswordAge, PasswordHistoryCount, LockoutThreshold, LockoutDuration, AppliesTo)
            }
        } catch {
            try {
                $alt = Get-ADObject -LDAPFilter '(objectClass=msDS-PasswordSettings)' -SearchBase "CN=Password Settings Container,CN=System,$($dom.DistinguishedName)" -Server $domName -Properties * -ErrorAction SilentlyContinue
                if ($alt) {
                    $dd.FGPPs = @($alt | Select-Object @{N='Name';E={$_.Name}},
                        @{N='Precedence';E={$_.'msDS-PasswordSettingsPrecedence'}},
                        @{N='MinPasswordLength';E={$_.'msDS-MinimumPasswordLength'}},
                        @{N='ComplexityEnabled';E={$_.'msDS-PasswordComplexityEnabled'}},
                        @{N='MaxPasswordAge';E={$_.'msDS-MaximumPasswordAge'}},
                        @{N='MinPasswordAge';E={$_.'msDS-MinimumPasswordAge'}},
                        @{N='PasswordHistoryCount';E={$_.'msDS-PasswordHistoryLength'}},
                        @{N='LockoutThreshold';E={$_.'msDS-LockoutThreshold'}},
                        @{N='LockoutDuration';E={$_.'msDS-LockoutDuration'}})
                }
            } catch { }
        }

        # Aggregate
        $ForestTotals.Users           += $dd.TotalUsers
        $ForestTotals.EnabledUsers    += $dd.EnabledUsers
        $ForestTotals.DisabledUsers   += $dd.DisabledUsers
        $ForestTotals.LockedUsers     += $dd.LockedUsers
        $ForestTotals.PwdNeverExp     += $dd.PwdNeverExp
        $ForestTotals.PwdExpired      += $dd.PwdExpired
        $ForestTotals.NeverLoggedOn   += $dd.NeverLoggedOn
        $ForestTotals.Inactive90      += $dd.Inactive90
        $ForestTotals.AdminCount      += $dd.AdminCount
        $ForestTotals.SmartCardReq    += $dd.SmartCardReq
        $ForestTotals.Computers       += $dd.TotalComputers
        $ForestTotals.EnabledComp     += $dd.EnabledComp
        $ForestTotals.DisabledComp    += $dd.DisabledComp
        $ForestTotals.Servers         += $dd.Servers
        $ForestTotals.Workstations    += $dd.Workstations
        $ForestTotals.StaleComp90     += $dd.StaleComp90
        $ForestTotals.Groups          += $dd.TotalGroups
        $ForestTotals.Security        += $dd.Security
        $ForestTotals.Distribution    += $dd.Distribution
        $ForestTotals.Global          += $dd.Global
        $ForestTotals.DomainLocal     += $dd.DomainLocal
        $ForestTotals.Universal       += $dd.Universal
        $ForestTotals.Empty           += $dd.Empty
        $ForestTotals.BuiltinGrp      += $dd.BuiltinGrp
        $ForestTotals.Privileged      += $dd.Privileged
        $ForestTotals.OUs             += $dd.TotalOUs
        $ForestTotals.ProtectedOUs    += $dd.ProtectedOUs
        $ForestTotals.GPOs            += $dd.TotalGPOs
        $ForestTotals.EnabledGPO      += $dd.EnabledGPO
        $ForestTotals.DisabledGPO     += $dd.DisabledGPO
        $ForestTotals.PartialGPO      += $dd.PartialGPO
        $ForestTotals.UserSettingsDisabledGPO += $dd.UserDisabledGPO
        $ForestTotals.CompSettingsDisabledGPO += $dd.CompDisabledGPO
        $ForestTotals.Containers      += $dd.ContainerCount
        $ForestTotals.Contacts        += $dd.ContactCount
        $ForestTotals.Printers        += $dd.PrinterCount
        $ForestTotals.FSPs            += $dd.FSPCount
        $ForestTotals.BitLockerKeys   += $dd.BitLockerKeys
        $ForestTotals.sMSAs           += $dd.sMSACount
        $ForestTotals.gMSAs           += $dd.gMSACount
        $ForestTotals.dMSAs           += $dd.dMSACount
        $ForestTotals.FGPPs           += @($dd.FGPPs).Count

        Write-Host "    Users:$($dd.TotalUsers) Computers:$($dd.TotalComputers) Groups:$($dd.TotalGroups) OUs:$($dd.TotalOUs) GPOs:$($dd.TotalGPOs) Containers:$($dd.ContainerCount) Printers:$($dd.PrinterCount) Contacts:$($dd.ContactCount) FSPs:$($dd.FSPCount)" -ForegroundColor Gray

        $AllDomainData[$domName] = $dd
        Write-Host "  [+] $domName -- $($dd.DomainMode)" -ForegroundColor Green

    } catch {
        Write-Host "  [!] Could not reach domain $domName : $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "  [+] Domain enumeration complete." -ForegroundColor Green
Write-Host ""

# ==============================================================================
# CONFIGURATION NC ENUMERATION (forest-wide)
# ==============================================================================
Write-Host "  [*] Enumerating Configuration NC ..." -ForegroundColor Yellow
$ConfigClassMap     = @{}
$ConfigTotalObjects = 0
$ConfigUnknownCount = 0
try {
    $rootEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$RootDomain/$ConfigDN")
    $searcher  = New-Object System.DirectoryServices.DirectorySearcher($rootEntry)
    $searcher.Filter = '(objectClass=*)'
    [void]$searcher.PropertiesToLoad.Add('objectClass')
    $searcher.PageSize    = 1000
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $searcher.SizeLimit   = 0
    $results = $searcher.FindAll()
    foreach ($r in $results) {
        $ConfigTotalObjects++
        $clsAttr = $r.Properties['objectclass']
        $cls = if ($clsAttr -and $clsAttr.Count -gt 0) { [string]$clsAttr[$clsAttr.Count - 1] } else { '' }
        if (-not $cls) { $cls = 'unknown'; $ConfigUnknownCount++ }
        if ($ConfigClassMap.ContainsKey($cls)) { $ConfigClassMap[$cls]++ } else { $ConfigClassMap[$cls] = 1 }
    }
    $results.Dispose()
    $searcher.Dispose()
    $rootEntry.Dispose()
    Write-Host "  [+] Configuration NC: $ConfigTotalObjects objects across $($ConfigClassMap.Count) distinct classes" -ForegroundColor Green
} catch {
    Write-Host "  [!] Could not enumerate Configuration NC: $($_.Exception.Message)" -ForegroundColor Red
}

# ==============================================================================
# DNS APPLICATION PARTITION ENUMERATION
# ==============================================================================
$DnsPartitionList = @()
try {
    $namingContexts = $RootDSE.namingContexts
    foreach ($nc in $namingContexts) {
        $ncStr = [string]$nc
        if ($ncStr -like '*DnsZones*') { $DnsPartitionList += $ncStr }
    }
} catch { }

$DnsClassMap         = @{}
$DnsTotalObjects     = 0
$DnsPartitionDetails = @()
foreach ($dnsNc in $DnsPartitionList) {
    Write-Host "  [*] Enumerating DNS partition: $dnsNc" -ForegroundColor Yellow
    $partTotal = 0
    $partClasses = @{}
    try {
        $rootEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$RootDomain/$dnsNc")
        $searcher  = New-Object System.DirectoryServices.DirectorySearcher($rootEntry)
        $searcher.Filter = '(objectClass=*)'
        [void]$searcher.PropertiesToLoad.Add('objectClass')
        $searcher.PageSize    = 1000
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $searcher.SizeLimit   = 0
        $results = $searcher.FindAll()
        foreach ($r in $results) {
            $partTotal++
            $clsAttr = $r.Properties['objectclass']
            $cls = if ($clsAttr -and $clsAttr.Count -gt 0) { [string]$clsAttr[$clsAttr.Count - 1] } else { 'unknown' }
            if (-not $cls) { $cls = 'unknown' }
            if ($partClasses.ContainsKey($cls)) { $partClasses[$cls]++ } else { $partClasses[$cls] = 1 }
            if ($DnsClassMap.ContainsKey($cls)) { $DnsClassMap[$cls]++ } else { $DnsClassMap[$cls] = 1 }
        }
        $results.Dispose()
        $searcher.Dispose()
        $rootEntry.Dispose()
        $DnsTotalObjects += $partTotal
        $partType = if ($dnsNc -like 'DC=ForestDnsZones*') { 'Forest-Wide' } elseif ($dnsNc -like 'DC=DomainDnsZones*') { 'Domain' } else { 'Custom' }
        $DnsPartitionDetails += [PSCustomObject]@{
            Partition       = $dnsNc
            Scope           = $partType
            TotalObjects    = $partTotal
            DistinctClasses = $partClasses.Count
            DnsRecords      = if ($partClasses.ContainsKey('dnsNode')) { $partClasses['dnsNode'] } else { 0 }
            DnsZones        = if ($partClasses.ContainsKey('dnsZone')) { $partClasses['dnsZone'] } else { 0 }
        }
        Write-Host "  [+] $dnsNc : $partTotal objects ($($partClasses['dnsNode']) records, $($partClasses['dnsZone']) zones)" -ForegroundColor Green
    } catch {
        Write-Host "  [!] Could not enumerate $dnsNc : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ==============================================================================
# BUILD HTML TABLES
# ==============================================================================
$DomainSummaryData = foreach ($domName in $ForestDomains) {
    if (-not $AllDomainData.ContainsKey($domName)) { continue }
    $dd = $AllDomainData[$domName]
    [PSCustomObject]@{
        Domain      = $dd.DomainName
        NetBIOS     = $dd.NetBIOS
        FuncLevel   = $dd.DomainMode
        DCs         = @($dd.DCs).Count
        TotalObjects= $dd.TotalObjects
        Users       = $dd.TotalUsers
        Computers   = $dd.TotalComputers
        Groups      = $dd.TotalGroups
        OUs         = $dd.TotalOUs
        GPOs        = $dd.TotalGPOs
        Containers  = $dd.ContainerCount
    }
}
$DomainSummaryTable = ConvertTo-HtmlTable -Data $DomainSummaryData -Properties Domain,NetBIOS,FuncLevel,DCs,TotalObjects,Users,Computers,Groups,OUs,GPOs,Containers
$AllDCsTable = ConvertTo-HtmlTable -Data $AllForestDCs -Properties Name, Domain, IPv4Address, Type, OperatingSystem, OSVersion, Site, IsGlobalCatalog, FSMORoles, Enabled
$TrustTable  = if ($AllTrusts.Count -gt 0) { ConvertTo-HtmlTable -Data $AllTrusts -Properties SourceDomain, TrustedDomain, Direction, TrustType, Transitive, SelectiveAuth, IntraForest } else { '<p class="empty-note">No trusts configured.</p>' }
$DNSTable    = if ($DNSZones.Count -gt 0) { ConvertTo-HtmlTable -Data $DNSZones -Properties ZoneName, ZoneType, IsReverseLookupZone, IsDsIntegrated, ReplicationScope, IsAutoCreated, IsSigned } else { '<p class="empty-note">DNS zone data not collected (not run on a DC, or DnsServer module unavailable).</p>' }

$DNSForwardCount = @($DNSZones | Where-Object { $_.IsReverseLookupZone -eq $false }).Count
$DNSReverseCount = @($DNSZones | Where-Object { $_.IsReverseLookupZone -eq $true }).Count
$DNSIntegrated   = @($DNSZones | Where-Object { $_.IsDsIntegrated -eq $true }).Count
$DNSFileBacked   = @($DNSZones | Where-Object { $_.IsDsIntegrated -eq $false }).Count
$DNSSigned       = @($DNSZones | Where-Object { $_.IsSigned -eq $true }).Count

$SiteTable    = ConvertTo-HtmlTable -Data $ADSites -Properties Name, Description
$SubnetTable  = ConvertTo-HtmlTable -Data $ADSubnets -Properties Name, Site, Location, Description
$SiteLinkTbl  = ConvertTo-HtmlTable -Data $ADSiteLinks -Properties Name, Cost, ReplicationFrequencyInMinutes, SitesIncluded

$ForestClassRows = $ForestClassMap.GetEnumerator() |
    ForEach-Object {
        $cls = $_.Key; $cnt = $_.Value
        $pct = if ($ForestObjectTotal -gt 0) { [math]::Round(($cnt * 100.0 / $ForestObjectTotal),2) } else { 0 }
        [PSCustomObject]@{
            Category    = Get-ClassCategory $cls
            FriendlyName= Get-FriendlyClassName $cls
            ObjectClass = $cls
            Count       = $cnt
            Percent     = "$pct %"
        }
    } | Sort-Object Count -Descending
$ForestClassTable = ConvertTo-HtmlTable -Data $ForestClassRows -Properties Category, FriendlyName, ObjectClass, Count, Percent

# ----- Configuration NC table -----
$ConfigClassRows = $ConfigClassMap.GetEnumerator() |
    ForEach-Object {
        $cls = $_.Key; $cnt = $_.Value
        $pct = if ($ConfigTotalObjects -gt 0) { [math]::Round(($cnt * 100.0 / $ConfigTotalObjects),2) } else { 0 }
        [PSCustomObject]@{
            Category    = Get-ClassCategory $cls
            FriendlyName= Get-FriendlyClassName $cls
            ObjectClass = $cls
            Count       = $cnt
            Percent     = "$pct %"
        }
    } | Sort-Object Count -Descending
$ConfigClassTable = if ($ConfigClassRows.Count -gt 0) { ConvertTo-HtmlTable -Data $ConfigClassRows -Properties Category, FriendlyName, ObjectClass, Count, Percent } else { '<p class="empty-note">Configuration NC could not be enumerated.</p>' }

# ----- DNS partition tables -----
$DnsPartitionTable = if ($DnsPartitionDetails.Count -gt 0) { ConvertTo-HtmlTable -Data $DnsPartitionDetails -Properties Partition, Scope, TotalObjects, DistinctClasses, DnsZones, DnsRecords } else { '<p class="empty-note">No AD-integrated DNS application partitions detected.</p>' }

$DnsClassRows = $DnsClassMap.GetEnumerator() |
    ForEach-Object {
        $cls = $_.Key; $cnt = $_.Value
        $pct = if ($DnsTotalObjects -gt 0) { [math]::Round(($cnt * 100.0 / $DnsTotalObjects),2) } else { 0 }
        [PSCustomObject]@{
            Category    = Get-ClassCategory $cls
            FriendlyName= Get-FriendlyClassName $cls
            ObjectClass = $cls
            Count       = $cnt
            Percent     = "$pct %"
        }
    } | Sort-Object Count -Descending
$DnsClassTable = if ($DnsClassRows.Count -gt 0) { ConvertTo-HtmlTable -Data $DnsClassRows -Properties Category, FriendlyName, ObjectClass, Count, Percent } else { '<p class="empty-note">No DNS partition objects enumerated.</p>' }

# ----- Heritage & Cleanup Candidates -----
$IPSecClasses     = @('ipsecPolicy','ipsecNegotiationPolicy','ipsecISAKMPPolicy','ipsecFilter','ipsecNFA')
$NTFRSClasses     = @('nTFRSSettings','nTFRSReplicaSet','nTFRSSubscriber','nTFRSSubscriptions','nTFRSMember')
$LinkTrackClasses = @('linkTrackVolumeTable','linkTrackObjectMoveTable','fileLinkTracking')

function Get-ClassSum($classes) {
    $total = 0
    foreach ($c in $classes) { if ($ForestClassMap.ContainsKey($c)) { $total += $ForestClassMap[$c] } }
    return $total
}

$IPSecCount        = Get-ClassSum $IPSecClasses
$NTFRSCount        = Get-ClassSum $NTFRSClasses
$LinkTrackCount    = Get-ClassSum $LinkTrackClasses
$DomainPolicyCount = if ($ForestClassMap.ContainsKey('domainPolicy')) { $ForestClassMap['domainPolicy'] } else { 0 }
$LSASecretCount    = if ($ForestClassMap.ContainsKey('secret'))       { $ForestClassMap['secret']       } else { 0 }

$HeritageRows = @()
if ($IPSecCount -gt 0) {
    $HeritageRows += [PSCustomObject]@{
        Type='Heritage'; Item='IPSec Legacy Policy Objects'; Count=$IPSecCount
        Description='Pre-Server 2008 IPSec policies (NFA, Negotiation, ISAKMP, Policy, Filter). Replaced by Windows Firewall with Advanced Security Connection Security Rules.'
        Recommendation='Audit GPO references; safe to remove if no GPO points to them.'
    }
}
if ($NTFRSCount -gt 0) {
    $HeritageRows += [PSCustomObject]@{
        Type='Heritage'; Item='NTFRS Replication Objects'; Count=$NTFRSCount
        Description='Pre-Server 2008 R2 File Replication Service objects. Superseded by DFSR for SYSVOL replication.'
        Recommendation='Confirm DFSR migration is complete (dfsrmig /getmigrationstate).'
    }
}
if ($DomainPolicyCount -gt 0) {
    $HeritageRows += [PSCustomObject]@{
        Type='Heritage'; Item='NT4-Era Domain Policy'; Count=$DomainPolicyCount
        Description='Legacy domainPolicy objects retained for NT4 SAM compatibility.'
        Recommendation='Obsolete; typically left in place because they are harmless.'
    }
}
if ($LinkTrackCount -gt 0) {
    $HeritageRows += [PSCustomObject]@{
        Type='Heritage'; Item='Distributed Link Tracking'; Count=$LinkTrackCount
        Description='Link tracking volume and move tables. The DLT service is disabled by default in modern Windows.'
        Recommendation='Safe to ignore; can be cleaned if confirmed unused.'
    }
}
if ($LSASecretCount -gt 0) {
    $HeritageRows += [PSCustomObject]@{
        Type='Audit'; Item='LSA Secrets'; Count=$LSASecretCount
        Description='Stored under CN=System: trust passwords, computer account secrets, and historically DPAPI master keys.'
        Recommendation='Review contents and confirm expected; investigate any unfamiliar entries.'
    }
}
if ($ForestUnknownCount -gt 0) {
    $HeritageRows += [PSCustomObject]@{
        Type='Audit'; Item='Tombstoned / No objectClass'; Count=$ForestUnknownCount
        Description='Objects returned without a resolvable objectClass attribute.'
        Recommendation='Will clear after garbage collection (every 12 hours by default).'
    }
}
if ($ForestTotals.Empty -gt 0) {
    $HeritageRows += [PSCustomObject]@{
        Type='Audit'; Item='Empty Groups'; Count=$ForestTotals.Empty
        Description='Groups with zero direct members.'
        Recommendation='Review for retirement; some are placeholders for future use.'
    }
}
if ($ForestTotals.StaleComp90 -gt 0) {
    $HeritageRows += [PSCustomObject]@{
        Type='Audit'; Item='Stale Computers (90d+)'; Count=$ForestTotals.StaleComp90
        Description='Computer accounts with PasswordLastSet older than 90 days; usually offline or decommissioned hosts.'
        Recommendation='Disable or remove if confirmed offline.'
    }
}
if ($ForestTotals.NeverLoggedOn -gt 0) {
    $HeritageRows += [PSCustomObject]@{
        Type='Audit'; Item='Never Logged On (Enabled)'; Count=$ForestTotals.NeverLoggedOn
        Description='Enabled user accounts that have never logged in.'
        Recommendation='Provisioned but unused -- disable, delete, or chase up the request.'
    }
}
if ($ForestTotals.PwdNeverExp -gt 0) {
    $HeritageRows += [PSCustomObject]@{
        Type='Audit'; Item='Password Never Expires'; Count=$ForestTotals.PwdNeverExp
        Description='User accounts with PasswordNeverExpires=True.'
        Recommendation='Acceptable for service accounts; otherwise an audit finding.'
    }
}

$HeritageTable = if ($HeritageRows.Count -gt 0) { ConvertTo-HtmlTable -Data $HeritageRows -Properties Type, Item, Count, Description, Recommendation } else { '<p class="empty-note">No heritage or cleanup candidates detected.</p>' }
$HeritageTotal = ($HeritageRows | Measure-Object -Property Count -Sum).Sum
if (-not $HeritageTotal) { $HeritageTotal = 0 }

# Forest unknown footnote
$ForestUnknownNote = if ($ForestUnknownCount -gt 0) {
    "<p class='section-desc' style='color:var(--amber)'>Note: $ForestUnknownCount object(s) were returned without a resolvable objectClass. These are typically tombstoned objects awaiting garbage collection or replication artifacts -- not a data quality issue with the script.</p>"
} else { '' }

# Charts JSON
$UserChartJSON  = '{"Enabled":' + $ForestTotals.EnabledUsers + ',"Disabled":' + $ForestTotals.DisabledUsers + ',"Locked":' + $ForestTotals.LockedUsers + ',"PwdNeverExp":' + $ForestTotals.PwdNeverExp + ',"PwdExpired":' + $ForestTotals.PwdExpired + ',"NeverLoggedOn":' + $ForestTotals.NeverLoggedOn + ',"Inactive90d":' + $ForestTotals.Inactive90 + '}'
$CompChartJSON  = '{"Enabled":' + $ForestTotals.EnabledComp + ',"Disabled":' + $ForestTotals.DisabledComp + ',"Servers":' + $ForestTotals.Servers + ',"Workstations":' + $ForestTotals.Workstations + ',"Stale90d":' + $ForestTotals.StaleComp90 + '}'
$GroupChartJSON = '{"Security":' + $ForestTotals.Security + ',"Distribution":' + $ForestTotals.Distribution + ',"Global":' + $ForestTotals.Global + ',"DomainLocal":' + $ForestTotals.DomainLocal + ',"Universal":' + $ForestTotals.Universal + ',"Empty":' + $ForestTotals.Empty + '}'
$GPOChartJSON   = '{"Enabled":' + $ForestTotals.EnabledGPO + ',"Disabled":' + $ForestTotals.DisabledGPO + ',"UserSettingsDisabled":' + $ForestTotals.UserSettingsDisabledGPO + ',"CompSettingsDisabled":' + $ForestTotals.CompSettingsDisabledGPO + '}'
$DNSChartJSON   = '{"Forward":' + $DNSForwardCount + ',"Reverse":' + $DNSReverseCount + ',"ADIntegrated":' + $DNSIntegrated + ',"FileBacked":' + $DNSFileBacked + ',"Signed":' + $DNSSigned + '}'

$TopClasses = $ForestClassRows | Select-Object -First 8
$OtherCount = ($ForestClassRows | Select-Object -Skip 8 | Measure-Object -Property Count -Sum).Sum
if (-not $OtherCount) { $OtherCount = 0 }
$ClassChartObj = [ordered]@{}
foreach ($t in $TopClasses) { $ClassChartObj[(Get-FriendlyClassName $t.ObjectClass)] = $t.Count }
if ($OtherCount -gt 0) { $ClassChartObj['Other'] = $OtherCount }
$ClassChartJSON = ($ClassChartObj | ConvertTo-Json -Compress)

# Category aggregation chart
$CategoryAggregation = @{}
foreach ($r in $ForestClassRows) {
    $cat = $r.Category
    if ($CategoryAggregation.ContainsKey($cat)) { $CategoryAggregation[$cat] += $r.Count }
    else { $CategoryAggregation[$cat] = $r.Count }
}
$CategoryChartObj = [ordered]@{}
foreach ($k in ($CategoryAggregation.GetEnumerator() | Sort-Object Value -Descending)) {
    $CategoryChartObj[$k.Key] = $k.Value
}
$CategoryChartJSON = ($CategoryChartObj | ConvertTo-Json -Compress)

$FW_OSDist = @{}
foreach ($domName in $ForestDomains) {
    if (-not $AllDomainData.ContainsKey($domName)) { continue }
    foreach ($k in $AllDomainData[$domName].OSDist.Keys) {
        if ($FW_OSDist.ContainsKey($k)) { $FW_OSDist[$k] += $AllDomainData[$domName].OSDist[$k] }
        else { $FW_OSDist[$k] = $AllDomainData[$domName].OSDist[$k] }
    }
}
$OSDistJSON = ($FW_OSDist.GetEnumerator() | Sort-Object Value -Descending |
    ForEach-Object { [PSCustomObject]@{os=$_.Key; count=$_.Value} } |
    ConvertTo-Json -Depth 2 -Compress)
if (-not $OSDistJSON) { $OSDistJSON = '[]' }

$DomObjCountObj = [ordered]@{}
foreach ($domName in $ForestDomains) {
    if (-not $AllDomainData.ContainsKey($domName)) { continue }
    $DomObjCountObj[$domName] = $AllDomainData[$domName].TotalObjects
}
$DomObjCountJSON = ($DomObjCountObj | ConvertTo-Json -Compress)

# ----- Per-Domain stacked-bar JSON (v1.5) -----
function New-PerDomainChartData {
    param([string[]]$Labels,[scriptblock]$ValueExtractor)
    $obj = [PSCustomObject]@{ labels = $Labels; domains = @() }
    foreach ($domName in $ForestDomains) {
        if (-not $AllDomainData.ContainsKey($domName)) { continue }
        $dd = $AllDomainData[$domName]
        $values = & $ValueExtractor $dd
        $obj.domains += [PSCustomObject]@{ name = $domName; values = @($values) }
    }
    return ($obj | ConvertTo-Json -Compress -Depth 5)
}

$PerDomainUserChartJSON = New-PerDomainChartData `
    -Labels @('Enabled','Disabled','Locked','Pwd Never Exp','Pwd Expired','Never Logged On','Inactive 90d') `
    -ValueExtractor { param($d) @($d.EnabledUsers, $d.DisabledUsers, $d.LockedUsers, $d.PwdNeverExp, $d.PwdExpired, $d.NeverLoggedOn, $d.Inactive90) }

$PerDomainComputerChartJSON = New-PerDomainChartData `
    -Labels @('Enabled','Disabled','Servers','Workstations','Stale 90d') `
    -ValueExtractor { param($d) @($d.EnabledComp, $d.DisabledComp, $d.Servers, $d.Workstations, $d.StaleComp90) }

$PerDomainGroupChartJSON = New-PerDomainChartData `
    -Labels @('Security','Distribution','Global','DomainLocal','Universal','Empty','Builtin','Privileged') `
    -ValueExtractor { param($d) @($d.Security, $d.Distribution, $d.Global, $d.DomainLocal, $d.Universal, $d.Empty, $d.BuiltinGrp, $d.Privileged) }

$PerDomainGPOChartJSON = New-PerDomainChartData `
    -Labels @('All Enabled','All Disabled','User Settings Off','Comp Settings Off') `
    -ValueExtractor { param($d) @($d.EnabledGPO, $d.DisabledGPO, $d.UserDisabledGPO, $d.CompDisabledGPO) }

# Per-domain object category breakdown
$PdCategoryLabels = @('Identity','Structure','Policy','Security','Replication','DNS','Service Account','Resource','Topology','Display','PKI','IPSec','Trust','Exchange','System','Other')
$PdCategoryObj = [PSCustomObject]@{ labels = $PdCategoryLabels; domains = @() }
foreach ($domName in $ForestDomains) {
    if (-not $AllDomainData.ContainsKey($domName)) { continue }
    $dd = $AllDomainData[$domName]
    $catCounts = @{}
    foreach ($cls in $dd.ClassMap.Keys) {
        $cat = Get-ClassCategory $cls
        if ($catCounts.ContainsKey($cat)) { $catCounts[$cat] += $dd.ClassMap[$cls] } else { $catCounts[$cat] = $dd.ClassMap[$cls] }
    }
    $values = @()
    foreach ($lbl in $PdCategoryLabels) {
        $values += if ($catCounts.ContainsKey($lbl)) { [int]$catCounts[$lbl] } else { 0 }
    }
    $PdCategoryObj.domains += [PSCustomObject]@{ name = $domName; values = @($values) }
}
$PerDomainCategoryChartJSON = ($PdCategoryObj | ConvertTo-Json -Compress -Depth 5)

# ==============================================================================
# PER-DOMAIN HTML
# ==============================================================================
$PerDomainHTML = [System.Text.StringBuilder]::new()

foreach ($domName in $ForestDomains) {
    if (-not $AllDomainData.ContainsKey($domName)) { continue }
    $dd = $AllDomainData[$domName]
    $domId = $domName -replace '[\.\s]','-'

    $classRows = $dd.ClassMap.GetEnumerator() | ForEach-Object {
        $cls = $_.Key; $cnt = $_.Value
        $pct = if ($dd.TotalObjects -gt 0) { [math]::Round(($cnt * 100.0 / $dd.TotalObjects),2) } else { 0 }
        [PSCustomObject]@{
            Category    = Get-ClassCategory $cls
            FriendlyName= Get-FriendlyClassName $cls
            ObjectClass = $cls
            Count       = $cnt
            Percent     = "$pct %"
        }
    } | Sort-Object Count -Descending
    $classTbl = ConvertTo-HtmlTable -Data $classRows -Properties Category, FriendlyName, ObjectClass, Count, Percent

    # Per-domain unknown footnote
    $domUnknownNote = if ($dd.UnknownCount -gt 0) {
        "<p class='section-desc' style='color:var(--amber)'>$($dd.UnknownCount) object(s) returned with no objectClass attribute -- typically tombstoned-but-not-yet-collected objects or replication artifacts.</p>"
    } else { '' }

    $dcTbl = if (@($dd.DCs).Count -gt 0) { ConvertTo-HtmlTable -Data $dd.DCs -Properties Name, IPv4Address, Type, OperatingSystem, OSVersion, Site, IsGlobalCatalog, FSMORoles } else { '<p class="empty-note">No DCs.</p>' }

    $ouShown = $dd.OUList | Select-Object -First 200
    $ouTbl   = if (@($ouShown).Count -gt 0) { ConvertTo-HtmlTable -Data $ouShown -Properties Name, DistinguishedName, ProtectedFromAccidentalDeletion, Description } else { '<p class="empty-note">No OUs.</p>' }
    $ouNote  = if (@($dd.OUList).Count -gt 200) { "<p class='section-desc'>Showing first 200 of $(@($dd.OUList).Count) OUs.</p>" } else { '' }

    $gpoShown = $dd.GPOList | Select-Object -First 200
    $gpoTbl   = if (@($gpoShown).Count -gt 0) { ConvertTo-HtmlTable -Data $gpoShown -Properties DisplayName, GpoStatus, CreationTime, ModificationTime, Owner } else { '<p class="empty-note">No GPOs.</p>' }
    $gpoNote  = if (@($dd.GPOList).Count -gt 200) { "<p class='section-desc'>Showing first 200 of $(@($dd.GPOList).Count) GPOs.</p>" } else { '' }

    $svcTbl = if (@($dd.SvcList).Count -gt 0) { ConvertTo-HtmlTable -Data $dd.SvcList -Properties Name, SamAccountName, Type, Enabled, Created } else { '<p class="empty-note">No service accounts (sMSA / gMSA / dMSA).</p>' }

    $ppHTML = '<p class="empty-note">No default password policy.</p>'
    if ($dd.PwdPolicy) {
        $pp = $dd.PwdPolicy
        $ppHTML = @"
<div class="info-grid">
  <div class="info-card"><span class="info-label">Min Password Length</span><span class="info-value">$($pp.MinPasswordLength)</span></div>
  <div class="info-card"><span class="info-label">Password History</span><span class="info-value">$($pp.PasswordHistoryCount)</span></div>
  <div class="info-card"><span class="info-label">Complexity Enabled</span><span class="info-value">$($pp.ComplexityEnabled)</span></div>
  <div class="info-card"><span class="info-label">Reversible Encryption</span><span class="info-value">$($pp.ReversibleEncryptionEnabled)</span></div>
  <div class="info-card"><span class="info-label">Min Password Age</span><span class="info-value">$($pp.MinPasswordAge)</span></div>
  <div class="info-card"><span class="info-label">Max Password Age</span><span class="info-value">$($pp.MaxPasswordAge)</span></div>
  <div class="info-card"><span class="info-label">Lockout Threshold</span><span class="info-value">$($pp.LockoutThreshold)</span></div>
  <div class="info-card"><span class="info-label">Lockout Duration</span><span class="info-value">$($pp.LockoutDuration)</span></div>
  <div class="info-card"><span class="info-label">Lockout Window</span><span class="info-value">$($pp.LockoutObservationWindow)</span></div>
</div>
"@
    }

    $fgppTbl = if (@($dd.FGPPs).Count -gt 0) { ConvertTo-HtmlTable -Data $dd.FGPPs -Properties Name, Precedence, MinPasswordLength, ComplexityEnabled, MaxPasswordAge, MinPasswordAge, PasswordHistoryCount, LockoutThreshold, LockoutDuration, AppliesTo } else { '<p class="empty-note">No fine-grained password policies.</p>' }

    [void]$PerDomainHTML.AppendLine(@"

<!-- DOMAIN: $domName -->
<div id="dom-$domId" class="section">
  <h2 class="domain-header">Domain: $($dd.DomainName)</h2>
  <div class="info-grid">
    <div class="info-card"><span class="info-label">NetBIOS</span><span class="info-value">$($dd.NetBIOS)</span></div>
    <div class="info-card"><span class="info-label">Functional Level</span><span class="info-value">$($dd.DomainMode)</span></div>
    <div class="info-card"><span class="info-label">Parent Domain</span><span class="info-value">$($dd.Parent)</span></div>
    <div class="info-card"><span class="info-label">PDC Emulator</span><span class="info-value">$($dd.PDC)</span></div>
    <div class="info-card"><span class="info-label">Domain DN</span><span class="info-value">$($dd.DN)</span></div>
    <div class="info-card"><span class="info-label">Total Objects</span><span class="info-value" style="color:var(--accent2)">$($dd.TotalObjects)</span></div>
  </div>

  <h3 class="sub-header">Object Class Census ($($dd.ClassMap.Count) distinct classes)</h3>
  <p class="section-desc">Every object in the domain naming context grouped by its most-specific objectClass. This is the headline view -- a complete inventory of what is in this domain.</p>
  $domUnknownNote
  $classTbl

  <h3 class="sub-header">Domain Controllers ($(@($dd.DCs).Count))</h3>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent)">$(@($dd.DCs).Count)</div><div class="card-label">Total DCs</div></div>
    <div class="card"><div class="card-val" style="color:var(--green)">$(@($dd.DCs | Where-Object {$_.Type -eq 'RWDC'}).Count)</div><div class="card-label">RWDC</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$(@($dd.DCs | Where-Object {$_.Type -eq 'RODC'}).Count)</div><div class="card-label">RODC</div></div>
    <div class="card"><div class="card-val" style="color:var(--accent2)">$(@($dd.DCs | Where-Object {$_.IsGlobalCatalog}).Count)</div><div class="card-label">Global Catalog</div></div>
  </div>
  $dcTbl

  <h3 class="sub-header">User Accounts ($($dd.TotalUsers))</h3>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent)">$($dd.TotalUsers)</div><div class="card-label">Total</div></div>
    <div class="card"><div class="card-val" style="color:var(--green)">$($dd.EnabledUsers)</div><div class="card-label">Enabled</div></div>
    <div class="card"><div class="card-val" style="color:var(--red)">$($dd.DisabledUsers)</div><div class="card-label">Disabled</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$($dd.LockedUsers)</div><div class="card-label">Locked</div></div>
    <div class="card"><div class="card-val" style="color:var(--orange)">$($dd.PwdExpired)</div><div class="card-label">Pwd Expired</div></div>
    <div class="card"><div class="card-val" style="color:var(--pink)">$($dd.PwdNeverExp)</div><div class="card-label">Pwd Never Exp</div></div>
    <div class="card"><div class="card-val" style="color:var(--purple)">$($dd.NeverLoggedOn)</div><div class="card-label">Never Logged On</div></div>
    <div class="card"><div class="card-val" style="color:var(--text-dim)">$($dd.Inactive90)</div><div class="card-label">Inactive 90d+</div></div>
    <div class="card"><div class="card-val" style="color:var(--accent2)">$($dd.AdminCount)</div><div class="card-label">AdminCount=1</div></div>
    <div class="card"><div class="card-val" style="color:var(--green)">$($dd.SmartCardReq)</div><div class="card-label">SmartCard Req</div></div>
  </div>

  <h3 class="sub-header">Computer Accounts ($($dd.TotalComputers))</h3>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent)">$($dd.TotalComputers)</div><div class="card-label">Total</div></div>
    <div class="card"><div class="card-val" style="color:var(--green)">$($dd.EnabledComp)</div><div class="card-label">Enabled</div></div>
    <div class="card"><div class="card-val" style="color:var(--red)">$($dd.DisabledComp)</div><div class="card-label">Disabled</div></div>
    <div class="card"><div class="card-val" style="color:var(--purple)">$($dd.Servers)</div><div class="card-label">Servers</div></div>
    <div class="card"><div class="card-val" style="color:var(--accent2)">$($dd.Workstations)</div><div class="card-label">Workstations</div></div>
    <div class="card"><div class="card-val" style="color:var(--orange)">$($dd.StaleComp90)</div><div class="card-label">Stale 90d+</div></div>
  </div>

  <h3 class="sub-header">Groups ($($dd.TotalGroups))</h3>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent)">$($dd.TotalGroups)</div><div class="card-label">Total</div></div>
    <div class="card"><div class="card-val" style="color:var(--green)">$($dd.Security)</div><div class="card-label">Security</div></div>
    <div class="card"><div class="card-val" style="color:var(--accent2)">$($dd.Distribution)</div><div class="card-label">Distribution</div></div>
    <div class="card"><div class="card-val" style="color:var(--purple)">$($dd.Global)</div><div class="card-label">Global</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$($dd.DomainLocal)</div><div class="card-label">Domain Local</div></div>
    <div class="card"><div class="card-val" style="color:var(--pink)">$($dd.Universal)</div><div class="card-label">Universal</div></div>
    <div class="card"><div class="card-val" style="color:var(--text-dim)">$($dd.Empty)</div><div class="card-label">Empty</div></div>
    <div class="card"><div class="card-val" style="color:var(--orange)">$($dd.BuiltinGrp)</div><div class="card-label">Builtin</div></div>
    <div class="card"><div class="card-val" style="color:var(--red)">$($dd.Privileged)</div><div class="card-label">Privileged (Admin)</div></div>
  </div>

  <h3 class="sub-header">Organizational Units ($($dd.TotalOUs))</h3>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent)">$($dd.TotalOUs)</div><div class="card-label">Total OUs</div></div>
    <div class="card"><div class="card-val" style="color:var(--green)">$($dd.ProtectedOUs)</div><div class="card-label">Protected</div></div>
    <div class="card"><div class="card-val" style="color:var(--red)">$($dd.TotalOUs - $dd.ProtectedOUs)</div><div class="card-label">NOT Protected</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$($dd.ContainerCount)</div><div class="card-label">Containers (CN)</div></div>
  </div>
  $ouNote
  $ouTbl

  <h3 class="sub-header">Group Policy Objects ($($dd.TotalGPOs))</h3>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent)">$($dd.TotalGPOs)</div><div class="card-label">Total</div></div>
    <div class="card"><div class="card-val" style="color:var(--green)">$($dd.EnabledGPO)</div><div class="card-label">All Enabled</div></div>
    <div class="card"><div class="card-val" style="color:var(--red)">$($dd.DisabledGPO)</div><div class="card-label">All Disabled</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$($dd.UserDisabledGPO)</div><div class="card-label">User Settings Off</div></div>
    <div class="card"><div class="card-val" style="color:var(--orange)">$($dd.CompDisabledGPO)</div><div class="card-label">Comp Settings Off</div></div>
  </div>
  $gpoNote
  $gpoTbl

  <h3 class="sub-header">Service Accounts (sMSA: $($dd.sMSACount) | gMSA: $($dd.gMSACount) | dMSA: $($dd.dMSACount))</h3>
  $svcTbl

  <h3 class="sub-header">Other Object Categories</h3>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent)">$($dd.ContactCount)</div><div class="card-label">Contacts</div></div>
    <div class="card"><div class="card-val" style="color:var(--purple)">$($dd.PrinterCount)</div><div class="card-label">Printers</div></div>
    <div class="card"><div class="card-val" style="color:var(--pink)">$($dd.FSPCount)</div><div class="card-label">Foreign Sec. Principals</div></div>
    <div class="card"><div class="card-val" style="color:var(--accent2)">$($dd.BitLockerKeys)</div><div class="card-label">BitLocker Keys</div></div>
  </div>

  <h3 class="sub-header">Default Domain Password Policy</h3>
  $ppHTML

  <h3 class="sub-header">Fine-Grained Password Policies ($(@($dd.FGPPs).Count))</h3>
  $fgppTbl
</div>
"@)
}

$DomainNavLinks = ($ForestDomains | ForEach-Object {
    $id = $_ -replace '[\.\s]','-'
    "    <a href=`"#dom-$id`">$_</a>"
}) -join "`n"

# ==============================================================================
# HTML REPORT
# ==============================================================================
$HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="author" content="Santhosh Sivarajan, Microsoft MVP"/>
<title>ADObjectCanvas -- $($Forest.Name)</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0f172a;--surface:#1e293b;--surface2:#273548;--border:#334155;
  --text:#e2e8f0;--text-dim:#94a3b8;--accent:#60a5fa;--accent2:#22d3ee;
  --green:#34d399;--red:#f87171;--amber:#fbbf24;--purple:#a78bfa;
  --pink:#f472b6;--orange:#fb923c;--accent-bg:rgba(96,165,250,.1);
  --radius:8px;--shadow:0 1px 3px rgba(0,0,0,.3);
  --font-body:'Segoe UI',system-ui,-apple-system,sans-serif;
}
html{scroll-behavior:smooth;font-size:15px}
body{font-family:var(--font-body);background:var(--bg);color:var(--text);line-height:1.65;min-height:100vh}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.wrapper{display:flex;min-height:100vh}
.sidebar{position:fixed;top:0;left:0;width:260px;height:100vh;background:var(--surface);border-right:1px solid var(--border);overflow-y:auto;padding:20px 0;z-index:100;box-shadow:2px 0 12px rgba(0,0,0,.3)}
.sidebar::-webkit-scrollbar{width:4px}.sidebar::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}
.sidebar .logo{padding:0 18px 14px;border-bottom:1px solid var(--border);margin-bottom:8px}
.sidebar .logo h2{font-size:1.05rem;color:var(--accent);font-weight:700}
.sidebar .logo p{font-size:.68rem;color:var(--text-dim);margin-top:2px}
.sidebar nav a{display:block;padding:5px 18px 5px 22px;font-size:.78rem;color:var(--text-dim);border-left:3px solid transparent;transition:all .15s}
.sidebar nav a:hover,.sidebar nav a.active{color:var(--accent);background:rgba(96,165,250,.08);border-left-color:var(--accent);text-decoration:none}
.sidebar nav .nav-group{font-size:.62rem;text-transform:uppercase;letter-spacing:.08em;color:var(--accent2);padding:10px 18px 2px;font-weight:700}
.main{margin-left:260px;flex:1;padding:24px 32px 50px;max-width:1200px}
.section{margin-bottom:36px}
.section-title{font-size:1.25rem;font-weight:700;color:var(--text);margin-bottom:4px;padding-bottom:8px;border-bottom:2px solid var(--border);display:flex;align-items:center;gap:8px}
.section-title .icon{width:24px;height:24px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:.8rem;flex-shrink:0}
.domain-header{font-size:1.35rem;color:var(--accent);border-bottom:2px solid var(--accent);padding-bottom:8px;margin-top:24px;margin-bottom:8px}
.sub-header{font-size:.92rem;color:var(--text);margin:16px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--border)}
.section-desc{color:var(--text-dim);font-size:.84rem;margin-bottom:14px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:16px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;box-shadow:var(--shadow)}
.card:hover{border-color:var(--accent)}
.card .card-val{font-size:1.5rem;font-weight:800;line-height:1.1}
.card .card-label{font-size:.68rem;color:var(--text-dim);margin-top:2px;text-transform:uppercase;letter-spacing:.05em}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px;margin-bottom:14px}
.info-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:10px 14px;box-shadow:var(--shadow)}
.info-label{display:block;font-size:.68rem;color:var(--text-dim);text-transform:uppercase;letter-spacing:.05em;margin-bottom:2px}
.info-value{font-size:.95rem;font-weight:600;color:var(--text)}
.table-wrap{overflow-x:auto;margin-bottom:8px;border-radius:var(--radius);border:1px solid var(--border);box-shadow:var(--shadow);max-height:520px}
table{width:100%;border-collapse:collapse;font-size:.78rem}
thead{background:var(--accent-bg);position:sticky;top:0}
th{text-align:left;padding:8px 10px;font-weight:600;color:var(--accent);white-space:nowrap;border-bottom:2px solid var(--border)}
td{padding:7px 10px;border-bottom:1px solid var(--border);color:var(--text-dim);max-width:360px;overflow:hidden;text-overflow:ellipsis}
tbody tr:hover{background:rgba(96,165,250,.06)}
tbody tr:nth-child(even){background:var(--surface2)}
.empty-note{color:var(--text-dim);font-style:italic;padding:8px 0}
.exec-summary{background:linear-gradient(135deg,#1e293b 0%,#1e3a5f 100%);border:1px solid #334155;border-radius:var(--radius);padding:22px 26px;margin-bottom:28px;box-shadow:var(--shadow)}
.exec-summary h2{font-size:1.1rem;color:var(--accent);margin-bottom:8px}
.exec-summary p{color:var(--text-dim);font-size:.86rem;line-height:1.7;margin-bottom:6px}
.exec-kv{display:inline-block;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:2px 8px;margin:2px;font-size:.78rem;color:var(--text)}
.exec-kv strong{color:var(--accent2)}
.big-num{font-size:2.5rem;font-weight:900;color:var(--accent2);line-height:1}
.big-num-label{font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;color:var(--text-dim);margin-top:4px}
.big-num-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin:14px 0 22px}
.big-num-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 20px;text-align:center;box-shadow:var(--shadow)}
.footer{margin-top:36px;padding:18px 0;border-top:1px solid var(--border);text-align:center;color:var(--text-dim);font-size:.74rem}
.footer a{color:var(--accent)}
@media print{.sidebar{display:none}.main{margin-left:0}body{background:#fff;color:#222}
  .card,.info-card,.exec-summary,.big-num-card{background:#f9f9f9;border-color:#ccc;color:#222}
  .card-val,.info-value,.section-title,.domain-header,.big-num{color:#222}
  .card-label,.info-label,.section-desc,.big-num-label{color:#555}
  th{color:#333;background:#eee}td{color:#444}}
@media(max-width:900px){.sidebar{display:none}.main{margin-left:0;padding:14px}}
</style>
</head>
<body>
<div class="wrapper">
<aside class="sidebar">
  <div class="logo">
    <h2>ADObjectCanvas</h2>
    <p>Developed by Santhosh Sivarajan</p>
    <p style="margin-top:6px">Forest: <strong style="color:#e2e8f0">$($Forest.Name)</strong></p>
  </div>
  <nav>
    <div class="nav-group">Overview</div>
    <a href="#exec-summary">Executive Summary</a>
    <a href="#forest-summary">Forest Summary</a>
    <a href="#all-dcs">All Domain Controllers</a>
    <a href="#object-class-census">Object Class Census</a>
    <a href="#config-nc">Configuration NC</a>
    <a href="#dns-partitions">DNS Partitions</a>
    <a href="#heritage">Heritage &amp; Cleanup</a>
    <div class="nav-group">Domains ($($ForestDomains.Count))</div>
$DomainNavLinks
    <div class="nav-group">Configuration</div>
    <a href="#trusts">Trust Relationships</a>
    <a href="#dns">DNS Zones</a>
    <a href="#sites-subnets">Sites &amp; Subnets</a>
    <a href="#schema">Schema</a>
    <div class="nav-group">Visuals</div>
    <a href="#charts-overview">Charts</a>
  </nav>
</aside>
<main class="main">

<div id="exec-summary" class="section">
  <div class="exec-summary">
    <h2>ADObjectCanvas -- $($Forest.Name)</h2>
    <p>Point-in-time inventory of every object in the Active Directory forest <strong>$($Forest.Name)</strong>, generated on <strong>$(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm")</strong>.
    The headline number below is the total count of objects across all domain naming contexts. Drill into each domain section for a complete object class census, plus per-class breakdowns.</p>
    <p style="margin-top:8px">
      <span class="exec-kv">Forest Mode: <strong>$ForestModeDisplay</strong></span>
      <span class="exec-kv">Domains: <strong>$($ForestDomains.Count)</strong></span>
      <span class="exec-kv">DCs: <strong>$($AllForestDCs.Count)</strong></span>
      <span class="exec-kv">Schema: <strong>$SchemaOS (v$SchemaVersion)</strong></span>
      <span class="exec-kv">Recycle Bin: <strong>$(if($RecycleBinEnabled){'Enabled'}else{'Not Enabled'})</strong></span>
      <span class="exec-kv">Tombstone: <strong>$TombstoneLife days</strong></span>
    </p>
  </div>

  <div class="big-num-grid">
    <div class="big-num-card"><div class="big-num">$ForestObjectTotal</div><div class="big-num-label">Total AD Objects</div></div>
    <div class="big-num-card"><div class="big-num" style="color:var(--accent)">$($ForestTotals.Users)</div><div class="big-num-label">Users</div></div>
    <div class="big-num-card"><div class="big-num" style="color:var(--purple)">$($ForestTotals.Computers)</div><div class="big-num-label">Computers</div></div>
    <div class="big-num-card"><div class="big-num" style="color:var(--green)">$($ForestTotals.Groups)</div><div class="big-num-label">Groups</div></div>
    <div class="big-num-card"><div class="big-num" style="color:var(--amber)">$($ForestTotals.OUs)</div><div class="big-num-label">OUs</div></div>
    <div class="big-num-card"><div class="big-num" style="color:var(--pink)">$($ForestTotals.GPOs)</div><div class="big-num-label">GPOs</div></div>
    <div class="big-num-card"><div class="big-num" style="color:var(--orange)">$($AllForestDCs.Count)</div><div class="big-num-label">Domain Controllers</div></div>
    <div class="big-num-card"><div class="big-num" style="color:var(--accent2)">$($DNSZones.Count)</div><div class="big-num-label">DNS Zones</div></div>
  </div>
</div>

<div id="forest-summary" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#127760;</span> Forest Summary</h2>
  <div class="info-grid">
    <div class="info-card"><span class="info-label">Forest Name</span><span class="info-value">$($Forest.Name)</span></div>
    <div class="info-card"><span class="info-label">Forest Mode</span><span class="info-value">$ForestModeDisplay</span></div>
    <div class="info-card"><span class="info-label">Root Domain</span><span class="info-value">$RootDomain</span></div>
    <div class="info-card"><span class="info-label">Schema Master</span><span class="info-value">$SchemaMaster</span></div>
    <div class="info-card"><span class="info-label">Domain Naming Master</span><span class="info-value">$NamingMaster</span></div>
    <div class="info-card"><span class="info-label">AD Recycle Bin</span><span class="info-value" style="color:$(if($RecycleBinEnabled){'var(--green)'}else{'var(--red)'})">$(if($RecycleBinEnabled){'Enabled'}else{'Not Enabled'})</span></div>
    <div class="info-card"><span class="info-label">Tombstone Lifetime</span><span class="info-value">$TombstoneLife days</span></div>
    <div class="info-card"><span class="info-label">Schema Version</span><span class="info-value">$SchemaVersion ($SchemaOS)</span></div>
    <div class="info-card"><span class="info-label">Schema Classes</span><span class="info-value">$SchemaClasses</span></div>
    <div class="info-card"><span class="info-label">Schema Attributes</span><span class="info-value">$SchemaAttributes</span></div>
  </div>

  <h3 class="sub-header">Per-Domain Summary</h3>
  $DomainSummaryTable

  <h3 class="sub-header">Forest-Wide Object Totals</h3>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent2)">$ForestObjectTotal</div><div class="card-label">All Objects</div></div>
    <div class="card"><div class="card-val" style="color:var(--accent)">$($ForestTotals.Users)</div><div class="card-label">Users</div></div>
    <div class="card"><div class="card-val" style="color:var(--purple)">$($ForestTotals.Computers)</div><div class="card-label">Computers</div></div>
    <div class="card"><div class="card-val" style="color:var(--green)">$($ForestTotals.Groups)</div><div class="card-label">Groups</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$($ForestTotals.OUs)</div><div class="card-label">OUs</div></div>
    <div class="card"><div class="card-val" style="color:var(--pink)">$($ForestTotals.GPOs)</div><div class="card-label">GPOs</div></div>
    <div class="card"><div class="card-val" style="color:var(--orange)">$($ForestTotals.Containers)</div><div class="card-label">Containers</div></div>
    <div class="card"><div class="card-val" style="color:var(--accent2)">$($ForestTotals.Contacts)</div><div class="card-label">Contacts</div></div>
    <div class="card"><div class="card-val" style="color:var(--purple)">$($ForestTotals.Printers)</div><div class="card-label">Printers</div></div>
    <div class="card"><div class="card-val" style="color:var(--pink)">$($ForestTotals.FSPs)</div><div class="card-label">Foreign Sec. Principals</div></div>
    <div class="card"><div class="card-val" style="color:var(--green)">$($ForestTotals.sMSAs + $ForestTotals.gMSAs + $ForestTotals.dMSAs)</div><div class="card-label">Service Accounts</div></div>
    <div class="card"><div class="card-val" style="color:var(--accent)">$($ForestTotals.FGPPs)</div><div class="card-label">FGPPs</div></div>
    <div class="card"><div class="card-val" style="color:var(--accent2)">$($ForestTotals.BitLockerKeys)</div><div class="card-label">BitLocker Keys</div></div>
  </div>
</div>

<div id="all-dcs" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(34,211,238,.15);color:var(--accent2)">&#128187;</span> All Domain Controllers ($($AllForestDCs.Count))</h2>
  $AllDCsTable
</div>

<div id="object-class-census" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(167,139,250,.15);color:var(--purple)">&#128202;</span> Forest-Wide Object Class Census</h2>
  <p class="section-desc">Every distinct objectClass found across all domain naming contexts in the forest, with counts and percentages. Sorted by count.</p>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent2)">$ForestObjectTotal</div><div class="card-label">Total Objects</div></div>
    <div class="card"><div class="card-val" style="color:var(--accent)">$($ForestClassMap.Count)</div><div class="card-label">Distinct Classes</div></div>
  </div>
  $ForestUnknownNote
  $ForestClassTable
</div>

<div id="config-nc" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(34,211,238,.15);color:var(--accent2)">&#9881;</span> Configuration Naming Context</h2>
  <p class="section-desc">Forest-wide configuration partition (<code>$ConfigDN</code>). Contains site topology, services, ADCS templates, Exchange configuration, and similar forest-level objects. Counted separately from domain NCs because Configuration NC replicates to every DC in every domain in the forest.</p>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent2)">$ConfigTotalObjects</div><div class="card-label">Total Objects</div></div>
    <div class="card"><div class="card-val" style="color:var(--accent)">$($ConfigClassMap.Count)</div><div class="card-label">Distinct Classes</div></div>
  </div>
  $ConfigClassTable
</div>

<div id="dns-partitions" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#128268;</span> DNS Application Partitions</h2>
  <p class="section-desc">When DNS is AD-integrated, DNS records and zones live in dedicated application partitions (<code>DomainDnsZones</code>, <code>ForestDnsZones</code>) rather than in the domain NC. The bulk of <code>dnsNode</code> objects in your forest are typically here.</p>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent)">$($DnsPartitionList.Count)</div><div class="card-label">Partitions</div></div>
    <div class="card"><div class="card-val" style="color:var(--accent2)">$DnsTotalObjects</div><div class="card-label">Total Objects</div></div>
    <div class="card"><div class="card-val" style="color:var(--green)">$(if($DnsClassMap.ContainsKey('dnsNode')){$DnsClassMap['dnsNode']}else{0})</div><div class="card-label">DNS Records</div></div>
    <div class="card"><div class="card-val" style="color:var(--purple)">$(if($DnsClassMap.ContainsKey('dnsZone')){$DnsClassMap['dnsZone']}else{0})</div><div class="card-label">DNS Zones</div></div>
  </div>
  <h3 class="sub-header">Partitions</h3>
  $DnsPartitionTable
  <h3 class="sub-header">Object Class Breakdown</h3>
  $DnsClassTable
</div>

<div id="heritage" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(251,146,60,.15);color:var(--orange)">&#9874;</span> Heritage &amp; Cleanup Candidates</h2>
  <p class="section-desc">Legacy artifacts (replaced by newer technologies) and audit candidates surfaced from the inventory above. <strong>Heritage</strong> rows describe genuinely obsolete object types you may want to clean up. <strong>Audit</strong> rows flag things that are not necessarily wrong but should be reviewed -- empty groups, stale computers, accounts with non-expiring passwords, and similar.</p>
  <p class="section-desc" style="color:var(--amber);font-style:italic">Note: some counts depend on the running account's read permissions. Standard domain users cannot read every <code>secret</code> or <code>msFVE-RecoveryInformation</code> object; for accurate LSA Secret and BitLocker Recovery counts, run as a Domain Admin or equivalent.</p>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--orange)">$IPSecCount</div><div class="card-label">IPSec Legacy</div></div>
    <div class="card"><div class="card-val" style="color:var(--orange)">$NTFRSCount</div><div class="card-label">NTFRS Legacy</div></div>
    <div class="card"><div class="card-val" style="color:var(--orange)">$DomainPolicyCount</div><div class="card-label">NT4 Domain Policy</div></div>
    <div class="card"><div class="card-val" style="color:var(--orange)">$LinkTrackCount</div><div class="card-label">Link Tracking</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$LSASecretCount</div><div class="card-label">LSA Secrets</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$ForestUnknownCount</div><div class="card-label">Tombstoned</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$($ForestTotals.Empty)</div><div class="card-label">Empty Groups</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$($ForestTotals.StaleComp90)</div><div class="card-label">Stale Computers</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$($ForestTotals.NeverLoggedOn)</div><div class="card-label">Never Logged On</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$($ForestTotals.PwdNeverExp)</div><div class="card-label">Pwd Never Exp</div></div>
  </div>
  $HeritageTable
</div>

$($PerDomainHTML.ToString())

<div id="trusts" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(244,114,182,.15);color:var(--pink)">&#128279;</span> Trust Relationships ($($AllTrusts.Count))</h2>
  $TrustTable
</div>

<div id="dns" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#128268;</span> DNS Zones$(if($DNSServer){" (from $DNSServer)"})</h2>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent)">$($DNSZones.Count)</div><div class="card-label">Total Zones</div></div>
    <div class="card"><div class="card-val" style="color:var(--accent2)">$DNSForwardCount</div><div class="card-label">Forward</div></div>
    <div class="card"><div class="card-val" style="color:var(--purple)">$DNSReverseCount</div><div class="card-label">Reverse</div></div>
    <div class="card"><div class="card-val" style="color:var(--green)">$DNSIntegrated</div><div class="card-label">AD-Integrated</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$DNSFileBacked</div><div class="card-label">File-Backed</div></div>
    <div class="card"><div class="card-val" style="color:var(--pink)">$DNSSigned</div><div class="card-label">Signed (DNSSEC)</div></div>
  </div>
  $DNSTable
</div>

<div id="sites-subnets" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(34,211,238,.15);color:var(--accent2)">&#127760;</span> Sites &amp; Subnets</h2>
  <h3 class="sub-header">Sites ($($ADSites.Count))</h3>
  $SiteTable
  <h3 class="sub-header">Subnets ($($ADSubnets.Count))</h3>
  $SubnetTable
  <h3 class="sub-header">Site Links ($($ADSiteLinks.Count))</h3>
  $SiteLinkTbl
</div>

<div id="schema" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#128218;</span> Schema</h2>
  <div class="info-grid">
    <div class="info-card"><span class="info-label">Schema Version</span><span class="info-value">$SchemaVersion</span></div>
    <div class="info-card"><span class="info-label">Corresponds To</span><span class="info-value">$SchemaOS</span></div>
    <div class="info-card"><span class="info-label">Schema DN</span><span class="info-value">$SchemaDN</span></div>
    <div class="info-card"><span class="info-label">Class Definitions</span><span class="info-value">$SchemaClasses</span></div>
    <div class="info-card"><span class="info-label">Attribute Definitions</span><span class="info-value">$SchemaAttributes</span></div>
    <div class="info-card"><span class="info-label">Schema Master</span><span class="info-value">$SchemaMaster</span></div>
  </div>
</div>

<div id="charts-overview" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#128202;</span> Object Charts</h2>
  <p class="section-desc">Aggregated object distribution across all domains, plus side-by-side per-domain comparisons. Hover any segment for exact counts.</p>
  <h3 class="sub-header">Forest-Wide Distribution</h3>
  <div id="chartsContainer" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:14px;margin-bottom:20px"></div>
  <h3 class="sub-header">Per-Domain Breakdown</h3>
  <p class="section-desc">Each bar represents one domain, normalised to 100% so distribution shape is comparable regardless of absolute size. Total object count for each domain shown on the right.</p>
  <div id="perDomainChartsContainer" style="display:flex;flex-direction:column;gap:14px;margin-bottom:20px"></div>
</div>

<div class="footer">
  ADObjectCanvas v1.5 -- AD Object Inventory Report -- $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
  Developed by <a href="mailto:santhosh@sivarajan.com">Santhosh Sivarajan</a>, Microsoft MVP --
  <a href="https://github.com/SanthoshSivarajan/ADObjectCanvas">github.com/SanthoshSivarajan/ADObjectCanvas</a>
</div>

</main>
</div>

<script>
var COLORS=['#60a5fa','#34d399','#f87171','#fbbf24','#a78bfa','#f472b6','#22d3ee','#fb923c','#a3e635','#e879f9','#facc15','#94a3b8'];
function buildDonut(title,dataObj,container){
  var data=dataObj;
  if(typeof data==='string'){try{data=JSON.parse(data)}catch(e){return}}
  var entries=[];
  if(Array.isArray(data)){for(var i=0;i<data.length;i++){var k=data[i].os||data[i].name||data[i].label||'?';entries.push([k,data[i].count||data[i].value||0])}}
  else {for(var k in data) entries.push([k,data[k]])}
  var total=0; for(var i=0;i<entries.length;i++) total+=entries[i][1];
  if(total===0) return;
  var box=document.createElement('div');
  box.style.cssText='background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:18px;box-shadow:var(--shadow)';
  box.innerHTML='<h3 style="font-size:.88rem;margin-bottom:12px;color:var(--text)">'+title+'</h3>';
  var d=document.createElement('div');d.style.cssText='display:flex;align-items:center;gap:18px;flex-wrap:wrap';
  var sv='<svg viewBox="0 0 100 100" width="140" height="140" style="flex-shrink:0">';
  var cx=50,cy=50,r=40,sa=-90;
  for(var i=0;i<entries.length;i++){
    var v=entries[i][1]; if(v===0) continue;
    var pct=v/total; var ang=pct*360;
    var ea=sa+ang;
    var x1=cx+r*Math.cos(sa*Math.PI/180), y1=cy+r*Math.sin(sa*Math.PI/180);
    var x2=cx+r*Math.cos(ea*Math.PI/180), y2=cy+r*Math.sin(ea*Math.PI/180);
    var lf=ang>180?1:0;
    sv+='<path d="M '+cx+','+cy+' L '+x1+','+y1+' A '+r+','+r+' 0 '+lf+',1 '+x2+','+y2+' Z" fill="'+COLORS[i%COLORS.length]+'"/>';
    sa=ea;
  }
  sv+='<circle cx="'+cx+'" cy="'+cy+'" r="22" fill="var(--surface)"/>';
  sv+='<text x="'+cx+'" y="'+(cy-2)+'" text-anchor="middle" font-size="9" fill="#e2e8f0" font-weight="700">'+total+'</text>';
  sv+='<text x="'+cx+'" y="'+(cy+9)+'" text-anchor="middle" font-size="5" fill="#94a3b8">total</text>';
  sv+='</svg>';
  d.innerHTML+=sv;
  var lg=document.createElement('div');lg.style.cssText='font-size:.74rem;flex:1;min-width:140px';
  for(var i=0;i<entries.length;i++){
    var v=entries[i][1]; var pct=total>0?((v/total)*100).toFixed(1):0;
    var item=document.createElement('div');item.style.cssText='margin-bottom:3px;display:flex;align-items:center;gap:6px';
    item.innerHTML='<span style="display:inline-block;width:10px;height:10px;background:'+COLORS[i%COLORS.length]+';border-radius:2px;flex-shrink:0"></span><span style="color:var(--text-dim);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+entries[i][0]+'</span><span style="color:var(--text);font-weight:600">'+v+' ('+pct+'%)</span>';
    lg.appendChild(item);
  }
  d.appendChild(lg);
  box.appendChild(d);
  container.appendChild(box);
}
function buildBarChart(title,dataObj,container){
  var data=dataObj;
  if(typeof data==='string'){try{data=JSON.parse(data)}catch(e){return}}
  var entries=[]; for(var k in data) entries.push([k,data[k]]);
  if(entries.length===0) return;
  var max=0; for(var i=0;i<entries.length;i++) if(entries[i][1]>max) max=entries[i][1];
  if(max===0) return;
  var box=document.createElement('div');
  box.style.cssText='background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:18px;box-shadow:var(--shadow)';
  box.innerHTML='<h3 style="font-size:.88rem;margin-bottom:12px;color:var(--text)">'+title+'</h3>';
  var list=document.createElement('div');list.style.cssText='font-size:.74rem';
  for(var i=0;i<entries.length;i++){
    var v=entries[i][1]; var pct=(v/max)*100;
    var row=document.createElement('div');row.style.cssText='margin-bottom:6px';
    row.innerHTML='<div style="display:flex;justify-content:space-between;margin-bottom:2px"><span style="color:var(--text-dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:60%">'+entries[i][0]+'</span><span style="color:var(--text);font-weight:600">'+v+'</span></div><div style="background:var(--surface2);height:8px;border-radius:4px;overflow:hidden"><div style="background:'+COLORS[i%COLORS.length]+';height:100%;width:'+pct+'%"></div></div>';
    list.appendChild(row);
  }
  box.appendChild(list);
  container.appendChild(box);
}
function buildPerDomainStacked(title,dataObj,container){
  var data=dataObj;
  if(typeof data==='string'){try{data=JSON.parse(data)}catch(e){return}}
  if(!data||!data.domains||data.domains.length===0||!data.labels||data.labels.length===0) return;
  var rows=[];
  for(var di=0;di<data.domains.length;di++){
    var d=data.domains[di]; var s=0;
    for(var i=0;i<d.values.length;i++) s+=d.values[i];
    if(s>0) rows.push({name:d.name,values:d.values,total:s});
  }
  if(rows.length===0) return;
  var box=document.createElement('div');
  box.style.cssText='background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:18px;box-shadow:var(--shadow)';
  box.innerHTML='<h3 style="font-size:.88rem;margin-bottom:12px;color:var(--text)">'+title+'</h3>';
  var bars=document.createElement('div');
  bars.style.cssText='font-size:.74rem;display:flex;flex-direction:column;gap:6px';
  for(var di=0;di<rows.length;di++){
    var row=rows[di];
    var rowDiv=document.createElement('div');
    rowDiv.style.cssText='display:flex;align-items:center;gap:8px';
    var name=document.createElement('div');
    name.style.cssText='min-width:160px;max-width:160px;color:var(--text-dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap';
    name.textContent=row.name;
    rowDiv.appendChild(name);
    var barWrap=document.createElement('div');
    barWrap.style.cssText='flex:1;display:flex;height:20px;border-radius:4px;overflow:hidden;background:var(--surface2);border:1px solid var(--border)';
    for(var i=0;i<row.values.length;i++){
      var v=row.values[i]; if(v===0) continue;
      var pct=(v/row.total)*100;
      var seg=document.createElement('div');
      seg.style.cssText='background:'+COLORS[i%COLORS.length]+';height:100%;width:'+pct+'%';
      seg.title=data.labels[i]+': '+v+' ('+pct.toFixed(1)+'%)';
      barWrap.appendChild(seg);
    }
    rowDiv.appendChild(barWrap);
    var totalLabel=document.createElement('div');
    totalLabel.style.cssText='min-width:55px;text-align:right;color:var(--text);font-weight:600';
    totalLabel.textContent=row.total;
    rowDiv.appendChild(totalLabel);
    bars.appendChild(rowDiv);
  }
  box.appendChild(bars);
  var legend=document.createElement('div');
  legend.style.cssText='margin-top:12px;display:flex;flex-wrap:wrap;gap:14px;font-size:.72rem';
  for(var i=0;i<data.labels.length;i++){
    var item=document.createElement('div');
    item.style.cssText='display:flex;align-items:center;gap:5px';
    item.innerHTML='<span style="display:inline-block;width:10px;height:10px;background:'+COLORS[i%COLORS.length]+';border-radius:2px;flex-shrink:0"></span><span style="color:var(--text-dim)">'+data.labels[i]+'</span>';
    legend.appendChild(item);
  }
  box.appendChild(legend);
  container.appendChild(box);
}

(function(){
  var c=document.getElementById('chartsContainer'); if(!c) return;
  buildDonut('Object Categories',$CategoryChartJSON,c);
  buildDonut('Top Object Classes',$ClassChartJSON,c);
  buildDonut('User Account Status',$UserChartJSON,c);
  buildDonut('Computer Account Status',$CompChartJSON,c);
  buildDonut('Group Types',$GroupChartJSON,c);
  buildDonut('GPO Status',$GPOChartJSON,c);
  buildDonut('DNS Zones',$DNSChartJSON,c);
  buildDonut('Operating Systems',$OSDistJSON,c);
  buildBarChart('Objects per Domain',$DomObjCountJSON,c);
  var pd=document.getElementById('perDomainChartsContainer'); if(!pd) return;
  buildPerDomainStacked('User Status by Domain',$PerDomainUserChartJSON,pd);
  buildPerDomainStacked('Computer Status by Domain',$PerDomainComputerChartJSON,pd);
  buildPerDomainStacked('Group Types by Domain',$PerDomainGroupChartJSON,pd);
  buildPerDomainStacked('GPO Status by Domain',$PerDomainGPOChartJSON,pd);
  buildPerDomainStacked('Object Categories by Domain',$PerDomainCategoryChartJSON,pd);
})();
(function(){
  var lk=document.querySelectorAll('.sidebar nav a');
  var sc=[];
  for(var i=0;i<lk.length;i++){
    var id=lk[i].getAttribute('href');
    if(id && id.charAt(0)==='#'){
      var el=document.querySelector(id);
      if(el) sc.push({el:el,link:lk[i]});
    }
  }
  window.addEventListener('scroll',function(){
    var cur=sc[0];
    for(var i=0;i<sc.length;i++){
      if(sc[i].el.getBoundingClientRect().top<=120) cur=sc[i];
    }
    for(var i=0;i<lk.length;i++) lk[i].classList.remove('active');
    if(cur) cur.link.classList.add('active');
  });
})();
</script>
</body>
</html>
<!--
================================================================================
  ADObjectCanvas v1.5 -- AD Object Inventory Report
  Author : Santhosh Sivarajan, Microsoft MVP
  Email  : santhosh@sivarajan.com
================================================================================
-->
"@

$HTML | Out-File -LiteralPath $OutputFile -Encoding UTF8 -Force
$FileSize = [math]::Round((Get-Item -LiteralPath $OutputFile).Length / 1KB, 1)

Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Green
Write-Host "  |   ADObjectCanvas -- Report Generation Complete             |" -ForegroundColor Green
Write-Host "  +============================================================+" -ForegroundColor Green
Write-Host ""
Write-Host "  FOREST OBJECT INVENTORY" -ForegroundColor White
Write-Host "  -----------------------" -ForegroundColor Gray
Write-Host "    Forest             : $($Forest.Name)" -ForegroundColor White
Write-Host "    Domains            : $($ForestDomains.Count)" -ForegroundColor White
Write-Host "    Domain Controllers : $($AllForestDCs.Count)" -ForegroundColor White
Write-Host "    Total Objects      : $ForestObjectTotal" -ForegroundColor Cyan
Write-Host "    Distinct Classes   : $($ForestClassMap.Count)" -ForegroundColor White
Write-Host "    Configuration NC   : $ConfigTotalObjects objects, $($ConfigClassMap.Count) classes" -ForegroundColor White
Write-Host "    DNS Partitions     : $($DnsPartitionList.Count) ($DnsTotalObjects objects, $(if($DnsClassMap.ContainsKey('dnsNode')){$DnsClassMap['dnsNode']}else{0}) records)" -ForegroundColor White
if ($ForestUnknownCount -gt 0) {
    Write-Host "    Unresolved Class   : $ForestUnknownCount (likely tombstoned objects)" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "  HERITAGE & CLEANUP CANDIDATES" -ForegroundColor White
Write-Host "  -----------------------------" -ForegroundColor Gray
Write-Host "    IPSec Legacy        : $IPSecCount" -ForegroundColor $(if($IPSecCount -gt 0){'Yellow'}else{'White'})
Write-Host "    NTFRS Legacy        : $NTFRSCount" -ForegroundColor $(if($NTFRSCount -gt 0){'Yellow'}else{'White'})
Write-Host "    NT4 Domain Policy   : $DomainPolicyCount" -ForegroundColor $(if($DomainPolicyCount -gt 0){'Yellow'}else{'White'})
Write-Host "    Link Tracking       : $LinkTrackCount" -ForegroundColor $(if($LinkTrackCount -gt 0){'Yellow'}else{'White'})
Write-Host "    LSA Secrets         : $LSASecretCount" -ForegroundColor White
Write-Host "    Empty Groups        : $($ForestTotals.Empty)" -ForegroundColor White
Write-Host "    Stale Computers     : $($ForestTotals.StaleComp90)" -ForegroundColor White
Write-Host "    Never Logged On     : $($ForestTotals.NeverLoggedOn)" -ForegroundColor White
Write-Host "    Pwd Never Expires   : $($ForestTotals.PwdNeverExp)" -ForegroundColor White
Write-Host ""
Write-Host "  CORE OBJECTS" -ForegroundColor White
Write-Host "  ------------" -ForegroundColor Gray
Write-Host "    Users              : $($ForestTotals.Users) (Enabled: $($ForestTotals.EnabledUsers), Disabled: $($ForestTotals.DisabledUsers))" -ForegroundColor White
Write-Host "    Computers          : $($ForestTotals.Computers) (Servers: $($ForestTotals.Servers), Workstations: $($ForestTotals.Workstations))" -ForegroundColor White
Write-Host "    Groups             : $($ForestTotals.Groups) (Security: $($ForestTotals.Security), Distribution: $($ForestTotals.Distribution))" -ForegroundColor White
Write-Host "    OUs                : $($ForestTotals.OUs) (Protected: $($ForestTotals.ProtectedOUs))" -ForegroundColor White
Write-Host "    GPOs               : $($ForestTotals.GPOs)" -ForegroundColor White
Write-Host "    Containers         : $($ForestTotals.Containers)" -ForegroundColor White
Write-Host "    Contacts           : $($ForestTotals.Contacts)" -ForegroundColor White
Write-Host "    Printers           : $($ForestTotals.Printers)" -ForegroundColor White
Write-Host "    FSPs               : $($ForestTotals.FSPs)" -ForegroundColor White
Write-Host "    Service Accounts   : $($ForestTotals.sMSAs + $ForestTotals.gMSAs + $ForestTotals.dMSAs) (sMSA: $($ForestTotals.sMSAs), gMSA: $($ForestTotals.gMSAs), dMSA: $($ForestTotals.dMSAs))" -ForegroundColor White
Write-Host "    FGPPs              : $($ForestTotals.FGPPs)" -ForegroundColor White
Write-Host "    BitLocker Keys     : $($ForestTotals.BitLockerKeys)" -ForegroundColor White
Write-Host "    Trusts             : $($AllTrusts.Count)" -ForegroundColor White
Write-Host "    DNS Zones          : $($DNSZones.Count) (AD-Integrated: $DNSIntegrated, File: $DNSFileBacked)" -ForegroundColor White
Write-Host "    AD Sites           : $($ADSites.Count)" -ForegroundColor White
Write-Host ""
Write-Host "  OUTPUT" -ForegroundColor White
Write-Host "  ------" -ForegroundColor Gray
Write-Host "    Report File : $OutputFile" -ForegroundColor White
Write-Host "    File Size   : $FileSize KB" -ForegroundColor White
Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host "  |  This report was generated using ADObjectCanvas v1.5       |" -ForegroundColor Cyan
Write-Host "  |  Developed by Santhosh Sivarajan, Microsoft MVP            |" -ForegroundColor Cyan
Write-Host "  |  santhosh@sivarajan.com                                    |" -ForegroundColor Cyan
Write-Host "  |  https://github.com/SanthoshSivarajan/ADObjectCanvas       |" -ForegroundColor Cyan
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host ""

<#
================================================================================
  ADObjectCanvas v1.5 -- AD Object Inventory Report Generator
  Author : Santhosh Sivarajan, Microsoft MVP
  Email  : santhosh@sivarajan.com
  GitHub : https://github.com/SanthoshSivarajan/ADObjectCanvas
================================================================================
#>
