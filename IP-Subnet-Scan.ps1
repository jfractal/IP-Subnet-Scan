##################################################
#############    IP-SUBNET-SCAN    ###############
##################################################
                                            # v1.8 

#  AUTHOR:  Justin B Brazil
#  DATE:    08/30/15
#  Written and validated using PowerShell ISE 4.0 
#  Requires: Version 3.0



#ASSIGNED TASK:  Using Powershell, write a script or script cmdlet to collect the hostname 
#belonging to all available Windows 2012R2 servers within 192.168.1.0/25

    #    You are administrator and all remote access capabilities are wide open for your use
    #    All servers are running 2012R2.
    #    Do not use DNS to recover the hostnames
    #    Pay attention to minimizing the duration of the script's run time.


#OUTLINE OF STEPS:
 

    #    USER DEFINED VARIABLES: 
           
            # This script will output an HTML report to your local disk and open it automatically.
            # Please set the disk location for the HTML report prior to running the script.
            # There are 3 user-defined variables at the start of the script - please review them before running the script.
               
    #    VALIDATE INPUT:  User input is validated, including IP address and output file location
   
    #    CIDR/SUBNET MATH: The CIDR IP range specified is converted an IP range array.
 
    #    IP SCANNING:  Hosts are scanned in parallel using Workflows.  Live hosts are tested
            # for WinRM manageability.  Manageable hosts are queried in parallel via WMI.

    #    HTML OUTPUT:  Hosts are scanned in parallel using Workflows.  Live hosts are tested
            # for WinRM manageability.  Manageable hosts are queried in parallel via WMI.

#NOTES:

# This script has been tested and benchmarked against a live network.  
# Originally the idea was to use Get-CIMInstanceE for speed but a number of live hosts rejected
    # opening a CIM session for varying reasons
    # In side-by-side comparisons Get-WMIObject ran almost as fast as Get-CIMInstance and was...
    # ...able to manage more hosts on the network (6 hosts on a 120+ host network).
# I did not opt to use RunSpaces for this particular code because the slowest command (TEST-CONNECTION)
    # Could be run in a parallel workflow.
    # Typically a case like this would be a good candidate for the open source INVOKE-PARALLELS...
    # ...script however I wanted to build this entire thing from scratch.
# Note: Opted to collect OS info for all systems and not filter on OS type at the time of WMI data collection.  
    # This is because the extra steps did not impact the runtime (benchmarked using Measure-Command)
    # This allows the script to retain some versatility.  In the future I would turn it into...
    # ...a function with an -OSType parameter defined so it could be used to query any OS.

#ASSUMPTION:  That WSMAn has been enabled on all hosts through GPO or similar (best practice for management)
#ASSUMPTION:  That an HTML report is an appropriate output for the purpose of this task.
#ASSUMPTION:  This script may need to be repurposed in the future to target other OSes and subnets....
    # ...and has been designed accordingly






##################################################
############# User-Defined Variables #############
##################################################

#PURPOSE: Enter your user-defined values here.


$CIDRADDRESS = "192.168.1.0/25"            # Enter an IP range to scan using CIDR notation
$CRED = Get-Credential                     # Account must have WinRM privileges  on target hosts
$OUTPUTLOCATION = "C:\Users\Report.htm"    # A report is generated at this location and opened automatically when the script finishes






##################################################
################ Input Validation ################
##################################################

#PURPOSE:  Validate IP address, subnet mask, and output location

#SECTION OUTLINE
   #0.1 - Split CIDRADDRESS into IP and bitmask
   #0.2 - Validate IP address and CIDR bitmask, terminate with warning if invalid
   #0.3 - Validate output file location, test write permissions
   



#0.1 - Split $CIDRADDRESS into IP and bitmask

$IPTEST = $CIDRADDRESS.Substring(0,($CIDRADDRESS.IndexOf('/')))
$CIDRTEST = $CIDRADDRESS.Substring($CIDRADDRESS.IndexOf('/')+1)

#0.2 - Validate IP address and CIDR bitmask, terminate with warning if invalid

try {$IPTEST -match [IPAddress]$IPTEST} 
catch {Write-Warning "Invalid IP Address Specified.  Please enter an IP range using CIDR notation (ex: 192.168.41.0/26). Terminating script."; return}
if (($CIDRTEST -lt 1) -or ($CIDRTEST -gt 32))
    {Write-Warning "Invalid CIDR mask Specified.  Please enter an IP range using CIDR notation (ex: 192.168.41.0/26). Terminating script."; return}
    


#0.3 - Validate output file target path, test write permissions to directory

if (Test-Path $OUTPUTLOCATION) {
    try {$PERMISSIONCHECK =  [IO.FILE]::OpenWrite($OUTPUTLOCATION); $PERMISSIONCHECK.close()}
    catch {Write-Warning "Cannot write output to specified location $OUTPUTLOCATION - Please ensure that the directory is valid and that you have write permissions"; Write-Warning "Please ensure that you have write permissions to the target directory"; Return}}
else {Write-Warning "Cannot write output to specified location $OUTPUTLOCATION - Please ensure that the directory is valid and that you have write permissions"; Write-Warning "Please ensure that you have write permissions to the target directory"; Return} 





##################################################
############# Section 1 - Subnet Math ############
##################################################

#PURPOSE:  Transfer a CIDR IP address into an array of useable IPs

   #Note:  This entire section was built from scratch, although a few external references were used for assistance with the logic to perform the manual binary AND comparison.
   #Note:  In a real-world scenario, it would be much faster to use an open-sourced script such as ipcalc.ps1 (source: https://gallery.technet.microsoft.com/scriptcenter/ipcalc-PowerShell-Script-01b7bd23) 
   #Note:  For the purposes of interview screening, I decided it would be best to write the entire script by hand rather than using prebuilt modules to save time.


#SECTION OUTLINE
   #1.0 - Define Conversion Functions
   #1.1 - Perform Logical Operations
   #1.2 - Calculate and convert NetMask
   #1.3 - Calculate start/end addresses by using a manual binary AND operation
   #1.4 - Calculate bytes using .Net class and above values, reverse the arrays (so span math will function properly)
   #1.5 - Create array, populate with range of IPs using an incremental counter, reverse values to original order
   #1.6 - Execute the CIDRMATH function

#METHODOLOGY:  This section is wrapped up into one large function called CIDRMATH


#FUNCTION: CIDRMATH
   #Inputs:   [string] CIDR-style IP address
   #Outputs:  [Array]$TARGETHOSTS: Array of all useable IP addresses in the target subnet
   
function CIDRMath ($CIDRADDRESS) {             



#1.0 - Define Conversion Functions

function ConvertToBinary ($DECIMAL){ 
    $DECIMAL.split(".") | %{$BINARY=$BINARY + $([convert]::toString($_,2).padleft(8,"0"))} 
    return $BINARY} 

function ConvertFromBinary ($BINARY){ 
    do {$DECIMAL += "." + [string]$([convert]::toInt32($BINARY.substring($i,8),2)); $i+=8 } while ($i -le 24) 
    return $DECIMAL.substring(1)} 
 



#1.1 - Perform Logical Operations
 
#Split CIDRADDRESS into IP Address and Netmask bits
$SPLIT = $CIDRADDRESS.IndexOf("/")
$IPADDRESS = $CIDRADDRESS.Substring(0, $SPLIT)
$NETMASKBITS = $CIDRADDRESS.Substring($SPLIT+1)




#1.2 - Calculate and convert NetMask

$HOSTBITS = 32 - $NETMASKBITS  
$BINNETMASK = ("1" * $NETMASKBITS + "0" * $HOSTBITS)
$NETMASK = ("1" * $NETMASKBITS + "0" * $HOSTBITS) -split '(.{8})' | ? {$_} | foreach {[system.convert]::ToByte($_,2)}; $NETMASK = $NETMASK -join '.'




#1.3 - Calculate start/end addresses by using a manual binary AND operation

$BINIPADDRESS = ConvertToBinary $($IPADDRESS) 
$STARTIP = ConvertFromBinary $($BINIPADDRESS.substring(0,$NETMASKBITS).padright(31,"0") + "1") 
$ENDIP = ConvertFromBinary $($BINIPADDRESS.substring(0,$NETMASKBITS).padright(31,"1") + "0") 




#1.4 - Calculate bytes using .Net class and above values, reverse the arrays (so span math will function properly)

$STARTIPCONVERSION = ([System.Net.IPAddress]$STARTIP).GetAddressBytes()
[Array]::Reverse($STARTIPCONVERSION)
$STARTIPCONVERSION = ([System.Net.IPAddress]($STARTIPCONVERSION -join '.')).Address

$ENDIPCONVERSION = ([System.Net.IPAddress]$ENDIP).GetAddressBytes()
[Array]::Reverse($ENDIPCONVERSION)
$ENDIPCONVERSION = ([System.Net.IPAddress]($ENDIPCONVERSION -join '.')).Address




#1.5 - Create array, populate with range of IPs using an incremental counter, reverse values to original order

$TARGETHOSTS = @()
for ($i=$STARTIPCONVERSION; $i -le $ENDIPCONVERSION; $i++) {
    $iprange = ([System.Net.IPAddress]$i).GetAddressBytes()
    [Array]::Reverse($iprange)
    $TARGETHOSTS += $iprange -join '.'}
    return $TARGETHOSTS}  
  
#End CIDRMATH function



#1.6 - Execute the CIDRMATH function

$TARGETHOSTS = CIDRMATH -CIDRADDRESS $CIDRADDRESS     




##################################################
############# Section 2 - IP Scanning ############
##################################################

#PURPOSE:  Find the most efficient way to scan every IP address in the subnet quickly and return information about the Operating System as quickly as possible
   #NOTE:  Measured speed for 5 different methods of data collection, selected fastest. 
   #Note:  Fast IP scanning achieved using parallelized Workflows 

#SECTION OUTLINE
   #2.0 - Define parallelized Workflows for fast PING/WSMAN sweeps
   #2.1 - Perform Logical Operations and Output Variables   

#METHODOLOGY:  This section is purposefully NOT wrapped into a single function.  This is so the reader can easily run snippets to measure the speed of... 
   #...individual steps (if desired) and query values to check results without worrying about variable scope.  If this were a production script I would...
   #...wrap it into a single function and add parameters and switches for ease of use.




#2.0 - Define parallelized Workflows for fast PING/WSMAN sweeps

Workflow PING-IPRANGE {
    param([string[]] $IPTARGET)
    foreach -Parallel ($TARGET in $IPTARGET) {
        sequence {
        $STATUS = Test-Connection -ComputerName $TARGET -Count 1 -Quiet
        $PINGRESULTS = New-Object -Type PSObject -Property @{
            IPAddress = $TARGET
            Status = $STATUS}
        $PINGRESULTS}}}

workflow TEST-WSMANHOSTS {
    param([string[]] $IPTARGET)
    foreach -parallel ($TARGET in $IPTARGET) {
        sequence {
        if (TEST-WSMAN -ComputerName $TARGET -ErrorAction SilentlyContinue){$WINRMHOSTS = $TARGET}
        $WINRMHOSTS}}}




#2.1 Perform Logical Operations and Output Variables   

$PINGRESULTS = PING-IPRANGE $TARGETHOSTS | Select -Property IPAddress, Status 
$LIVEHOSTS = $PINGRESULTS | Where-Object {$_.status -like "True"}
$WINRMHOSTS = TEST-WSMANHOSTS -IPTARGET $LIVEHOSTS.Ipaddress
$HOSTINFO =  Invoke-Command -Computer $WINRMHOSTS -Credential $CRED -Authentication Negotiate -ScriptBlock {$HOSTINFO = New-Object -Type PSObject -Property @{HOSTNAME = (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).CSName; OSTYPE = (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption; OSSERVICEPACK = (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).ServicePackMajorVersion; OSBUILD = (Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue).Version};$HOSTINFO}
$2012HOSTS = $HOSTINFO | Where-Object {$_.ostype -ilike "*2012*"}
$CIDRIP = $CIDRADDRESS.Split('/')[0]
$CIDRBITMASK = $CIDRADDRESS.Split('/')[1]



##################################################
############# Section 3 - Reporting ##############
##################################################

#PURPOSE:  Format output as a nice HTML report

#SECTION OUTLINE
   #3.0 - Format simple objects for HTML conversion
   #3.1 - Format multi-valued array objects into custom objects for HTML conversion
   #3.2 - Create Style Sheet for HTML report
   #3.3 - Transform objects into HTML-formatted output fragments
   #3.4 - Combine HTML fragments and CSS, output and open report




#3.0 - Format simple objects for HTML conversion

$HTML1 = [pscustomobject]@{
"IP Address" = $CIDRIP
"CIDR Bitmask" = $CIDRBITMASK}

$HTML2 = [PSCustomObject]@{
"Start Address" = $TARGETHOSTS[0]
"End Address" = $TARGETHOSTS[$TARGETHOSTS.GetUpperBound(0)]} 

$HTML3 = [PSCustomObject]@{
"Responded" = $LIVEHOSTS.Count
"No Response" = ($TARGETHOSTS.Count - $LIVEHOSTS.Count)} 

$HTML4 = [PSCustomObject]@{
"WinRM Enabled" = $WINRMHOSTS.Count
"WinRM Unavailable" = ($LIVEHOSTS.Count - $WINRMHOSTS.Count)} 




#3.1 - Format multi-valued array objects into custom objects for HTML conversion

function HTML5Function {
PROCESS {
  $HTML5 = New-Object PSObject
  $HTML5 | Add-Member NoteProperty Hostname($2012HOST.Hostname)
  $HTML5 | Add-Member NoteProperty OSType($2012HOST.OSType)
  $HTML5 | Add-Member NoteProperty IPAddress($2012HOST.PSComputerName)
  return $HTML5}  }
$HTML5 = foreach ($2012HOST in $2012HOSTS){$2012HOST | HTML5Function}

function HTML6Function {
PROCESS {
  $HTML6 = New-Object PSObject
  $HTML6 | Add-Member NoteProperty Hostname($HOSTSYSTEM.Hostname)
  $HTML6 | Add-Member NoteProperty OSType($HOSTSYSTEM.OSType)
  $HTML6 | Add-Member NoteProperty IPAddress($HOSTSYSTEM.PSComputerName)
  return $HTML6}  }
$HTML6 = foreach ($HOSTSYSTEM in $HOSTINFO){$HOSTSYSTEM | HTML6Function}




#3.2 - Create Style Sheet for HTML report

$CSSHEADER = "
<style>
    BODY{background-color:#23415A;}
    TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}
    TH{border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color:Black;color:white;}
    TD{border-width: 1px;padding: 3px;border-style: solid;border-color: black;}
    tr:nth-child(odd) { background-color:#ECF2F8;} 
    tr:nth-child(even) { background-color:white;}
    h2 {color:white;}    
</style>"




#3.3 - Transform objects into HTML-formatted output fragments

$HTML1 = $HTML1 | ConvertTo-Html -Property "IP Address","CIDR Bitmask" -Fragment -PreContent '<h2>Target Subnet</h2>' | Out-String
$HTML2 = $HTML2 | ConvertTo-Html -Property "Start Address","End Address" -Fragment -PreContent '<h2>IP Address Range</h2>' | Out-String
$HTML3 = $HTML3 | ConvertTo-Html -Property "Responded","No Response" -Fragment -PreContent '<h2>ICMP/Ping Scan Results</h2>' | Out-String
$HTML4 = $HTML4 | ConvertTo-Html -Property "WinRM Enabled","WinRM Unavailable" -Fragment -PreContent '<h2>Hosts Manageable via WinRM</h2>' | Out-String
$HTML5 = $HTML5 | ConvertTo-Html -Property "Hostname","OSType","IPAddress" -Fragment -PreContent '<h2>Hosts Running Server 2012</h2>' | Out-String
$HTML6 = $HTML6 | ConvertTo-Html -Property "Hostname","OSType","IPAddress" -Fragment -PreContent '<h2>Full Subnet OS Audit</h2>' | Out-String




#3.4 - Combine HTML fragments and CSS, output and open report

ConvertTo-HTML -head $CSSHEADER -PostContent $HTML1, $HTML2, $HTML3, $HTML4, $HTML5, $HTML6 -PreContent "<h1 style='color:white'>Subnet Scan Results</h1><h3 style='color:white'>Written by Justin Brazil on 08/30/15</h3>" | Out-File $OUTPUTLOCATION
Invoke-Expression $OUTPUTLOCATION




#Future Improvements/Tasks:
 
    # If no 2012 hosts are present on the network, generate a warning on the HTML output report in big red letters.
    # Turn script into one huge function
    # Offer email output in addition to the HTML report
