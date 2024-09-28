# Low end IPv6 Scanner

# Tonton Jo - 2024 

# Version 1.0

# Usage:
# Run the script directly and select the interface.
# If you want to try to discover hostnames, pass option -c. Disabled by default as it's slow and will not retreive many informations.

# Informations about this script:
# This script will list hosts connected to a specific network interface and using ipv6.
# It relies on ping and will takes advantages of multicasts messages to find hosts
# In order to get fresh infos and forget old know / seen hosts, administrators privileges are required



# ------------------ Env. Settings ---------------------------
$url = "https://standards-oui.ieee.org/oui/oui.txt"			# Mac database
$version = "1.0"											# Version
$Host.UI.RawUI.WindowTitle = 'IPv6 Scanner - Tonton Jo' 	# Give me some credits
$neighboursdiscoverycalls = "3" 							# Making 3 pings to hosts to give a chance to the late people to answer the call of Gondor
$discoverydelay = "2000" 									# How long we wait for ping answers
# ------------------ Env. Settings ---------------------------
# Set te console size to fully display results - not working with the new Windows terminal
[console]::WindowWidth=150; 
[console]::BufferWidth=[console]::WindowWidth

$options=$args[0]
# ------------------ Header ---------------------------

function header {
    cls
    write-host "
._____________         ________   _________                                         
|   \______   \___  __/  _____/  /   _____/ ____ _____    ____   ____   ___________ 
|   ||     ___/\  \/ /   __  \   \_____  \_/ ___\\__  \  /    \ /    \_/ __ \_  __ \
|   ||    |     \   /\  |__\  \  /        \  \___ / __ \|   |  \   |  \  ___/|  | \/
|___||____|      \_/  \_____  / /_______  /\___  >____  /___|  /___|  /\___  >__|   
                            \/          \/     \/     \/     \/     \/     \/       
                Tonton Jo - Version $version
"
}

# ------------------ Checking if we're administrator ---------------------------
# If we're admin, we can clear the cache to better reflect actual network
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "- For accurate results, please run as administrator (Needed to clear cache)"
    Start-Sleep -seconds 1
    $isadmin = "no"
} else {
    $isadmin = "yes"
}

# ------------------ Downloading the mac address database ---------------------------
# Function to fetch MAC vendor data from the URL and return it as a hashtable
function Get-MACVendorList {
    header
    Write-Host "- Downloading a fresh MAC database"
    $response = Invoke-WebRequest -Uri $url -UseBasicParsing
    $content = $response.Content

    # Parse the content into a hashtable
    $macVendorList = @{}
    $lines = $content -split "`n"
    foreach ($line in $lines) {
        if ($line -match '^([0-9A-F]{6})\s+(.+)$') {
            $mac = $matches[1]
            # Get the vendor out of the database
            $vendor = $matches[2]
            # Filter informations
            $vendor = $vendor -replace "\(base 16\)\s*", ""
            $macVendorList[$mac] = $vendor
        }
    }
    return $macVendorList
}

# ------------------ Initializing menu entries ---------------------------
# List all network interfaces
$networkInterfaces = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

# Function to display the menu and get user selection
function Show-Menu {
    param (
        [Parameter(Mandatory=$true)]
        [array]$menuItems
    )
    header
    # Display menu
    for ($i = 0; $i -lt $menuItems.Length; $i++) {
        Write-Host "$($i + 1). $($menuItems[$i].Name)"
    }

    # Get user selection
    $selection = Read-Host "Choose interface to scan: (1-$($menuItems.Length))"
    # Validate input
    if ($selection -match '^[0-9]+$' -and $selection -gt 0 -and $selection -le $menuItems.Length) {
        return $menuItems[$selection - 1]
    } else {
        Write-Host "Invalid selection. Please try again."
        return $null
    }
}

# ------------------ Host discovery  ---------------------------
# Function to get the vendor name based on the MAC address
function Get-MACVendorName {
    param (
        [Parameter(Mandatory=$true)]
        [string]$macAddress,
        [Parameter(Mandatory=$true)]
        [hashtable]$macVendorList
    )

    if ($macVendorList.ContainsKey($macAddress)) {
        return $macVendorList[$macAddress]
    } else {
        return "Unknown"
    }
}

# Function to get the hostname from an IPv6 address
function Get-HostnameFromIPv6 {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ipAddress
    )
    $pingOutput = ping -w $discoverydelay -n 1 -a $ipAddress
    $hostnameMatch = $pingOutput | Select-String -Pattern 'Pinging\s+([^\s]+)\s+\['
    if ($hostnameMatch) {
        $hostname = $hostnameMatch.Matches[0].Groups[1].Value
        return $hostname
    }
}

# ------------------ Main script ---------------------------
$macVendorList = Get-MACVendorList

# Create a menu with the discovered interfaces
do {
    $selectedInterface = Show-Menu -menuItems $networkInterfaces
} until ($selectedInterface -ne $null)

# Set selected interface ID in a variable
$selectedInterfaceID = $selectedInterface.InterfaceIndex

# If we're admin, we run a command that clear the cache
# Emptying cache actually does not remove ip addresses but only clear the mac address leaging it to be 00-00-00-00-00-00
if ($isadmin -eq "yes") {
    # Display the selected interface ID
    Write-Host "- Clearing Neighbours cache"
    Remove-NetNeighbor -AddressFamily IPv6 -InterfaceIndex $selectedInterfaceID -Confirm:$False
}

# Display the selected interface ID
Write-Host "- Interface $selectedInterfaceID - Querying network neighbors!"

# In order to have an actual list of neighbors, we need to ping all nodes using multicast to get their mac and ip address cached
ping -w $discoverydelay -n $neighboursdiscoverycalls ff02::1%$selectedInterfaceID > $null

# Now that we have them cached, let's list them selecting the wanted interface and ignore addresses starting with ff02:
$discoveredNeighbors = Get-NetNeighbor -AddressFamily IPv6 -InterfaceIndex $selectedInterfaceID |
                        Where-Object { $_.IPAddress -notlike "ff*" } |
                        Select-Object IPAddress, LinkLayerAddress

# Group the neighbors by MAC address and sort them
$groupedNeighbors = $discoveredNeighbors | Group-Object -Property LinkLayerAddress

# Some results have a mac of 00-00-00-00-00-00, we try to ping em once again to ensure it's an old cached data. if the host is alive, the mac address will be refreshed
foreach ($neighbor in $groupedneighbors) {
    foreach ($macaddress in $neighbor.Group) {
        if ($macaddress.LinkLayerAddress -eq "00-00-00-00-00-00") {
            $pingmeagainaddress = $macaddress.IPaddress 
            write-host "- ping again $pingmeagainaddress"
            ping -n 1 $pingmeagainaddress%$selectedInterfaceID > $null
        }
    }
}

# List the neighbors again and this time we filter mac 00-00-00-00-00-00 aswell
$discoveredNeighbors = Get-NetNeighbor -AddressFamily IPv6 -InterfaceIndex $selectedInterfaceID |
                        Where-Object { $_.IPAddress -notlike "ff*" } |
						Where-Object { $_.LinkLayerAddress -ne "00-00-00-00-00-00" } |
                        Select-Object IPAddress, LinkLayerAddress
# If after a ping the host still have a mac address of 00-, it means it's an old cached device so we remove it from results
$groupedNeighbors = $discoveredNeighbors | Group-Object -Property LinkLayerAddress 

header
write-host "- Discovering hostnames if possible using ping - not accurate"

$results = @{}

# Loop through neighbors
foreach ($group in $groupedNeighbors) {
    $macAddress = $group.Name
    $macAddresslookup = $macAddress.Substring(0, 8).Replace("-", "")
    $vendor = Get-MACVendorName -macAddress $macAddresslookup -macVendorList $macVendorList
#	if ($macAddress -eq "00-00-00-00-00-00") {
#	continue
#	}
    # Check if the mac address already exist in database
    if (-not $results.ContainsKey($macAddress)) {
        # Initialiser la liste des adresses IP pour cette adresse MAC
        $results[$macAddress] = [PSCustomObject]@{
            "MAC Address" = $macAddress
            "Vendor" = $vendor
            "Link-Local IP Addresses" = @()
            "Other known IP Addresses" = @()
            "Hostname" = "N/A"
        }
    }

    # Add ip addresses to the mac address relation table
    foreach ($neighbor in $group.Group) {
        if ($neighbor.IPAddress -like "fe80*") {
            $results[$macAddress]."Link-Local IP Addresses" += $neighbor.IPAddress
        } else {
            $results[$macAddress]."Other known IP Addresses" += $neighbor.IPAddress
        }
    }
	if ($options -eq "-h") {
		# Get the hostname for the first link-local IP address
		$testedip = $results[$macAddress]."Link-Local IP Addresses"[0]
		header
		write-host "- Checking hostname for $testedip"
		$results[$macAddress]."Hostname" = Get-HostnameFromIPv6 -ipAddress $results[$macAddress]."Link-Local IP Addresses"[0]
	}
}

# Convert to Table
$finalResults = $results.Values | ForEach-Object {
    [PSCustomObject]@{
        "MAC Address" = $_."MAC Address"
        "Vendor" = $_."Vendor"
        "Hostname" = $_."Hostname"
        "Link-Local IP Addresses" = ($_. "Link-Local IP Addresses" -join ", ")
        "Other known IP Addresses" = ($_. "Other known IP Addresses" -join ", ")
    }
}

# Sort results by vendor, then mac address
$sortedResults = $finalResults | Sort-Object -Property Vendor, "MAC Address"

# ---------- Display results ---------------
header
# Count how many hosts we have!
$totalEntries = $sortedResults.Count
Write-Host "Discovered Hosts: $totalEntries"

# Display the results
$sortedResults | Format-Table -AutoSize -wrap
PAUSE