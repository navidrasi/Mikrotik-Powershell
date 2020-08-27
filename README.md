# Mikrotik-Powershell
Powershell module to manage mikrotik devices using Mikrotik API
For more information about Filters and Attributes please check http://wiki.mikrotik.com/wiki/Manual:API

Exmaples:

PS C:\>Import-Module Mikrotik.dll
PS C:\> Get-Command -Module Mikrotik

CommandType Name Version Source
----------- ---- ------- ------
Cmdlet Connect-Mikrotik 1.0.0.0 Mikrotik
Cmdlet Disconnect-Mikrotik 1.0.0.0 Mikrotik
Cmdlet Send-Mikrotik 1.0.0.0 Mikrotik

#Connecting using API default port and save the connection object in C$ then we can use C$ to send commands
PS C:\> $C=Connect-Mikrotik -IPaddress 192.168.3.1 -UserName admin -Password password
Connected to 192.168.3.1 , Identity=TEST1

#Connecting using API-SSL default port
PS C:\> $C=Connect-Mikrotik -IPaddress 192.168.3.1 -UserName admin -Password password -UseSSL
Connected to 192.168.3.1 , Identity=TEST1

#Connecting using API-SSL on diffrenet port that 8729
PS C:\> $C=Connect-Mikrotik -IPaddress 192.168.3.1 -UserName admin -Password svgafara -UseSSL -Port 3323

#get all ethernet interface which is not disabled

PS C:\> Send-Mikrotik -Connection $C -Command "/interface/getall" -Filters "type=ether","disabled=false"

#add ip to ether 1
PS C:\> Send-Mikrotik -Connection $C -Command "/ip/address/add" -Attributes "interface=ether1","address=192.168.201.1/24"

#get ether1 ip addres
PS C:\> Send-Mikrotik -Connection $C -Command "/ip/address/getall" -Filters "interface=ether1"

#Close the connection
PS C:\> Disconnect-Mikrotik -Connection $C
