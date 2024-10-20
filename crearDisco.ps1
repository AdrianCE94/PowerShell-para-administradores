$disco=Read-Host "Introduce el nombre del disco (Path)"
[double]$tamano=Read-Host "Tamaño del disco en bytes"
New-VHD -Path $disco -SizeBytes $tamano -Dynamic
Mount-vhd -Path $Disco -Passthru|
Initialize-Disk -PassThru|
New-Partition -AssignDriveLetter -UseMaximumSize|
Format-Volume -FileSystem NTFS -Confirm:$false