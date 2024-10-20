# para actualizar powersehll
```powershell
winget install --id Microsoft.Powershell --source winget
```

# Usuarios
```powershell
Get-Command *localuser*
Get-help Get-localuser -examples
```
```powershell
# inormacion de usuario
Get-LocalUser
Get-LocalUser -Name "usuario"|fl
```
```powershell
# crear usuario
New-LocalUser -Name "usuario"
# crear usuario con contraseña
$contra = Converto-SecureString "1234" -AsPlainText -Force
New-LocalUser -Name "usuario" -Password $contra
# modificar usuario
set-localuser -Name "usuario" -fullname "nombre completo"
# para que una cuenta nunca expire
Set-LocalUser -Name "usuario" -PasswordNeverExpires $true
# añadir contraseña a usuario
set-localuser -Name "usuario" -Password (Converto-SecureString "1234" -AsPlainText -Force)
# renombrar usuario
Rename-LocalUser -Name "usuario" -NewName "usuario2"
# desactivar una cuenta
Disable-LocalUser -Name "usuario"
# activar una cuenta
Enable-LocalUser -Name "usuario"
# eliminar usuario
Remove-LocalUser -confirm -Name "usuario" 
```

# Grupos
```powershell
Get-Command *localgroup*
Get-help Get-localgroup -examples
```
```powershell
Get-LocalGroup
Get-LocalGroup -Name "Administradores"|fl
```
```powershell
# crear grupo
New-LocalGroup -Name "grupo"
# modificar grupo
Set-LocalGroup -Name "grupo" -Description "descripcion"
# renombrar grupo
Rename-LocalGroup -Name "grupo" -NewName "grupo2"
# eliminar grupo
Remove-LocalGroup -confirm -Name "grupo"
# ver miebros de un grupo
Get-LocalGroupMember -Group "grupo"
# añadir usuario a grupo
Add-LocalGroupMember -Group "grupo" -Member "usuario"
# eliminar usuario de grupo
Remove-LocalGroupMember -Group "grupo" -Member "usuario"
```
```powershell
# creacion y eliminación de usuarios masiva

# Creación de un usuario
Clear
$usuario=Read-Host "Introduce nombre de usuario"
$contra=Read-Host "Introduce contraseña" -AsSecureString
New-LocalUser $usuario -Password $contra
Add-LocalGroupMember usuarios -Member $usuario

# Creación de forma masiva
#leer de fichero cvs (tener creado el fichero)
$usuarios= Import-Csv -Path C:\material\usuarios.csv
foreach ($i in $usuarios){

$clave= ConvertTo-SecureString $i.contra -AsPlainText -Force
New-LocalUser $i.nombre -Password $clave -AccountNeverExpires -PasswordNeverExpires
Add-LocalGroupMember -Group usuarios -Member $i.nombre
}

# Eliminación de usuarios de forma masiva
$usuarios= Import-Csv -Path C:\material\usuarios.csv
foreach ($i in $usuarios){
Remove-LocalUser $i.nombre
}
```

[!NOTE] 
PUEDE DESCARGARR LOS SCRIPTS DE CREACION DE USUARIOS MASIVA CLONANDO EL REPPSITORIO DE GITHUB


# Carpetas compartidas
```powershell
