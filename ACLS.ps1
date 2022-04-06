
#Requires -Modules ActiveDirectory
Import-Module ActiveDirectory
#Requires -Modules Microsoft.PowerShell.Security
Import-Module Microsoft.PowerShell.Security

# variables

# C'est le nom donné à la l'OU racine sur l'AD du client
$racine = "root"

# C'est le nom de domaine local sans son extension
$domain = "domain"

# c'est l'extension seule du domaine local
$ext= "extension"

# /variables

# fontion de test de GG existant
function Test-ADGroup {
   Param([Parameter(Mandatory=$true)][string]$Identity)
   $filter = 'Name -eq "'+$Identity+'"'
   $groups = Get-ADGroup -Filter $filter
   ($groups -ne $null)
}
# /fontion de test de GG existant

# Fin de fonctions

# Creation OU racine sur AD
write-host **************************************
write-host * CREATION DES UNITES D ORGANISATION *
write-host **************************************

$OUName = "name -like '$racine'"
if([bool](Get-ADOrganizationalUnit -Filter $OUName))
{ Write-host RACINE DEJA EXISTANTE: $racine
}
else
{
write-host CREATION OU: $racine -ForegroundColor Green;

New-ADOrganizationalUnit -Name "$racine" -Path "dc=$domain,dc=$ext" -ProtectedFromAccidentalDeletion $False
}

# creation arborescence AD dans OU racine
write-host ******************************
write-host * CREATION DE L ARBORESCENCE *
write-host ******************************
Get-Content -Path "$PSSCRIPTROOT\ARBO_AD.csv" | Out-File -FilePath "$PSSCRIPTROOT\ARBO_ADUni.csv" -Encoding Unicode
Import-Csv -Delimiter ";" -Path "$PSSCRIPTROOT\ARBO_ADuni.csv" | select niveau0 | Select -ExpandProperty niveau0 | Sort-Object -Unique | Foreach-Object {
$partages=$_
write-host CREATION OU: $racine - $partages -ForegroundColor Green;
New-ADOrganizationalUnit -Name "$partages" -Path "ou=$racine,dc=$domain,dc=$ext" -ProtectedFromAccidentalDeletion $False
}

Import-Csv -Delimiter ";" -Path "$PSSCRIPTROOT\ARBO_ADuni.csv" | select niveau0,niveau1 | Sort-Object niveau1 -Unique | Foreach-Object {
$partages=$_.niveau0
$niv1=$_.niveau1
write-host CREATION OU: $racine - $partages - $niv1 -ForegroundColor Green;
New-ADOrganizationalUnit -Name "$niv1" -Path "ou=$partages,ou=$racine,dc=$domain,dc=$ext" -ProtectedFromAccidentalDeletion $False
}

Import-Csv -Delimiter ";" -Path "$PSSCRIPTROOT\ARBO_ADuni.csv" | select niveau0,niveau1,niveau2 | Sort-Object niveau2 -Unique | Where-Object { $_.niveau2 }| Foreach-Object {
$partages=$_.niveau0
$niv1=$_.niveau1
$niv2=$_.niveau2
write-host CREATION OU: $racine - $partages - $niv1 - $niv2 -ForegroundColor Green;
New-ADOrganizationalUnit -Name "$niv2" -Path "ou=$niv1,ou=$partages,ou=$racine,dc=$domain,dc=$ext" -ProtectedFromAccidentalDeletion $False
}
pause

# Creation des utilisateurs
write-host *****************************
write-host * CREATION DES UTILISATEURS *
write-host *****************************

Get-Content -Path "$PSSCRIPTROOT\USERS.csv" | Out-File -FilePath "$PSSCRIPTROOT\USERS_uni.csv" -Encoding Unicode
$ADUsers = Import-Csv $PSSCRIPTROOT\USERS_uni.csv -Delimiter ","


foreach ($User in $ADUsers) {

    
    $username = $User.username
    $password = $User.password
    $firstname = $User.firstname
    $lastname = $User.lastname
    $OU = $User.ou #This field refers to the OU the user account is to be created in


    
    if (Get-ADUser -F { SamAccountName -eq $username }) {
        
        
        Write-Warning "UN UTILISATEUR AVEC LE NOM $username EXISTE DEJA."
    }
    else {

        
        New-ADUser `
            -SamAccountName "$username" `
            -Name "$firstname $lastname" `
            -GivenName "$firstname" `
            -Surname "$lastname" `
            -Enabled $True `
            -DisplayName "$lastname, $firstname" `
            -Path "$OU" `
            -AccountPassword (ConvertTo-secureString $password -AsPlainText -Force) -ChangePasswordAtLogon $True


        
        Write-Host "UTILISATEUR $username CREE." -ForegroundColor Green;
    }
}
pause

# creation des Groupes globaux
write-host ********************************
write-host * CREATION DES GROUPES GLOBAUX *
write-host ********************************

Get-Content -Path "$PSSCRIPTROOT\GROUPS_USERS.csv" | Out-File -FilePath "$PSSCRIPTROOT\GROUPS_USERSUni.csv" -Encoding Unicode
Import-Csv -Delimiter "," -Path "$PSSCRIPTROOT\GROUPS_USERSUni.csv" | select GROUPES | Select -ExpandProperty GROUPES | Sort-Object -Unique | Foreach-Object {

$GG=$_
$testGG = Test-ADGroup $GG
if ( $testGG -eq $True)
{
write-host GROUPE DEJA EXISTANT: $GG 
}
else
{
write-host CREATION DU GROUPE GLOBAL: $GG -ForegroundColor Green;
New-ADGroup -Name $GG -GroupScope Global -GroupCategory Security -Path "ou=Groupes Utilisateurs,ou=Groupes,ou=$racine,dc=$domain,dc=$ext"
}
}
pause
# Ajout des membres dans les groupes
write-host *************************************
write-host * AFFECTATION DES USERS AUX GROUPES *
write-host *************************************
$GroupUsers = Import-Csv -Delimiter "," -Path “$PSSCRIPTROOT\GROUPS_USERSUni.csv”
ForEach ($user in $GroupUsers) {
Add-ADGroupMember -Identity $user.GROUPES -Members $user.UTILISATEURS
write-host $user.UTILISATEURS est membre de $user.GROUPES -ForegroundColor Green;
}
pause
# création des groupes locaux de partages dans l'OU Niveau_0 de Groupes NTFS
write-host ************************************
write-host * CREATION DES GROUPES DL PARTAGES *
write-host ************************************


import-csv -Delimiter "," -path $PSSCRIPTROOT\ARBO_CLIENT.csv|select partages,niveau1,niveau2,DL_auto | Where-Object { [string]::IsNullOrEmpty($_.niveau2) -and [string]::IsNullOrEmpty($_.niveau1) } |foreach {
$partage=$_.dl_auto
$nameRWP=$partage+'_RW_PARENT'
$nameRWC=$partage+'_RW_CHILDREN'
$nameRO=$partage+'_RO'

write-host CREATION DU GROUPE LOCAL PARTAGES: $nameRWP -ForegroundColor Green;
New-ADGroup -Name $nameRWP -GroupScope DomainLocal -GroupCategory Security -Path "ou=NIVEAU 0,ou=Groupes NTFS,ou=Groupes,ou=$racine,dc=$domain,dc=$ext"
write-host CREATION DU GROUPE LOCAL PARTAGES: $nameRO -ForegroundColor Green;
New-ADGroup -Name $nameRO -GroupScope DomainLocal -GroupCategory Security -Path "ou=NIVEAU 0,ou=Groupes NTFS,ou=Groupes,ou=$racine,dc=$domain,dc=$ext"
write-host CREATION DU GROUPE LOCAL PARTAGES: $nameRWP -ForegroundColor Green;
New-ADGroup -Name $nameRWP -GroupScope DomainLocal -GroupCategory Security -Path "ou=NIVEAU 0,ou=Groupes NTFS,ou=Groupes,ou=$racine,dc=$domain,dc=$ext"
}
pause
# création des groupes locaux de partages dans l'OU Niveau_1 de Groupes NTFS
write-host ***************************************
write-host * CREATION DES GROUPES DL AU NIVEAU 1 *
write-host ***************************************

import-csv -Delimiter "," -path $PSSCRIPTROOT\ARBO_CLIENT.csv | select partages,niveau1,niveau2,DL_auto | Where-Object {$_.niveau1 -gt 0 -and [string]::IsNullOrEmpty($_.niveau2)} |foreach {
$partage=$_.dl_auto
$nameRWP=$partage+'_RW_PARENT'
$nameRWC=$partage+'_RW_CHILDREN'
$nameRO=$partage+'_RO'

write-host CREATION DU GROUPE LOCAL NIVEAU 1: $nameRWP -ForegroundColor Green;
New-ADGroup -Name $nameRWP -GroupScope DomainLocal -GroupCategory Security -Path "ou=NIVEAU 1,ou=Groupes NTFS,ou=Groupes,ou=$racine,dc=$domain,dc=$ext"
write-host CREATION DU GROUPE LOCAL NIVEAU 1: $nameRO -ForegroundColor Green;
New-ADGroup -Name $nameRO -GroupScope DomainLocal -GroupCategory Security -Path "ou=NIVEAU 1,ou=Groupes NTFS,ou=Groupes,ou=$racine,dc=$domain,dc=$ext"
write-host CREATION DU GROUPE LOCAL NIVEAU 1: $nameRWC -ForegroundColor Green;
New-ADGroup -Name $nameRWC -GroupScope DomainLocal -GroupCategory Security -Path "ou=NIVEAU 1,ou=Groupes NTFS,ou=Groupes,ou=$racine,dc=$domain,dc=$ext"
}
pause
# création des groupes locaux de partages dans l'OU Niveau_2 de Groupes NTFS
write-host ************************************
write-host * CREATION DES GROUPES DL NIVEAU 2 *
write-host ************************************

import-csv -Delimiter "," -path $PSSCRIPTROOT\ARBO_CLIENT.csv | select partages,niveau1,niveau2,DL_auto | Where-Object {$_.niveau2 -gt 0}|foreach {
$partage=$_.dl_auto
$nameRWP=$partage+'_RWP'
$nameRWC=$partage+'_RWC'
$nameRO=$partage+'_RO'

write-host CREATION DU GROUPE LOCAL NIVEAU 2: $nameRWP -ForegroundColor Green;
New-ADGroup -Name $nameRWP -GroupScope DomainLocal -GroupCategory Security -Path "ou=NIVEAU 2,ou=Groupes NTFS,ou=Groupes,ou=$racine,dc=$domain,dc=$ext"
write-host CREATION DU GROUPE LOCAL NIVEAU 2: $nameRO -ForegroundColor Green;
New-ADGroup -Name $nameRO -GroupScope DomainLocal -GroupCategory Security -Path "ou=NIVEAU 2,ou=Groupes NTFS,ou=Groupes,ou=$racine,dc=$domain,dc=$ext"
write-host CREATION DU GROUPE LOCAL NIVEAU 2: $nameRWC -ForegroundColor Green;
New-ADGroup -Name $nameRWC -GroupScope DomainLocal -GroupCategory Security -Path "ou=NIVEAU 2,ou=Groupes NTFS,ou=Groupes,ou=$racine,dc=$domain,dc=$ext"
}
pause
# Creation des utilisateurs
write-host ************************************
write-host * MISE EN PLACE DES GG DANS LES DL *
write-host ************************************

$DROITSDL = Import-Csv $PSSCRIPTROOT\GROUPS_DROITS.csv -Delimiter ","


Foreach ($data in $DROITSDL) 
{
    
    $DL = $data.DL
    $GROUPES = $data.GROUPES
    $DROITS = $data.DROITS
   write-host $DL - $GROUPES - $DROITS

    If ($DROITS -eq 'RW')
    { 
    $nameRW=$DL+'_RWP'
	#Get-ADGroupMember $nameRW | ForEach-Object {Remove-ADGroupMember $nameRW $_ -Confirm:$false}
    $DNameRWP= Get-ADGroup -Filter "Name -like '*$nameRWP*'"
    write-host CREATION LIEN: $GROUPES EST MEMBRE DE $nameRWP -ForegroundColor Green;
    Add-ADGroupMember -Identity $DNameRWP -Members $GROUPES
    } 


    If ($DROITS -eq 'RW')
    { 
    $nameRWC=$DL+'_RWC'
	#Get-ADGroupMember $nameRW | ForEach-Object {Remove-ADGroupMember $nameRW $_ -Confirm:$false}
    $DNameRWC= Get-ADGroup -Filter "Name -like '*$nameRWC*'"
    write-host CREATION LIEN: $GROUPES EST MEMBRE DE $nameRWC -ForegroundColor Green;
    Add-ADGroupMember -Identity $DNameRWC -Members $GROUPES
    } 


    If ($DROITS -eq 'RO')
        { 
        $nameRO=$DL+'_RO'
        #Get-ADGroupMember $nameRO | ForEach-Object {Remove-ADGroupMember $nameRO $_ -Confirm:$false}
        $DNameRO= Get-ADGroup -Filter "Name -like '*$nameRO*'"
        write-host CREATION LIEN:  $GROUPES EST MEMBRE DE $nameRO -ForegroundColor Green;
        Add-ADGroupMember -Identity $DNameRO -Members $GROUPES
        }
}
pause

# Application des DL_RO et DL_RW sur les dossiers
# EA+DA
write-host ****************************************************
write-host * MISE EN PLACE DES DL RO RW SUR TOUS LES DOSSIERS *
write-host ****************************************************

write-host ********************************************************
write-host * MISE EN PLACE DES DL RO RW SUR LES DOSSIERS NIVEAU 0 *
write-host ********************************************************

import-csv -Delimiter "," -path $PSSCRIPTROOT\ARBO_CLIENT.csv|select chemin_complet,partages,niveau1,niveau2,DL_auto | Where-Object { [string]::IsNullOrEmpty($_.niveau2) -and [string]::IsNullOrEmpty($_.niveau1) } |%{
$partage=$_.dl_auto
$nameRWP=$partage+'_RW'
$nameRWC=$partage+'_RW'
$nameRO=$partage+'_RO'
$chemin=$_.chemin_complet


$ACL = Get-ACL $chemin

        # Supprimer les ACL
        $acl.Access | %{$acl.RemoveAccessRule($_)} # % est équivalent à For Each et $_ indique l'objet en cours

 

        # Droits complets pour le groupe Administrateurs
        $permission  = "Administrateurs","FullControl", "ContainerInherit,ObjectInherit","None","Allow"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
        $acl.SetAccessRule($accessRule) #Ajouter le droits
        
        # Droits complets pour le groupe Système
        $permission  = "Système","FullControl", "ContainerInherit,ObjectInherit","None","Allow"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
        $acl.SetAccessRule($accessRule) #Ajouter le droits
       
        # Droits de modification pour le groupe DL_RWC
         $permission  = "$nameRWC","Modify","ContainerInherit, ObjectInherit", "None", "Allow" #Paramètres dans l'ordre : Le compte, FileSystemRights (Read, ReadAndExecute, Write, Modify, ListDirectory, FullControl etc), InheritanceFlags (ContainerInherit None ou ObjectInherit), PropagationFlags (InheritOnly, None ou NoPropagateInherit) , AccessControlType (Allow, Deny)
         $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission 
         $acl.SetAccessRule($AccessRule) #Ajouter le droits
         $acl.SetAccessRuleProtection($true,$false) #desactiver l'heritage en supprimant les ACL hérités

         # Droits de limités sur le dossier pour le groupe DL_RWP
         $permission  = "$nameRWP",'ReadAndExecute', 'None', 'None', 'Allow') #Paramètres dans l'ordre : Le compte, FileSystemRights (Read, ReadAndExecute, Write, Modify, ListDirectory, FullControl etc), InheritanceFlags (ContainerInherit None ou ObjectInherit), PropagationFlags (InheritOnly, None ou NoPropagateInherit) , AccessControlType (Allow, Deny)
         $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission 
         $acl.SetAccessRule($AccessRule) #Ajouter le droits
         $acl.SetAccessRuleProtection($true,$false) #desactiver l'heritage en supprimant les ACL hérités

         #Droits de lecture pour le groupe DL_RO
         $permission2  = "$nameRO","ReadAndExecute","ContainerInherit, ObjectInherit", "None", "Allow" #Paramètres dans l'ordre : Le compte, FileSystemRights (Read, ReadAndExecute, Write, Modify, ListDirectory, FullControl etc), InheritanceFlags (ContainerInherit None ou ObjectInherit), PropagationFlags (InheritOnly, None ou NoPropagateInherit) , AccessControlType (Allow, Deny)
         $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission2 
         $acl.SetAccessRule($AccessRule) #Ajouter le droits
         $acl.SetAccessRuleProtection($true,$false) #desactiver l'heritage en supprimant les ACL hérités
         
         #Mise à jour des droits sur le dossier
         write-host APPLICATION DES DROITS RW ET RO SUR LE DOSSIER $chemin -ForegroundColor Green;
         $acl |Set-Acl #Appliquer les droits
}
pause

write-host ********************************************************
write-host * MISE EN PLACE DES DL RO RW SUR LES DOSSIERS NIVEAU 1 *
write-host ********************************************************

import-csv -Delimiter "," -path $PSSCRIPTROOT\ARBO_CLIENT.csv | select chemin_complet,partages,niveau1,niveau2,DL_auto | Where-Object {$_.niveau1 -gt 0 -and [string]::IsNullOrEmpty($_.niveau2)} | %{
$partage=$_.dl_auto
$nameRWP=$partage+'_RW'
$nameRWC=$partage+'_RW'
$nameRO=$partage+'_RO'
$chemin=$_.chemin_complet


$ACL = Get-ACL $chemin

        # Supprimer les ACL
        $acl.Access | %{$acl.RemoveAccessRule($_)} # % est équivalent à For Each et $_ indique l'objet en cours

 

        # Droits complets pour le groupe Administrateurs
        $permission  = "Administrateurs","FullControl", "ContainerInherit,ObjectInherit","None","Allow"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
        $acl.SetAccessRule($accessRule) #Ajouter le droits
        
        # Droits complets pour le groupe Système
        $permission  = "Système","FullControl", "ContainerInherit,ObjectInherit","None","Allow"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
        $acl.SetAccessRule($accessRule) #Ajouter le droits
       
         # Droits de modification pour le groupe DL_RWC
         $permission  = "$nameRWC","Modify","ContainerInherit, ObjectInherit", "None", "Allow" #Paramètres dans l'ordre : Le compte, FileSystemRights (Read, ReadAndExecute, Write, Modify, ListDirectory, FullControl etc), InheritanceFlags (ContainerInherit None ou ObjectInherit), PropagationFlags (InheritOnly, None ou NoPropagateInherit) , AccessControlType (Allow, Deny)
         $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission 
         $acl.SetAccessRule($AccessRule) #Ajouter le droits
         $acl.SetAccessRuleProtection($true,$false) #desactiver l'heritage en supprimant les ACL hérités

         # Droits de limités sur le dossier pour le groupe DL_RWP
         $permission  = "$nameRWP",'ReadAndExecute', 'None', 'None', 'Allow') #Paramètres dans l'ordre : Le compte, FileSystemRights (Read, ReadAndExecute, Write, Modify, ListDirectory, FullControl etc), InheritanceFlags (ContainerInherit None ou ObjectInherit), PropagationFlags (InheritOnly, None ou NoPropagateInherit) , AccessControlType (Allow, Deny)
         $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission 
         $acl.SetAccessRule($AccessRule) #Ajouter le droits
         $acl.SetAccessRuleProtection($true,$false) #desactiver l'heritage en supprimant les ACL hérités

         #Droits de lecture pour le groupe DL_RO
         $permission2  = "$nameRO","ReadAndExecute","ContainerInherit, ObjectInherit", "None", "Allow" #Paramètres dans l'ordre : Le compte, FileSystemRights (Read, ReadAndExecute, Write, Modify, ListDirectory, FullControl etc), InheritanceFlags (ContainerInherit None ou ObjectInherit), PropagationFlags (InheritOnly, None ou NoPropagateInherit) , AccessControlType (Allow, Deny)
         $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission2 
         $acl.SetAccessRule($AccessRule) #Ajouter le droits
         $acl.SetAccessRuleProtection($true,$false) #desactiver l'heritage en supprimant les ACL hérités
         
         #Mise à jour des droits sur le dossier
         write-host APPLICATION DES DROITS RW ET RO SUR LE DOSSIER $chemin -ForegroundColor Green;
         $acl |Set-Acl #Appliquer les droits
}
pause

write-host ********************************************************
write-host * MISE EN PLACE DES DL RO RW SUR LES DOSSIERS NIVEAU 2 *
write-host ********************************************************

import-csv -Delimiter "," -path $PSSCRIPTROOT\ARBO_CLIENT.csv | select chemin_complet,partages,niveau1,niveau2,DL_auto | Where-Object {$_.niveau2 -gt 0} |%{
$partage=$_.dl_auto
$nameRWP=$partage+'_RW'
$nameRWC=$partage+'_RW'
$nameRO=$partage+'_RO'
$chemin=$_.chemin_complet

$ACL = Get-ACL $chemin

        # Supprimer les ACL
        $acl.Access | %{$acl.RemoveAccessRule($_)} # % est équivalent à For Each et $_ indique l'objet en cours

 

        # Droits complets pour le groupe Administrateurs
        $permission  = "Administrateurs","FullControl", "ContainerInherit,ObjectInherit","None","Allow"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
        $acl.SetAccessRule($accessRule) #Ajouter le droits
        
        # Droits complets pour le groupe Système
        $permission  = "Système","FullControl", "ContainerInherit,ObjectInherit","None","Allow"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
        $acl.SetAccessRule($accessRule) #Ajouter le droits

        # Droits de modification pour le groupe DL_RWC
         $permission  = "$nameRWC","Modify","ContainerInherit, ObjectInherit", "None", "Allow" #Paramètres dans l'ordre : Le compte, FileSystemRights (Read, ReadAndExecute, Write, Modify, ListDirectory, FullControl etc), InheritanceFlags (ContainerInherit None ou ObjectInherit), PropagationFlags (InheritOnly, None ou NoPropagateInherit) , AccessControlType (Allow, Deny)
         $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission 
         $acl.SetAccessRule($AccessRule) #Ajouter le droits
         $acl.SetAccessRuleProtection($true,$false) #desactiver l'heritage en supprimant les ACL hérités

         # Droits de limités sur le dossier pour le groupe DL_RWP
         $permission  = "$nameRWP",'ReadAndExecute', 'None', 'None', 'Allow') #Paramètres dans l'ordre : Le compte, FileSystemRights (Read, ReadAndExecute, Write, Modify, ListDirectory, FullControl etc), InheritanceFlags (ContainerInherit None ou ObjectInherit), PropagationFlags (InheritOnly, None ou NoPropagateInherit) , AccessControlType (Allow, Deny)
         $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission 
         $acl.SetAccessRule($AccessRule) #Ajouter le droits
         $acl.SetAccessRuleProtection($true,$false) #desactiver l'heritage en supprimant les ACL hérités

         #Droits de lecture pour le groupe DL_RO
         $permission2  = "$nameRO","ReadAndExecute","ContainerInherit, ObjectInherit", "None", "Allow" #Paramètres dans l'ordre : Le compte, FileSystemRights (Read, ReadAndExecute, Write, Modify, ListDirectory, FullControl etc), InheritanceFlags (ContainerInherit None ou ObjectInherit), PropagationFlags (InheritOnly, None ou NoPropagateInherit) , AccessControlType (Allow, Deny)
         $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission2 
         $acl.SetAccessRule($AccessRule) #Ajouter le droits
         $acl.SetAccessRuleProtection($true,$false) #desactiver l'heritage en supprimant les ACL hérités
         
         #Mise à jour des droits sur le dossier
         write-host APPLICATION DES DROITS RW ET RO SUR LE DOSSIER $chemin -ForegroundColor Green;
         $acl |Set-Acl #Appliquer les droits
}
# Suppression des fichiers inutiles
# rm $PSSCRIPTROOT\ARBO_CLIENTUni.csv
write-host "On passe un coup de balai"
rm $PSSCRIPTROOT\ARBO_ADUni.csv
rm $PSSCRIPTROOT\USERS_uni.csv
rm $PSSCRIPTROOT\GROUPS_USERSUni.csv
write-host C EST DEJA FINI!!!!!!!
write-host C EST COOL NON?
write-warning "Le script est en pause pour vous permettre de vérifier les erreurs"
pause
