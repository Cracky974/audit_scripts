#Cherche dans les fichiers donnés par le script pour l'audit windows
#Idée pour plus tard, "voulez vous faire tourner le script pour recupéré la conf ? Y/N" et le lancer (le plus, ajouter des cmd dans le script qui pourront s'effectuer


Set-Alias ss Select-String



$onAudit

$version = (ss -Pattern "version :(.+)" sysInfos.txt).Matches.groups[1].value
$hote = $(ss -Pattern "Nom de l'h�te:( +)(.+)" systeminfo.txt).Matches.Groups[2].value
$OS = $(ss -Pattern "Nom du syst�me d'exploitation:( +)(.+)" systeminfo.txt).Matches.Groups[2].value
$GPObitlocker = $(ss -Pattern " GPPT Global Windows 10 Bitlocker Policy V2" gpres*.txt)

#Fw activé sur le domaine
$isFWenDom = $(ss -Pattern "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile\\EnableFirewall;(.+)" *).Matches.Groups[1].value
#FW activé sur l'hote
$isFWenHo = $(ss -Pattern "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\EnableFirewall;(.+)" *).Matches.Groups[1].value
$AntiVirusProduct = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct
#isWinrmEn vérifie que Winrm est activé pour l'envoie de logs
$isWinrmEn = $(ss -Pattern "WinRM(  +)(.+)( +)(.+)" services.txt).Matches.Groups[4].value
$winrmMode = $(ss -Pattern "WinRM(  +)(.+)( +)(.+)" services.txt).Matches.Groups[2].value
#Password policy
$passwdHistorySize = [int]$(ss -Pattern "PasswordHistorySize = ([0-9]+)" secedit.txt).Matches.Groups[1].value
$maximumPasswdAge = [int]$(ss -Pattern "MaximumPasswordAge = ([0-9]+)" secedit.txt).Matches.Groups[1].value
$minimumPasswdAge = [int]$(ss -Pattern "MinimumPasswordAge = ([0-9]+)" secedit.txt).Matches.Groups[1].value
$minimumPasswdLength = [int]$(ss -Pattern "MinimumPasswordLength = ([0-9]+)" secedit.txt).Matches.Groups[1].value
#Account Lockout Policy
$LockoutDuration = [int]$(ss -Pattern "LockoutDuration = ([0-9]+)" secedit.txt).Matches.Groups[1].value
$LockoutBadCount = [int]$(ss -Pattern "LockoutBadCount = ([0-9]+)" secedit.txt).Matches.Groups[1].value
#Admin approval
$adminApproval = [int]$(ss -Pattern "ConsentPromptBehaviorAdmin=4,([0-9]+)" secedit.txt).Matches.Groups[1].value
#Installation d'application
$appInstall = [int]$(ss -Pattern "EnableInstallerDetection=4,([0-9]+)" secedit.txt).Matches.Groups[1].value
#MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA
$enableLUA = [int]$(ss -Pattern "EnableLUA=4,([0-9]+)" secedit.txt).Matches.Groups[1].value
#MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=4,1
$secureDesktop = [int]$(ss -Pattern "PromptOnSecureDesktop=4,([0-9]+)" secedit.txt).Matches.Groups[1].value 
#MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=4,1
$enableVirtualization = [int]$(ss -Pattern "EnableVirtualization=4,([0-9]+)" secedit.txt).Matches.Groups[1].value 
$enableUIADesktopToggle = [int]$(ss -Pattern "EnableUIADesktopToggle=4,([0-9]+)" secedit.txt).Matches.Groups[1].value
$remotelyAccessibleReg = $(ss -Pattern "AllowedPaths\\Machine=7,(.+)" secedit.txt).Matches.Groups[1].value
$answerRemotelyAccessibleReg = "System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog"
$newAdminName = $(ss -Pattern "NewAdministratorName = (.+)" secedit.txt).Matches.Groups[1].value
$newGuestName = $(ss -Pattern "NewGuestName = (.+)" secedit.txt).Matches.Groups[1].value
$requireSignOrSeal = $(ss -Pattern "RequireSignOrSeal=4,([0-9]+)" secedit.txt).Matches.Groups[1].value
$DisablePasswordChange = $(ss -Pattern "DisablePasswordChange=4,([0-9]+)" secedit.txt).Matches.Groups[1].value
$DontDisplayLastUserName =  $(ss -Pattern "DontDisplayLastUserName;(.+)" miscReg.txt).Matches.Groups[1].value
$AutoDisconnect = [int]$(ss -Pattern "AutoDisconnect=4,(.+)" secedit.txt).Matches.Groups[1].value
$AutoAdminLogon = $(ss -Pattern "AutoAdminLogon;(.+)" miscReg.txt).Matches.Groups[1].value
$DisableIPSourceRouting = $(ss -Pattern "DisableIPSourceRouting;(.+)" miscReg.txt).Matches.Groups[1].value
$EnableICMPRedirect = $(ss -Pattern "EnableICMPRedirect;(.+)" miscReg.txt).Matches.Groups[1].value
$KeepAliveTime = $(ss -Pattern "KeepAliveTime;(.+)" miscReg.txt).Matches.Groups[1].value
$PerformRouterDiscovery = $(ss -Pattern "PerformRouterDiscovery;(.+)" miscReg.txt).Matches.Groups[1].value
$TcpMaxDataRetransmissions = $(ss -Pattern "TcpMaxDataRetransmissions;(.+)" miscReg.txt).Matches.Groups[1].value
$RestrictAnonymousSAM = [int]$(ss -Pattern "RestrictAnonymousSAM=4,(.+)" secedit.txt).Matches.Groups[1].value
$NullSessionPipes = $(ss -Pattern "NullSessionPipes=7,(.+)" secedit.txt).Matches.Groups[1].value
$Machine = $(ss -Pattern "AllowedExactPaths\\Machine=7,(.+)" secedit.txt).Matches.Groups[1].value
$RestrictNullSessAccess = $(ss -Pattern "RestrictNullSessAccess=4,(.+)" secedit.txt).Matches.Groups[1].value
$ForceGuest = $(ss -Pattern "ForceGuest=4,(.+)" secedit.txt).Matches.Groups[1].value
$ObCaseInsensitive = $(ss -Pattern "ObCaseInsensitive=4,(.+)" secedit.txt).Matches.Groups[1].value
$ProtectionMode = $(ss -Pattern "ProtectionMode=4,(.+)" secedit.txt).Matches.Groups[1].value
$CachedLogonCount = [int]$(ss -Pattern "cachedlogonscount;(.+)" miscReg.txt).Matches.Groups[1].value

############################################################################################################################


"
Hote : $hote"
"
OS : $OS"
"
Version : $version"
"
GPO Bitlocker : $(if($GPObitlocker) {"GPO bitlocker est activé" } else {"GPO bitlocker désactivé (vérifier manuellement)"})"
"
Verifier le backup avec wbadmin.exe ainsi que leurs chiffrement"

if($onAudit -eq "Y"){
wbadmin.exe > ./resultwbadmin.txt
"Regarder le resultat dans resultwbadmin.txt"
}
"
Pare-feu actif sur le domaine : $isFWenDom"
"
Pare-feu actif sur l'hote : $isFWenHo"

if ((Get-Content .\checkForUpdateOffline.txt | Measure-Object –Line).Lines -gt 10){
"
Les logiciels partenaires windows ne semblent pas être à jours ($((Get-Content .\checkForUpdateOffline.txt | Measure-Object –Line).Lines - 2) log non à jour)"
} else {"Les logiciels partenaires windows semblent à jours"}

if($onAudit -eq "Y"){
"
Produit antivirus : "+$AntiVirusProduct.displayName
}
"
Externalisation des evenements :
Winrm est $isWinrmEn, en mode $winrmMode"

"
Password policy :
Historique des mots de passe : $passwdHistorysize" 
if($passwdHistorySize -lt 24){"Non conforme, le CIS recommande un historique de mdp de 24 ou plus" }
else{"Conforme"}

"Durée de vie des mot de passes : $maximumPasswdAge"
if(-Not($maximumPasswdAge -lt 60 -and -not 0)){"Non conforme, le CIS recommande de changer de mot de passe tous les 90j ou moins" }
else{"Conforme"}

"Durée d’utilisation minimum d’un mot de passe : $minimumPasswdAge"
if($minimumPasswdAge -lt 1){"Non conforme, le CIS recommande une durée de vie de mdp minimal de 1j" }
else{"Conforme"}

"Taille minimum des mots de passe : $minimumPasswdLength"
if($minimumPasswdLength -lt 14 -and $minimumPasswdLength -gt 7) {"Conformité partiel, mot de passe de 8 caratère ou +, mot de passe fort mais pas assez pour les recommendations CIS"}
elseif($minimumPasswdLength -lt 14){"Non conforme, le CIS recommande une taille de mot de passe de plus de 14 caractère" }
else{"Conforme"}

"
Account Lockout Policy:
Durée de verrouillage des comptes : $LockoutDuration"
if($LockoutDuration -lt 15){"Non conforme, le CIS recommande de verrouiller le compte pour 15 minutes ou plus" }
else{"Conforme"}
"Seuil de verrouillage de comptes: $LockoutBadCount"
if(-Not($LockoutBadCount -lt 10 -and -not 0)){"Non conforme, le CIS recommande de verrouiller le compte au bout de 10 tentatives ou moins, mais pas 0" }
else{"Conforme"}
#Rajouter :
#dans secedit.txt PasswordComplexity = 1

#Lockout duration (minutes):                           30
#

#"Audit des evenements : "
$auditSystemEvents = $(ss -Pattern "AuditSystemEvents = ([0-9]+)" secedit.txt).Matches.Groups[1].value
$auditLogonEvents = $(ss -Pattern "AuditLogonEvents = ([0-9]+)" secedit.txt).Matches.Groups[1].value
$AuditObjectAccess = $(ss -Pattern "AuditObjectAccess = ([0-9]+)" secedit.txt).Matches.Groups[1].value
$AuditPrivilegeUse = $(ss -Pattern "AuditPrivilegeUse = ([0-9]+)" secedit.txt).Matches.Groups[1].value
$AuditPolicyChange = $(ss -Pattern "AuditPolicyChange = ([0-9]+)" secedit.txt).Matches.Groups[1].value
$AuditAccountManage = $(ss -Pattern "AuditAccountManage = ([0-9]+)" secedit.txt).Matches.Groups[1].value
$AuditProcessTracking = $(ss -Pattern "AuditDSAccess = ([0-9]+)" secedit.txt).Matches.Groups[1].value
$AuditDSAccess = $(ss -Pattern "AuditProcessTracking = ([0-9]+)" secedit.txt).Matches.Groups[1].value
$AuditAccountLogon = $(ss -Pattern "AuditAccountLogon = ([0-9]+)" secedit.txt).Matches.Groups[1].value


#[Event Audit]
#AuditSystemEvents = 0
#AuditLogonEvents = 3
#AuditObjectAccess = 1
#AuditPrivilegeUse = 0
#AuditPolicyChange = 1
#AuditAccountManage = 3
#AuditProcessTracking = 0
#AuditDSAccess = 0
#AuditAccountLogon = 0
"
Mode admin approval : MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=$adminapproval "
if($adminApproval -eq 2){"
Conforme"}
else{"Non conforme, doit être egal a 2"}

"Installation d’application : HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableInstallerDetection = $appInstall"
if($appInstall -eq 1){"CONFORME. La GPO Detect application installations and prompt for elevation est activée"}
else{"NON CONFORME"}

"Activer l’UAC pour les comptes administrateurs : MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=$enableLUA"
if($enableLUA -eq 1){"CONFORME"}
else{"NON CONFORME. activé la GPO :
Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop"}

"
Afficher la fenêtre d’élévation de privilèges : 
La GPO suivante doit être activée : Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Switch to the secure desktop when prompting for elevation
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=$secureDesktop"
if($secureDesktop -eq 1){"CONFORME"}
else{"NON CONFORME"}

"
Fichiers et registres virtuels :
La GPO suivante doit être activée :
Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Virtualize file and registry write failures to per-user locations
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=$enableVirtualization"
if($enableVirtualization -eq 1){"CONFORME"}
else{"NON CONFORME"}

"
Elévation de privilèges pour les applications UIAccess:
Cette GPO définit si une application est autorisée à élever ses privilèges sans utiliser le « secure desktop »
Cette GPO doit être désactivé.
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle=4,0"
if($enableUIADesktopToggle -eq 0){"CONFORME"}
else{"NON CONFORME"}

"
Accès à distance au chemin des registres.:
"
if($remotelyAccessibleReg -eq $answerRemotelyAccessibleReg){"CONFORME"}
else{"NON CONFORME; $remotelyAccessibleReg"}

"
Renommer le compte d'administration : 
Compte admin : $NewAdminName"
if($NewAdminName -eq '"Administrateur"' -or $NewAdminName -eq '"Administrator"'){"NON CONFORME"}
else{"CONFORME"}

"
Renommer ou desactivé le compte invité : 
Compte invité : $newGuestName"
if([int]$(ss -Pattern "EnableGuestAccount = ([0-9]+)" secedit.txt).Matches.Groups[1].Value -eq 0){"CONFORME, compte désactivé"}
elseif($newGuestName -eq '"Invité"' -or $newGuestName -eq '"Guest"'){"NON CONFORME"}
else{"CONFORME"}

"
Média amovibles :
Le privilège de formater et d’éjecter des media amovible doit être accordé qu’aux Administateurs.
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:AllocateDASD (NON VERIFIE)"


"
Chiffrement pour les canaux sécurisés:
La GPO suivante vérifie que le chiffrement est activé lors de l’utilisation de canaux sécurisés.
Elle doit être activée.
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters:RequireSignOrSeal=$RequireSignOrSeal"
if($RequireSignOrSeal -eq 1){"CONFORME"}
else{"NON CONFORME"}

"
Changement volontaire de mots de passe :
La GPO suivante autorise un utilisateur de changer périodiquement le mot de passe de son compte.
Elle doit être désactivée.
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters:DisablePasswordChange=$DisablePasswordChange"
if($DisablePasswordChange -eq 0){"CONFORME"}
else{"NON CONFORME"}

#Winlogon\DontDisplayLastUserName
"
Affichage dernier utilisateur:
Il est recommandé de ne pas afficher l’identifiant du compte du dernier utilisateur à s’être connecté sur un poste.
Winlogon\DontDisplayLastUserName = $DontDisplayLastUserName"
if($DontDisplayLastUserName -eq 1){"CONFORME"}
else{"NON CONFORME"}

"
Déconnexion automatique des utilisateurs:
Après une période d’inactivité, il est conseillé de faire fermer automatique les sessions ouverte.
La GPO suivante doit être activée :
Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network server: Amount of idle time required before suspending session
LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:AutoDisconnect = $AutoDisconnect"
if($AutoDisconnect -lt 16 -and -not 0){"CONFORME"}
else{"NON CONFORME, doit etre à 15 ou moins mais pas 0"}

"
Connexion automatique
La GPO suivante définit si un utilisateur avec un accès physique au poste est capable de s’authentifier automatiquement.
Elle doit être désactivée :
Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon = $AutoAdminLogon"
if($AutoAdminLogon -eq 0){"CONFORME"}
else{"NON CONFORME"}
"
Mauvais niveau de protection contre « IP source routing »
La GPO contrôle si Windows accepte les paquets « source routed ». Le « source routing » autorise l’émetteur des packets à imposer la route que prendra le packet jusqu'à sa destination.
Vérifier que la GPO est configurée avec les paramètres suivants : Highest protection, source routing is completely disabled
HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting = $DisableIPSourceRouting"
if($DisableIPSourceRouting -eq 0 -or "Disabled"){"CONFORME"}
else{"NON CONFORME
Un attaquant peut envoyer des paquets en spécifiant une route évitant certains intermédiaires de protection." }

"
Messages ICMP
La GPO détermine si les messages ICMP redirigés sont autorisés à effacer les routes OSPF.
Vérifier que la GPO est désactivée.
HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect = $EnableICMPRedirect"
if($DisableIPSourceRouting -eq 0 -or "Disabled"){"CONFORME"}
else{"NON CONFORME.
Un attaquant peut modifier la vision du réseau qu’à le poste."}

"
Fréquence d’envoi des paquets Keep-Alive
L’envoie de paquets Keep-Alive vérifie que la connexion entre deux machine est toujours active.
Il est recommandé d’initialiser la GPO à 5 minutes.
HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime= $KeepAliveTime"
if($KeepAliveTime -eq 300000){"CONFORME 300000/5mn"}
else{"NON CONFORME, Des attaquants peuvent maintenir ouverts de multiples sessions en simultané et créer un déni de service."}

"
Internet Router Discover Protocol (IRDP)
L’Internet Router Discover Protocol (IRDP) est utilisé pour détecter et configurer automatiquement l’adresse de la passerelle par défaut.
Vérifier que la GPO suivante est désactivé :
Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\parameters\PerformRouterDiscovery = $PerformRouterDiscovery"
if($DisableIPSourceRouting -eq 0 -or "Disabled"){"CONFORME"}
else{"Un attaquant qui a pris le contrôle d'un ordinateur sur le même segment de réseau peut configurer un ordinateur sur le réseau pour usurper l'identité d'un routeur. Les autres ordinateurs sur lesquels IRDP est activé essaient alors d'acheminer leur trafic via l'ordinateur déjà compromis."}

"
Données « non reconnues »
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters:TcpMaxDataRetransmissions=$TcpMaxDataRetransmissions"
if($TcpMaxDataRetransmissions -eq 3 -or $TcpMaxDataRetransmissions -eq "Enabled: 3"){"CONFORME"}
else{"NON CONFORME, doit etre initialisé a 3"}

"
Enumération des comptes SAM
Cette GPO définit si un utilisateur anonyme est autorisé d’énumérer les comptes présents dans le Security Account Manager.
Il est conseillé d’activer la GPO suivante :
Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Do not allow anonymous enumeration of SAM accounts
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM=$RestrictAnonymousSAM "
if($RestrictAnonymousSAM -eq 1){"CONFORME"}
else{"NON CONFORME.Un utilisateur sans privilèges pourrait lister les comptes et ressources partagées."}

"
Permissions pour les utilisateurs anonymes
Cette GPO définit quelle permissions supplémentaire seront appliquées aux utilisateurs anonymes.
Il est conseillé de désactiver la GPO suivante :
Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Let Everyone permissions apply to anonymous users
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes=$NullSessionPipes"
if($NullSessionPipes -eq $null){"CONFORME"}
else{"Level 1 - Domain Controller. The recommended state for this setting is: LSARPC, NETLOGON, SAMR and (when the legacy Computer Browser service is enabled) BROWSER.
 Level 1 - Member Server. The recommended state for this setting is: <blank> (i.e. None), or (when the legacy Computer Browser service is enabled) BROWSER."}

 "Accès à distance des chemins vers les registres
 Cette GPO définit quels chemins vers les registres peuvent être accessible à distance.
Il est recommandé de configurer cette GPO
Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Remotely accessible registry paths
avec les paramètres suivants :
System\CurrentControlSet\Control\ProductOptions System\CurrentControlSet\Control\Server Applications Software\Microsoft\Windows NT\CurrentVersion"
if($Machine = "System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion"){"CONFORME"}
else{"NON CONFORME"}

"
Accès anonymes aux canaux nommés
Cette GPO autorise ou non les accès  anonymes aux canaux nommés.
Accès anonymes aux répertoires de partage
Cette GPO définit la liste de répertoires accessible anonymement.
Il est recommandé d’initialiser la GPO suivante à None :
Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Shares that can be accessed anonymously
Il est recommandé d’activer la GPO suivante :
Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Restrict anonymous access to Named Pipes and Shares
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess=$RestrictNullSessAccess"
if($RestrictNullSessAccess -eq 1){"CONFORME"}
else{"NON CONFORME. "}

"
Modèle de sécurité pour les comptes locaux.
Cette GPO définit le comportement des connexions utilisant l’authentification d’un compte local.
Il est recommandé d’initialiser la GPO suivante à : Classic - local users authenticate as themselves :
Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Sharing and security model for local accounts
MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest=$ForceGuest"
if($ForceGuest -eq 0){"CONFORME, 0 - Classic: Local users authenticate as themselves."}
else{"NON CONFORME 1 - Guest only: Local users authenticate as Guest."}

"
Sensibilité à la CASE
Cette GPO définit si le système est sensible à la CASE ou non.
Il est recommandé d’activer la GPO suivante :
Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\System objects: Require case insensitivity for non-Windows subsystems
MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive=$ObCaseInsensitive"
if($ObCaseInsensitive -eq 1){"CONFORME"}
else{"NON CONFORME"}

"
Robustesse de la DACL
Cette GPO définit l’efficacité de la DACL à aider à sécuriser les objets partagés du système.
Il est recommandé d’activer la GPO suivante :
Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)
MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode=$ProtectionMode"
if($ProtectionMode -eq 1){"CONFORME"}
else{"NON CONFORME"}

"
Nombre d'ouvertures de session précédentes dans le cache
Il est recommandé de regler à 4 la mise en cache des sessions.
Cache Logons Count;HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\cachedlogonscount=$CachedLogonCount
"
if($CachedLogonCount -lt 5){"CONFORME"}
else{"NON CONFORME"}

"
Utilisation d’un contrôleur de domain
La centralisation des accès et des droits sur un SI est nécessaire à la bonne sécurité du SI.
"
"
Utilisation du compte administrateur local
L’usage du compte administrateur local n’est pas une bonne pratique. Il ne doit être réservé que lorsque le domaine n’est pas joignable et que le cache d’authentification n’est plus valide.
(usersinfo.txt)"
"
Utilisation de comptes locaux
L’utilisation de compte locaux n’est pas une bonne pratique d’administration. Ceux-ci ne peuvent être audité dans le cadre général de la plateforme et la gestion est impossible.
"
"
Utilisation des partages windows
Le partage de fichier et d’imprimante windows est dangereux pour le système qui les partage. La possibilité d’écrire à distance sur une ressource dans un réseau non sécurisé est à limiter.
"