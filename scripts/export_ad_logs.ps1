<#
.SYNOPSIS
    Exporte les evenements de securite Windows (4769 - tickets Kerberos,
    4624 - ouvertures de session) au format CSV attendu par le module
    Sentinel : backend/detection/ad_log_parser.py

    Peut collecter en LOCAL (sur la machine ou il s'execute) ou A DISTANCE
    sur une ou plusieurs machines (autre sous-reseau, autre domaine, poste
    d'un partenaire/client) via WinRM.

.DESCRIPTION
    A executer en PowerShell Administrateur. Lecture seule des logs, ne
    modifie rien sur les systemes cibles.

    ATTENTION - AUTORISATION REQUISE : la collecte a distance necessite des
    identifiants valides sur la machine cible et WinRM active (standard en
    environnement d'entreprise gere par GPO). N'utilisez ce mode que sur des
    systemes que vous administrez, ou avec une autorisation explicite du
    client/partenaire (mandat, contrat de service, convention d'audit). Une
    connexion a distance sans autorisation reste illegale meme avec des
    identifiants valides obtenus par ailleurs.

.PARAMETER OutputPath
    Chemin du fichier CSV de sortie. Par defaut : .\security_events_export.csv

.PARAMETER HoursBack
    Nombre d'heures a remonter dans les logs. Par defaut : 24

.PARAMETER ComputerNames
    Liste de noms d'hotes ou IP a interroger a distance (DC ou postes,
    potentiellement sur un autre sous-reseau/domaine). Si omis, la collecte
    se fait en local uniquement.

.PARAMETER Credential
    Identifiants a utiliser pour la connexion a distance (WinRM). Si omis
    et que -ComputerNames est fourni, PowerShell demandera une invite de
    connexion interactive.

.EXAMPLE
    # Collecte locale (sur le DC ou vous executez le script)
    .\export_ad_logs.ps1

.EXAMPLE
    # Collecte a distance sur plusieurs machines, y compris un autre reseau
    $cred = Get-Credential
    .\export_ad_logs.ps1 -ComputerNames "dc01.labo.local","10.20.0.5" -Credential $cred -HoursBack 4
#>

param(
    [string]$OutputPath = ".\security_events_export.csv",
    [int]$HoursBack = 24,
    [string[]]$ComputerNames = @(),
    [System.Management.Automation.PSCredential]$Credential
)

$startTime = (Get-Date).AddHours(-$HoursBack)

# ---- Bloc de collecte, execute en local ou distant via Invoke-Command ----
$collectionScript = {
    param($StartTimeUtc)

    $filterXml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4769 or EventID=4624) and TimeCreated[@SystemTime&gt;='$StartTimeUtc']]]
    </Select>
  </Query>
</QueryList>
"@

    try {
        $events = Get-WinEvent -FilterXml $filterXml -ErrorAction Stop
    } catch [Exception] {
        if ($_.Exception.Message -match "No events were found") { return @() }
        Write-Warning "Erreur lecture journal Securite sur $env:COMPUTERNAME : $_"
        return @()
    }

    foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $data = @{}
        foreach ($node in $xml.Event.EventData.Data) {
            if ($node.Name) { $data[$node.Name] = $node.'#text' }
        }

        if ($evt.Id -eq 4769) {
            [PSCustomObject]@{
                SourceHost            = $env:COMPUTERNAME
                TimeCreated           = $evt.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss")
                EventID               = "4769"
                AccountName           = $data["TargetUserName"]
                IpAddress             = ($data["IpAddress"] -replace "^::ffff:", "")
                TicketEncryptionType  = $data["TicketEncryptionType"]
                LogonType             = ""
            }
        }
        elseif ($evt.Id -eq 4624) {
            [PSCustomObject]@{
                SourceHost            = $env:COMPUTERNAME
                TimeCreated           = $evt.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss")
                EventID               = "4624"
                AccountName           = $data["TargetUserName"]
                IpAddress             = ($data["IpAddress"] -replace "^::ffff:", "")
                TicketEncryptionType  = ""
                LogonType             = $data["LogonType"]
            }
        }
    }
}

$startTimeUtc = $startTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z")
$allRows = @()

if ($ComputerNames.Count -eq 0) {
    Write-Host "[*] Collecte LOCALE des evenements 4769/4624 depuis $startTime ..." -ForegroundColor Cyan
    $allRows += & $collectionScript $startTimeUtc
}
else {
    Write-Host "[*] Collecte A DISTANCE sur $($ComputerNames.Count) machine(s) : $($ComputerNames -join ', ')" -ForegroundColor Cyan
    Write-Host "[!] Verifiez que vous etes autorise a collecter des logs sur ces machines avant de continuer." -ForegroundColor Yellow

    $icmParams = @{
        ComputerName = $ComputerNames
        ScriptBlock  = $collectionScript
        ArgumentList = $startTimeUtc
        ErrorAction  = "Continue"
    }
    if ($Credential) { $icmParams["Credential"] = $Credential }

    try {
        $allRows += Invoke-Command @icmParams
    } catch {
        Write-Host "[!] Erreur de connexion a distance : $_" -ForegroundColor Red
        Write-Host "    Verifiez : WinRM active sur la cible (Enable-PSRemoting), pare-feu, identifiants." -ForegroundColor Yellow
    }
}

Write-Host "[+] $($allRows.Count) evenement(s) brut(s) collecte(s), extraction/filtrage..." -ForegroundColor Cyan

# On ecarte les comptes systeme/techniques peu utiles pour la demo (bruit)
$rows = $allRows | Where-Object {
    $_.AccountName -and
    $_.AccountName -notmatch '\$$' -and
    $_.AccountName -ne "ANONYMOUS LOGON"
}

if (-not $rows -or $rows.Count -eq 0) {
    Write-Host "[!] Aucun evenement exploitable apres filtrage." -ForegroundColor Yellow
    exit 0
}

# Note : la colonne SourceHost est conservee dans l'export pour tracabilite
# multi-machines/multi-reseaux, mais n'est pas utilisee par ad_log_parser.py
# (elle est simplement ignoree si presente en trop dans le CSV).
$rows | Sort-Object TimeCreated | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "[+] Export termine : $OutputPath ($($rows.Count) ligne(s), $(($rows.SourceHost | Sort-Object -Unique).Count) machine(s) source)" -ForegroundColor Green
Write-Host "[*] Lancez maintenant : python ad_log_parser.py `"$OutputPath`"" -ForegroundColor Cyan

