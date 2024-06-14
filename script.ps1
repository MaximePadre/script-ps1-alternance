
$ipAddress = Read-Host "Entrez l'adresse IP à rechercher (par exemple, 192.168.140.16)"

# Demander à l'utilisateur d'entrer la date et l'heure de début de la plage horaire (optionnel)
$startTimeInput = Read-Host "Entrez la date et l'heure de début de la plage horaire (format : dd/MM/yyyy HH:mm, laissez vide pour ignorer)"

if ($startTimeInput -ne "") {
    try {
        $startTime = [DateTime]::ParseExact($startTimeInput, 'dd/MM/yyyy HH:mm', $null)
    } catch {
        Write-Output "Erreur : Format de date/heure invalide. Utilisez le format 'dd/MM/yyyy HH:mm'."
        exit 1
    }
}

# Demander à l'utilisateur d'entrer la date et l'heure de fin de la plage horaire (optionnel)
$endTimeInput = Read-Host "Entrez la date et l'heure de fin de la plage horaire (format : dd/MM/yyyy HH:mm, laissez vide pour ignorer)"

if ($endTimeInput -ne "") {
    try {
        $endTime = [DateTime]::ParseExact($endTimeInput, 'dd/MM/yyyy HH:mm', $null)
    } catch {
        Write-Output "Erreur : Format de date/heure invalide. Utilisez le format 'dd/MM/yyyy HH:mm'."
        exit 1
    }
}

# Convertir l'adresse IPv4 en adresse IPv6 conforme (adresse IPv6 mappée IPv4)
try {
    $ipV6Address = [System.Net.IPAddress]::Parse($ipAddress).MapToIPv6()
} catch {
    Write-Output "Erreur : Adresse IP invalide."
    exit 1
}

function FormatEventInfo($userName, $eventTime) {
    return "$userName le $eventTime"
}

$found4768 = $false
$found4769 = $false

# Récupérer les événements 4768 du journal de sécurité contenant l'adresse IP spécifiée dans la plage horaire spécifiée (si définie)
try {
    if ($startTime -and $endTime) {
        $logs4768 = Get-WinEvent -FilterXPath "*[System[EventID=4768] and EventData/Data[@Name='IpAddress']='$ipV6Address']" -LogName Security -ErrorAction Stop | Where-Object { $_.TimeCreated -ge $startTime -and $_.TimeCreated -le $endTime }
    } else {
        $logs4768 = Get-WinEvent -FilterXPath "*[System[EventID=4768] and EventData/Data[@Name='IpAddress']='$ipV6Address']" -LogName Security -ErrorAction Stop
    }

    if ($logs4768.Count -gt 0) {
        Write-Output "----- Événements 4768 -----"
        foreach ($log in $logs4768) {
            $xml = [xml]$log.ToXml()
            $userData = $xml.Event.EventData.Data

            $user = $null
            $eventTime = $log.TimeCreated.ToString('dd/MM/yyyy à HH:mm')  # Formater l'heure de l'événement

            # Rechercher le nom de l'utilisateur dans les données de l'événement
            foreach ($data in $userData) {
                if ($data.Name -eq "TargetUserName") {
                    $user = $data.'#text'
                    $formattedInfo = FormatEventInfo $user $eventTime
                    Write-Output "L'utilisateur associé à l'adresse IP $ipAddress avec l'événement 4768 est : $formattedInfo"
                    $found4768 = $true
                    break
                }
            }
        }
    }
} catch {
    Write-Output "Aucun événement 4768 trouvé pour l'adresse IP $ipAddress dans la plage horaire spécifiée (ou sans plage horaire)."
}

# Récupérer les événements 4769 du journal de sécurité contenant l'adresse IP spécifiée dans la plage horaire spécifiée (si définie)
try {
    if ($startTime -and $endTime) {
        $logs4769 = Get-WinEvent -FilterXPath "*[System[EventID=4769] and EventData/Data[@Name='IpAddress']='$ipV6Address']" -LogName Security -ErrorAction Stop | Where-Object { $_.TimeCreated -ge $startTime -and $_.TimeCreated -le $endTime }
    } else {
        $logs4769 = Get-WinEvent -FilterXPath "*[System[EventID=4769] and EventData/Data[@Name='IpAddress']='$ipV6Address']" -LogName Security -ErrorAction Stop
    }

    if ($logs4769.Count -gt 0) {
        if ($found4768) {
            Write-Output "----- Événements 4769 -----"
        } else {
            Write-Output "----- Aucun événement 4768 trouvé pour l'adresse IP $ipAddress dans la plage horaire spécifiée (ou sans plage horaire) -----"
        }
        foreach ($log in $logs4769) {
            $xml = [xml]$log.ToXml()
            $userData = $xml.Event.EventData.Data

            $user = $null
            $eventTime = $log.TimeCreated.ToString('dd/MM/yyyy à HH:mm')  # Formater l'heure de l'événement

            # Rechercher le nom de l'utilisateur dans les données de l'événement
            foreach ($data in $userData) {
                if ($data.Name -eq "TargetUserName") {
                    $user = $data.'#text'
                    $formattedInfo = FormatEventInfo $user $eventTime
                    Write-Output "L'utilisateur associé à l'adresse IP $ipAddress avec l'événement 4769 est : $formattedInfo"
                    $found4769 = $true
                    break
                }
            }
        }
    } elseif (!$found4768) {
        Write-Output "Aucun événement 4769 trouvé pour l'adresse IP $ipAddress dans la plage horaire spécifiée (ou sans plage horaire)."
    }
} catch {
    Write-Output "Aucun événement 4769 trouvé pour l'adresse IP $ipAddress dans la plage horaire spécifiée (ou sans plage horaire)."
}

# Afficher un message si aucun événement 4768 ou 4769 n'a été trouvé
if (!$found4768 -and !$found4769) {
    Write-Output "Aucun événement trouvé pour l'adresse IP $ipAddress dans la plage horaire spécifiée (ou sans plage horaire)."
}
