/*
 * Règles YARA d'exemple pour le TP2.
 * Ajoutez-en au moins deux à vous.
 */

rule Suspicious_Downloader
{
    meta:
        author = "esgi"
        description = "Telechargement + execution d'une charge distante"
    strings:
        $dll = "urlmon.dll" nocase
        $api = "URLDownloadToFile" nocase
        $run = "WinExec" nocase
    condition:
        2 of them
}

rule Reverse_Shell
{
    meta:
        author = "esgi"
        description = "Socket sortante + shell de commande"
    strings:
        $ws = "WSASocket" nocase
        $sh = "cmd.exe" nocase
    condition:
        $ws and $sh
}

rule Keylogger
{
    meta:
        author = "esgi"
        description = "Hook clavier"
    strings:
        $hook = "SetWindowsHookEx" nocase
        $key = "GetAsyncKeyState" nocase
    condition:
        any of them
}

rule C2_HTTP_Callback
{
    meta:
        author = "moi"
        description = "connexion a un serveur C2"
    strings:
        $dom = ".example.test" nocase
        $gate = "gate.php" nocase
    condition:
        any of them
}

rule Registry_Run_Persistence
{
    meta:
        author = "moi"
        description = "detection de persistance"
    strings:
        $run = "CurrentVersion\\Run" nocase
    condition:
        $run
}