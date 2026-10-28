param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$TestBinary,
    [string]$OutputDirectory = (Join-Path $env:TEMP 'wirekcp-phase2-results'),
    [ValidateSet('udp', 'lan', 'wan')][string[]]$Modes = @('udp', 'lan', 'wan'),
    [ValidateRange(3, 60)][int]$Seconds = 5,
    [switch]$SkipTests,
    [switch]$SkipImpairment
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $OutputDirectory | Out-Null
$sshOptions = @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2')
$root = '/root/wirekcp-phase2-test'
$results = [System.Collections.Generic.List[object]]::new()
$impaired = $false

function Invoke-Vm([int]$Vm, [string]$Command) {
    $address = if ($Vm -eq 1) { '192.168.94.10' } else { '192.168.94.11' }
    $arguments = $sshOptions + @('-o', "HostName=$address", '-o', "HostKeyAlias=alpine$Vm.local", "alpine$Vm", $Command.Replace("`r", ''))
    $output = & ssh @arguments
    if ($LASTEXITCODE -ne 0) {
        $output | Set-Content (Join-Path $OutputDirectory "vm$Vm-last-failure.txt")
        throw "VM $Vm command failed ($LASTEXITCODE): $Command"
    }
    return ($output -join "`n")
}

function Copy-Vm([int]$Vm, [string]$Source, [string]$Target) {
    $address = if ($Vm -eq 1) { '192.168.94.10' } else { '192.168.94.11' }
    & scp @sshOptions -o "HostName=$address" -o "HostKeyAlias=alpine$Vm.local" $Source "alpine${Vm}:$Target"
    if ($LASTEXITCODE -ne 0) { throw "Upload to VM $Vm failed" }
}

function Stop-Engine([int]$Vm) {
    Invoke-Vm $Vm @'
for process in /proc/[0-9]*; do
    executable=$(readlink "$process/exe" 2>/dev/null || true)
    case "$executable" in
        /usr/local/bin/wirekcp-phase1|/usr/local/bin/wirekcp-phase2)
            kill -TERM "${process##*/}" 2>/dev/null || true ;;
    esac
done
'@ | Out-Null
}

function Start-Mode([string]$Name, [string]$Profile) {
    foreach ($vm in 1, 2) { Stop-Engine $vm }
    Invoke-Vm 2 "nohup timeout 20 tcpdump -U -ni eth1 -c 32 -w $root/$Name.pcap 'udp port 51820' >$root/$Name-capture.log 2>&1 </dev/null &" | Out-Null
    foreach ($vm in 1, 2) {
        Invoke-Vm $vm 'if ss -lunp | grep -q ":51820 "; then echo test_port_still_busy; exit 1; fi' | Out-Null
        $peer = if ($vm -eq 1) { 2 } else { 1 }
        $outer = if ($vm -eq 1) { '192.168.94.11' } else { '192.168.94.10' }
        $mode = if ($Name -eq 'udp') { 'udp' } else { 'kcp' }
        $public = $publicKeys[$peer]
        $command = @"
set -eu
umask 077
cat > $root/config.toml <<EOF
IPv4CIDR = "192.168.201.$vm/24"
ListenPort = 51820
PrivateKey = "`$(cat /root/wirekcp-phase1-test/private.key)"
Mode = "$mode"
KCPProfile = "$Profile"
[[Peers]]
PublicKey = "$public"
Endpoint = "${outer}:51820"
AllowedIPs = "192.168.201.$peer/32"
EOF
nohup /usr/local/bin/wirekcp-phase2 --config $root/config.toml --foreground up >$root/$Name-engine.log 2>&1 </dev/null &
echo `$! >$root/engine.pid
"@
        Invoke-Vm $vm $command | Out-Null
    }
    $warmup = Invoke-Vm 1 'timeout 25 ping -c 10 -i 0.2 -W 2 192.168.201.2'
    $warmup | Set-Content (Join-Path $OutputDirectory "$Name-warmup.txt")
    foreach ($vm in 1, 2) {
        $state = Invoke-Vm $vm "timeout 5 wg show wirekcp0; ip route get 192.168.201.$(if ($vm -eq 1) { 2 } else { 1 }); grep 'Using .* mode' $root/$Name-engine.log"
        $state | Set-Content (Join-Path $OutputDirectory "$Name-vm$vm-state.txt")
        $handshake = Invoke-Vm $vm 'timeout 5 wg show wirekcp0 latest-handshakes'
        if ($handshake -notmatch '\s[1-9][0-9]*$') { throw "$Name VM $vm has no WireGuard handshake" }
    }
    Write-Output "Started $Name profile=$Profile (reliable KCP)"
}

function Measure-Iperf([string]$Mode, [string]$Label, [string]$Arguments) {
    $raw = Invoke-Vm 1 "timeout $($Seconds + 30) iperf3 -c 192.168.201.2 -p 5201 -t $Seconds -J $Arguments"
    $raw | Set-Content (Join-Path $OutputDirectory "$Mode-$Label.json")
    $report = $raw | ConvertFrom-Json
    if ($report.error) { throw "$Mode $Label iperf error: $($report.error)" }
    $udp = $Arguments -match '(^| )-u( |$)'
    $udpReceiver = $report.end.sum_received
    if ($udp -and $null -eq $udpReceiver) { $udpReceiver = $report.end.streams[0].udp }
    $entry = [pscustomobject]@{
        Mode = $Mode
        Test = $Label
        ReceiveMbps = if ($udp) { [math]::Round($udpReceiver.bits_per_second / 1e6, 3) } else { [math]::Round($report.end.sum_received.bits_per_second / 1e6, 3) }
        Retransmits = if ($udp) { $null } else { $report.end.sum_sent.retransmits }
        LostPercent = if ($udp) { $udpReceiver.lost_percent } else { $null }
        JitterMs = if ($udp) { $udpReceiver.jitter_ms } else { $null }
    }
    $results.Add($entry)
    $results | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $OutputDirectory 'results.json')
    Write-Output ($entry | ConvertTo-Json -Compress)
}

function Test-Integrity([string]$Label, [int]$Bytes = 8388608) {
    $source = "$root/payload.bin"
    $hash = $expectedHash
    if ($Bytes -ne 8388608) {
        $source = "$root/payload-short.bin"
        Invoke-Vm 1 "head -c $Bytes $root/payload.bin >$source" | Out-Null
        $hash = (Invoke-Vm 1 "sha256sum $source").Split(' ')[0]
    }
    $receiver = @"
set -eu
if [ -f $root/integrity.pid ]; then kill `$(cat $root/integrity.pid) 2>/dev/null || true; fi
rm -f $root/receipt
mkfifo -m 600 $root/receipt
nohup sh -c 'socat -u TCP4-LISTEN:5301,reuseaddr OPEN:$root/received.bin,creat,trunc; result=`$?; if [ "`$result" -eq 0 ]; then sha256sum $root/received.bin >$root/receipt; else echo FAILED >$root/receipt; fi' >$root/integrity.log 2>&1 </dev/null &
echo `$! >$root/integrity.pid
"@
    Invoke-Vm 2 $receiver | Out-Null
    Invoke-Vm 1 "timeout 90 socat -u OPEN:$source TCP4:192.168.201.2:5301,connect-timeout=5" | Out-Null
    $received = (Invoke-Vm 2 "timeout 90 cat $root/receipt").Split(' ')[0]
    if ($received -ne $hash) { throw "$Label integrity mismatch: $received" }
    "$Label SHA256=$received bytes=$Bytes receiver_eof=true" | Add-Content (Join-Path $OutputDirectory 'integrity.txt')
    Write-Output "$Label $Bytes bytes verified after receiver EOF"
}

function Set-Impairment {
    $script:impaired = $true
    foreach ($vm in 1, 2) {
        Invoke-Vm $vm @'
set -eu
modprobe sch_prio
modprobe sch_netem
modprobe cls_u32
tc qdisc add dev eth1 root handle 1: prio bands 3 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
tc qdisc add dev eth1 parent 1:3 handle 30: netem delay 10ms 2ms loss 1% duplicate 0.2% reorder 25% 50%
tc filter add dev eth1 protocol ip parent 1: prio 1 u32 match ip protocol 17 0xff match ip dport 51820 0xffff flowid 1:3
'@ | Out-Null
    }
}

function Clear-Impairment {
    if ($script:impaired) {
        foreach ($vm in 1, 2) {
            Invoke-Vm $vm "tc -s qdisc show dev eth1; tc qdisc del dev eth1 root" | Set-Content (Join-Path $OutputDirectory "$impairmentLabel-netem-vm$vm.txt")
        }
        $script:impaired = $false
    }
}

$publicKeys = @{}
foreach ($vm in 1, 2) {
    Stop-Engine $vm
    Copy-Vm $vm $Binary '/tmp/wirekcp-phase2-upload'
    Copy-Vm $vm $TestBinary '/tmp/conn-phase2.test'
    $verification = Invoke-Vm $vm "set -eu; mkdir -p $root; chmod 700 $root; install -m 755 /tmp/wirekcp-phase2-upload /usr/local/bin/wirekcp-phase2; chmod 755 /tmp/conn-phase2.test; sha256sum /usr/local/bin/wirekcp-phase2"
    if (-not $SkipTests) {
        $verification += "`n" + (Invoke-Vm $vm "timeout 90 /tmp/conn-phase2.test -test.run 'TestKCP' -test.count=10 -test.timeout=60s -test.v")
    }
    $verification | Set-Content (Join-Path $OutputDirectory "vm$vm-tests.txt")
    $publicKeys[$vm] = Invoke-Vm $vm 'cat /root/wirekcp-phase1-test/public.key'
    Invoke-Vm $vm "nohup iperf3 -s -p 5201 >$root/iperf-server.log 2>&1 </dev/null & echo `$! >$root/iperf-server.pid" | Out-Null
}
Invoke-Vm 1 "dd if=/dev/urandom of=$root/payload.bin bs=1048576 count=8 2>/dev/null" | Out-Null
$expectedHash = (Invoke-Vm 1 "sha256sum $root/payload.bin").Split(' ')[0]

try {
    foreach ($mode in $Modes) {
        $profile = if ($mode -eq 'wan') { 'wan' } else { 'lan' }
        Start-Mode $mode $profile
        for ($repeat = 1; $repeat -le 3; $repeat++) { Measure-Iperf $mode "tcp-$repeat" '' }
        Measure-Iperf $mode 'tcp-reverse' '-R'
        Measure-Iperf $mode 'udp-5m' '-u -b 5M -l 1200'
        Measure-Iperf $mode 'udp-25m' '-u -b 25M -l 1200'
        if ($mode -eq 'udp') {
            Measure-Iperf $mode 'udp-100m' '-u -b 100M -l 1200'
        }
        Test-Integrity $mode
    }
    foreach ($mode in $(if ($SkipImpairment) { @() } else { @('wan') })) {
        $impairmentLabel = "$mode-loss"
        Set-Impairment
        try {
            Start-Mode "$mode-loss" 'wan'
            Measure-Iperf "$mode-loss" 'tcp' ''
            Test-Integrity "$mode-loss" 1048576
            $ping = Invoke-Vm 1 'ping -c 100 -i 0.05 -W 2 192.168.201.2'
            $ping | Set-Content (Join-Path $OutputDirectory "$mode-loss-ping.txt")
        } finally { Clear-Impairment }
    }
} finally {
    Clear-Impairment
    Start-Mode 'final-kcp' 'wan'
    foreach ($vm in 1, 2) {
        Invoke-Vm $vm "if [ -f $root/iperf-server.pid ]; then kill `$(cat $root/iperf-server.pid) 2>/dev/null || true; fi" | Out-Null
    }
}

$results | Format-Table -AutoSize
Write-Output "Raw evidence: $OutputDirectory"