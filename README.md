# Simulador Modular de Sistema Operacional

Projeto didático em Python que integra os gerenciadores das cinco etapas: sistema de arquivos; E/S e RAID; identidade, permissões e proteção; memória; e processos. Inclui terminal de comandos e uma interface web local para demonstração. **É uma simulação em memória:** não altera o disco nem a RAM reais do computador.

## Executar

Requer Python 3.10 ou superior. A criptografia usa a dependência `cryptography`.

```bash
python3 -m pip install -r requirements.txt
```

Terminal de comandos:

```bash
python3 simulador.py
```

Interface no navegador:

```bash
python3 web_app.py
```

Abra [http://127.0.0.1:8000](http://127.0.0.1:8000). A interface escuta somente no computador local; não é um deploy público. Use os botões de exemplo ou digite `help` no terminal. O servidor não precisa de Flask ou Streamlit.

**Credencial inicial de demonstração:** usuário `root`, senha `root`. É pública e serve apenas para o exercício. Contas, arquivos e demais dados simulados existem apenas enquanto a sessão está ativa; reiniciar o programa os apaga. Não exponha o servidor à internet nem utilize senhas ou dados pessoais.

## O que demonstrar

| Etapa | Recursos incluídos | Comandos/recursos de exemplo |
|---|---|---|
| **1 — Sistema de arquivos** | Árvore, caminhos absolutos e relativos, CRUD, alocação contígua/encadeada/indexada e fragmentação | `mkdir`, `create`, `read`, `update`, `rm`, `tree`, `fs_status` |
| **2 — E/S e armazenamento** | Requisições de leitura/escrita, FCFS/SSTF/SCAN/C-SCAN, RAID 0/1/4/5 e simulação de recuperação | `write_file`, `disk_status`, `raid_status`, `fail_disk` |
| **3 — Segurança** | Usuários e grupos, senha com PBKDF2-HMAC-SHA256 e salt, modo root/usuário, ACL rwx, criptografia Fernet e auditoria de integridade | `useradd`, `login`, `chmod`, `acl`, `encrypt_file`, `antivirus_scan`, `audit_log` |
| **4 — Memória** | Região reservada contígua, memória virtual sob demanda, tradução de páginas, LRU/Segunda Chance, swap simulado, fragmentação e compactação | `create_process`, `translate_address`, `execute_step`, `memory_status`, `memory_compact` |
| **5 — Processos** | Estados do ciclo de vida, prioridades com Round-Robin, syscalls e bloqueio de E/S, disputa de mutex, referências de página e métricas | `create_process --burst`, `schedule`, `run_simulation`, `process_status` |

## Sessão rápida de demonstração

No terminal do simulador, execute os comandos em ordem:

```text
mkdir /sistema
mkdir /sistema/logs
create /sistema/logs/app.log --size 8KB
write_file /sistema/logs/app.log "registro demonstrativo"
read /sistema/logs/app.log
fs_status
raid_status
```

Crie processos e demonstre a integração de escalonamento, syscall, memória e métricas:

```text
create_process --name App_Web --burst 8ms --priority 1 --type normal --syscall "read_disk at 3ms (duration: 4ms)"
create_process --name App_Render --burst 5ms --priority 1 --type normal
schedule --algorithm Priority_RR --quantum 2ms
process_status
memory_status --virtual
disk_status
```

Demonstre a região crítica reservada e sua compactação:

```text
create_process --name Kernel_Driver --size 512KB --type critical
memory_status --reserved
memory_compact --reserved
terminate_process --name Kernel_Driver
```

Consulte `help` para ver opções completas. Para acessar operações administrativas na interface de terminal, `login --user root` solicita a senha sem exibi-la. Para reprodução do exemplo SSTF do enunciado, a API `DiskScheduler` aceita trilhas `[98, 183, 37, 122, 14]` com a cabeça em 53 e totaliza 208 trilhas.

## Testes

Na pasta do projeto, rode:

```bash
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

A suíte cobre os módulos das cinco etapas, os comandos e as sessões da interface web.



## Limitações didáticas

Árvore, blocos, RAID, memória e processos são modelos em memória, não persistem entre sessões nem usam hardware real. O escalonador mapeia blocos para trilhas de forma ilustrativa. A árvore de arquivos e o arranjo RAID são simulações integradas por operações de E/S, mas não correspondem a um filesystem gravado num RAID físico. A varredura detecta hashes alterados e assinaturas de teste inofensivas; não é um antivírus real. A interface local não oferece autenticação de serviço, TLS, persistência ou controles para deploy público.
