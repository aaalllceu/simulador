# Simulador de Sistema de Arquivos, E/S e RAID

Projeto didático em Python que integra árvore de diretórios e arquivos, operações CRUD, alocação física, geração e escalonamento de requisições de E/S, arranjos RAID, controles de segurança (usuários, grupos, ACL, criptografia e auditoria), memória híbrida paginada e escalonamento de processos. A etapa de processos oferece ciclo de vida, prioridade + Round-Robin, perfil de syscalls/E/S, bloqueio por mutex, referências de página dinâmicas e métricas WT/TAT, trocas de contexto e utilização de CPU. Os dados do sistema simulado ficam em memória; nenhuma operação grava no disco físico do computador. A criptografia usa a biblioteca `cryptography` (Fernet com chave derivada por PBKDF2-HMAC-SHA256).

## Requisitos e execução

- Python 3.10 ou superior
- Dependência de criptografia: `cryptography`

```bash
python3 -m pip install -r requirements.txt
python3 simulador.py
```

O sistema inicia em `root` para permitir a configuração. Para demonstração, a conta inicial usa `root` como senha; troque-a no código antes de qualquer uso fora do exercício. No terminal interativo, `login --user <nome>` solicita a senha sem exibi-la; `logout` encerra em modo convidado sem privilégios. Autentique como `root` para retomar operações administrativas. Contas e arquivos vivem somente durante a sessão atual.

Configuração padrão: blocos de 4 KiB, 16 blocos, alocação indexada, escalonamento SSTF, cabeça na trilha 53 e RAID 5 com 3 discos. Parâmetros podem ser alterados:

```bash
python3 simulador.py --block-size 4096 --blocks 16 --strategy indexed \
  --scheduler SSTF --tracks 200 --head 53 --raid 5 --raid-disks 3 \
  --reserved-memory 4MB --kernel-memory 1MB --page-size 4KB --frames 8 --page-algorithm LRU
```

Memória padrão: região reservada de 4 MiB (com 1 MiB para o núcleo), páginas de 4 KiB, 8 molduras físicas dinâmicas e substituição LRU. `--page-algorithm` também aceita `SECOND_CHANCE`.

### Escalonadores

`--scheduler` aceita `FCFS`, `SSTF`, `SCAN` e `C-SCAN`. O braço parte da posição inicial, serve as solicitações pendentes por trilha, contabiliza o movimento total e mantém a última posição para a próxima operação. SCAN e C-SCAN percorrem os extremos da superfície simulada conforme necessário. Exemplo do enunciado:

```text
[98, 183, 37, 122, 14] | cabeça 53 | SSTF
Ordem: 53 -> 37 -> 14 -> 98 -> 122 -> 183
Movimento: 208 trilhas
```

### RAID

`--raid` aceita 0, 1, 4 ou 5; `--raid-disks` define o número de discos (mínimo: RAID 0/1, 2; RAID 4/5, 3). RAID 0 distribui dados sem redundância; RAID 1 espelha; RAID 4 usa paridade dedicada; RAID 5 distribui dados e paridade rotativa. RAID 1/4/5 podem simular falha de um disco e reconstruir os blocos a partir da redundância; RAID 0 informa que a recuperação é impossível. A demonstração trabalha com blocos preenchidos com zeros quando necessário, apenas para simular o armazenamento e XOR de paridade.

## Comandos interativos

| Comando | Descrição |
|---|---|
| `mkdir <caminho>` | Cria diretório |
| `create <caminho> --size <tamanho>` | Cria arquivo e reserva blocos no sistema de arquivos simulado |
| `read <caminho>` | Lê informações e gera solicitações de leitura escalonadas |
| `write_file <caminho> "texto"` | Grava conteúdo demonstrativo e gera E/S/arranjo RAID |
| `write_file <caminho> --size 8KB` | Simula gravação de tamanho especificado |
| `update <caminho> --size <tamanho>` | Atualiza o tamanho reservado |
| `rm <caminho>` | Remove arquivo ou diretório vazio |
| `cd <caminho>` / `pwd` | Navegação |
| `tree` | Árvore de diretórios |
| `fs_status --details` | Mapa físico simulado e fragmentação |
| `disk_status` | Histórico de escalonamento de E/S |
| `raid_status` | Estado dos discos e blocos do arranjo RAID |
| `fail_disk <número>` | [root] Simula falha e, se houver redundância, reconstrução |
| `login --user <nome>` / `logout` / `whoami` | Autenticação e consulta do modo |
| `groupadd <grupo>` / `useradd <usuário> <grupo>` | [root] Cadastro de grupos e usuários |
| `chmod <modo> <caminho>` / `acl <caminho>` | [root] Altera e consulta permissões rwx (ex.: 750) |
| `encrypt_file <caminho>` / `decrypt_file <caminho>` | Criptografa dados em repouso / exibe conteúdo descriptografado; chave solicitada de forma oculta |
| `antivirus_scan [diretório]` | [root] Verifica hashes de blocos e assinaturas de teste |
| `tamper_block <caminho> <bloco>` | [root] Adultera dados para demonstração de auditoria |
| `audit_log` | Lista eventos e acessos negados desta sessão |
| `create_process --name X --burst 8ms --priority 1 --type normal [--syscall "read_disk at 3ms (duration: 4ms)"]` | Cadastra processo pronto, com perfil de E/S; `--syscall random` gera evento reproduzível |
| `create_process --name X --burst 8ms --priority 1 --type normal --mutex "Buffer at 2ms (duration: 3ms)" --thread T1` | Agenda disputa de mutex durante o burst |
| `schedule --algorithm Priority_RR --quantum 2ms` | Executa fila multinível por prioridade, com Round-Robin dentro de cada nível |
| `run_simulation --process X --steps 3 --quantum 2ms` | Avança até três ms de CPU e mantém os processos para continuar depois |
| `process_status` | Lista PID, burst, tempo restante e estado do ciclo de vida |
| `create_process --name X --size 512KB --type critical\|normal` | Compatibilidade com a interface de alocação de memória da etapa anterior |
| `terminate_process --name X` | Finaliza processo não executando e libera memória |
| `translate_address --process X --page 1` | Traduz página para moldura; indica HIT ou page fault |
| `execute_step --process X --instruction "LOAD_DATA Página 2"` | Executa referência de memória e pode gerar page fault |
| `memory_status [--reserved\|--virtual]` | Mostra mapa e ocupação das regiões de RAM |
| `memory_compact --reserved` | Compacta processos críticos contíguos |
| `help` / `exit` | Ajuda / encerrar |

Caminhos absolutos e relativos são aceitos. Tamanhos aceitam bytes, `K`, `KB`, `M` e `MB` (base 1024). `read` gera a E/S dos blocos de dados (e bloco de índice quando aplicável); `write_file` escalona os mesmos tipos de requisição e distribui os bytes no arranjo RAID configurado. Senhas são armazenadas como hashes PBKDF2-HMAC-SHA256 com salt aleatório; não são persistidas em texto puro. Arquivos começam com permissões Unix `644`, diretórios com `755` e pastas pessoais com `700`. A varredura detecta alteração depois do registro em memória, mas não é um antivírus real. A criptografia em repouso é simulada nos bytes mantidos na memória; o estado não sobrevive ao encerramento do programa.

### Etapa 5 — processos, E/S, memória e escalonamento

Os processos recebem PID incremental (iniciando em 101), estado inicial `PRONTO`, burst em ms, prioridade positiva e tipo `normal` ou `critical`. Número de prioridade menor indica nível mais alto. Processos normais recebem referências de página pseudoaleatórias determinísticas, enviadas ao mesmo `MemoryManager` LRU/Segunda Chance das etapas anteriores; processos críticos continuam usando a região reservada contígua.

A fila seleciona sempre a prioridade mais alta pronta e faz Round-Robin entre processos do mesmo nível, com quantum configurável. Syscalls ocorrem ao atingir o tempo de CPU indicado: geram uma requisição para o escalonador de disco configurado e bloqueiam o processo pela duração definida; `random` escolhe um instante/duração determinísticos para facilitar a reprodução. Eventos mutex são configurados por processo para demonstrar aquisição, contenção, bloqueio e retomada do primeiro processo à espera. `run_simulation --steps N` limita o tempo de CPU executado e pode ser chamado novamente para continuar.

Exemplo de sessão (entre aspas, pois os perfis contêm espaços):

```text
create_process --name App_Web --burst 8ms --priority 1 --type normal --syscall "read_disk at 3ms (duration: 4ms)"
create_process --name App_Render --burst 5ms --priority 2 --type normal --syscall random
create_process --name App_Mutex --burst 5ms --priority 1 --type normal --mutex "Buffer_Video at 2ms (duration: 3ms)" --thread T1
process_status
schedule --algorithm Priority_RR --quantum 2ms
memory_status --virtual
disk_status
```

`WT` mede o tempo em estado pronto (não inclui bloqueio); `TAT` é o intervalo entre chegada e conclusão e inclui espera e bloqueio. As métricas também mostram bloqueio acumulado, trocas de contexto e utilização de CPU na execução. A simulação concorrente de mutex representa disputas de processos/threads no tempo compartilhado, sem threads do sistema operacional reais.

### Gerenciamento híbrido de memória

Processos `critical` recebem uma área contígua na região reservada, após o núcleo base; processos `normal` recebem espaço virtual paginado sob demanda, sem carregar páginas até a primeira referência. A RAM dinâmica tem capacidade de `--page-size × --frames`; ao lotar, a página menos recentemente usada (LRU) ou a escolhida pela Segunda Chance vai para o swap simulado. `memory_status --reserved` informa lacunas e fragmentação externa; `memory_compact --reserved` move os processos críticos para consolidar o espaço. O relatório virtual informa fragmentação interna, páginas residentes, molduras e falhas.

Demonstração:

```text
create_process --name Kernel_DiskDriver --size 512KB --type critical
create_process --name Kernel_NetDriver --size 1024KB --type critical
create_process --name Kernel_CryptoEngine --size 512KB --type critical
terminate_process --name Kernel_NetDriver
memory_status --reserved
memory_compact --reserved
create_process --name App_Navegador --size 10KB --type normal
translate_address --process App_Navegador --page 1
execute_step --process App_Navegador --instruction "LOAD_DATA Página 2"
memory_status --virtual
```

A memória, o swap e os endereços são abstrações didáticas em memória do programa; não representam nem alteram a RAM real do computador.

### Demonstração da etapa de segurança

```text
groupadd devs
useradd carlos devs            # informe uma senha quando solicitado
mkdir /sistema
create /sistema/config.sys --size 128
chmod 750 /sistema/config.sys
login --user carlos             # senha solicitada sem eco
read_file /sistema/config.sys   # negado por ACL
logout
mkdir /home/carlos/docs
create /home/carlos/docs/segredo.txt --size 32
write_file /home/carlos/docs/segredo.txt "meu segredo"
encrypt_file /home/carlos/docs/segredo.txt
antivirus_scan /
tamper_block /home/carlos/docs/segredo.txt 0
antivirus_scan /
audit_log
```

A lista de assinaturas é intencionalmente inofensiva e usa marcadores de teste (`EICAR-STANDARD-ANTIVIRUS-TEST-FILE` e `MALWARE_SIMULADO`), sem baixar ou executar malware.

## Demonstração

```text
mkdir /sistema
mkdir /sistema/logs
create /sistema/logs/app.log --size 8KB
write_file /sistema/logs/app.log --size 8KB
read /sistema/logs/app.log
raid_status
fail_disk 2
disk_status
```

Para reproduzir o exemplo SSTF exato do enunciado diretamente pela API:

```bash
python3 - <<'PY'
from disk_io import DiskScheduler, IORequest
scheduler = DiskScheduler("SSTF", tracks=200, head=53)
requests = [IORequest(t, "READ") for t in [98, 183, 37, 122, 14]]
print(scheduler.schedule(requests))
PY
```

## Testes

Na pasta do projeto, execute:

```bash
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

Os testes validam árvore e CRUD, fragmentação, escalonamento de disco, RAID, autenticação/ACL/criptografia/auditoria, memória crítica e paginada, page faults e LRU/Segunda Chance, e os novos cenários de prioridade/RR, perfil de syscalls, integração de E/S de processo, mutex, ciclo de vida e métricas.


## Limitações didáticas

É um simulador educacional em memória, não um sistema de arquivos real. Os números de trilha são obtidos do identificador de bloco módulo quantidade de trilhas; isso ilustra o algoritmo, mas não representa geometria física moderna. O estado RAID e a árvore do sistema de arquivos são simulações separadas; os blocos lógicos do sistema de arquivos não representam alocação real de blocos em hardware RAID.
