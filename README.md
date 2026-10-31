# Simulador de Sistema de Arquivos, E/S e RAID

Projeto didático em Python que integra árvore de diretórios e arquivos, operações CRUD, alocação física, geração e escalonamento de requisições de E/S, arranjos RAID e controles de segurança (usuários, grupos, ACL, criptografia e auditoria). Os dados do sistema simulado ficam em memória; nenhuma operação grava no disco físico do computador. A criptografia usa a biblioteca `cryptography` (Fernet com chave derivada por PBKDF2-HMAC-SHA256).

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
  --scheduler SSTF --tracks 200 --head 53 --raid 5 --raid-disks 3
```

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
| `help` / `exit` | Ajuda / encerrar |

Caminhos absolutos e relativos são aceitos. Tamanhos aceitam bytes, `K`, `KB`, `M` e `MB` (base 1024). `read` gera a E/S dos blocos de dados (e bloco de índice quando aplicável); `write_file` escalona os mesmos tipos de requisição e distribui os bytes no arranjo RAID configurado. Senhas são armazenadas como hashes PBKDF2-HMAC-SHA256 com salt aleatório; não são persistidas em texto puro. Arquivos começam com permissões Unix `644`, diretórios com `755` e pastas pessoais com `700`. A varredura detecta alteração depois do registro em memória, mas não é um antivírus real. A criptografia em repouso é simulada nos bytes mantidos na memória; o estado não sobrevive ao encerramento do programa.

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
python3 -m unittest discover -s tests -v
```

Os testes validam árvore e CRUD, fragmentação, escalonamento, integração de E/S/RAID, credenciais salgadas, privilégios, ACL por proprietário/grupo/outros, criptografia autenticada, adulteração de bloco e detecção de assinatura de teste.


## Limitações didáticas

É um simulador educacional em memória, não um sistema de arquivos real. Os números de trilha são obtidos do identificador de bloco módulo quantidade de trilhas; isso ilustra o algoritmo, mas não representa geometria física moderna. O estado RAID e a árvore do sistema de arquivos são simulações separadas; os blocos lógicos do sistema de arquivos não representam alocação real de blocos em hardware RAID.
