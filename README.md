# DNSSeeker

Este script Python realiza enumeração avançada de DNS, abrangendo:

- Consulta WHOIS para obter informações sobre domínios.
- Enumeração de subdomínios com brute force.
- Busca em logs de transparência de certificados (CT logs).
- Tentativa de transferência de zona DNS.
- Verificação de serviços em subdomínios descobertos.
- Detecção de possíveis vulnerabilidades, como subdomain takeover e problemas de SSL/TLS.

## Pré-requisitos

Antes de executar o script, certifique-se de ter instalado:

- **Python 3.8 ou superior**
- Bibliotecas Python necessárias:

  ```bash
  pip install -r requirements.txt
  ```

- No arquivo `requirements.txt`, inclua dependências como:
  ```
  dnspython
  requests
  whois
  cryptography
  
  ```

## Configuração

Certifique-se de que o script possui permissões de execução e que você tem as ferramentas de rede apropriadas no seu sistema.

### Para usuários do Windows
1. Instale o Python 3.x a partir do [site oficial](https://www.python.org/downloads/).
2. Certifique-se de adicionar o Python ao PATH durante a instalação.
3. Abra o prompt de comando e execute:
   ```bash
   pip install -r requirements.txt
   ```
4. Execute o script:
   ```bash
   python dnsseeker.py
   ```

### Para usuários do Linux
1. Instale o Python e o pip:
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip
   ```
2. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```
3. Torne o script executável (opcional):
   ```bash
   chmod +x dnsseeker.py
   ```
4. Execute o script:
   ```bash
   ./dnsseeker.py
   ```

## Uso

Execute o script fornecendo um domínio como argumento:

```bash
python dnsseeker.py -d example.com
```

Parâmetros adicionais:

- `-d` ou `--domain`: Domínio alvo para enumeração.
- `-w` ou `--wordlist`: Caminho para uma wordlist de subdomínios.
- `--zone-transfer`: Habilita tentativa de transferência de zona DNS.
- `--scan-ports`: Habilita varredura de portas em subdomínios descobertos.

Exemplo completo:

```bash
python script_dns_enum.py -d example.com -w wordlist.txt --zone-transfer --scan-ports
```

## Saída

Os resultados serão exibidos no terminal e salvos em um arquivo de log (`dns_enum_results.txt`) no mesmo diretório do script.

---

Se tiver dúvidas ou encontrar problemas, sinta-se à vontade para abrir um issue ou enviar um pull request!
