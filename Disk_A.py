import z3
from css.table import table
from pwn import remote, context
from css.mangle import mangle
from tqdm import tqdm
from itertools import cycle
from css.cipher import Cipher
from css.mode import Mode

context.log_level = "error"

# Função para enviar query e receber resposta
# Envia dados formatados e recebe uma resposta de 8 bytes.
def query(mangle_in):
    r = remote("127.0.0.1", 1996)
    r.sendline(bytes([0] * 8 + list(mangle_in)))
    res = r.recv(8)
    r.close()
    return list(res)

# Input e saída de mangling para análise
# Conjunto de entradas e saídas usadas para análise do comportamento do mangle 
# através de consultas ao servidor.
# Fazemos isso para capturar o comportamento do sistema e usar essas 
# informações no processo de resolução do solver.


mangle_ins = [
    [0, 0, 0, 0, 0, 0, 0, 0],
    [1, 0, 0, 0, 0, 0, 0, 0],
    [0, 1, 0, 0, 0, 0, 0, 0],
    [0, 0, 1, 0, 0, 0, 0, 0],
    [0, 0, 0, 1, 0, 0, 0, 0],
    [0, 0, 0, 0, 1, 0, 0, 0],
    [0, 0, 0, 0, 0, 1, 0, 0],
    [0, 0, 0, 0, 0, 0, 1, 0],
    [0, 0, 0, 0, 0, 0, 0, 1],
]

## Cada entrada é um vetor de 8 bytes, onde apenas um bit é "ativo" (definido como 1), 
# enquanto os demais são 0. Este padrão ajuda a isolar e compreender como cada bit individualmente
# afeta a saída.

mangle_outs = [query(mangle_in) for mangle_in in mangle_ins]

# Lógica de resolução com Z3

# mix e shift: Operações que manipulam os valores de entrada e dependem de uma chave (key).
# Utilizam operações lógicas (XOR, shifts) para transformar os valores.

def mix(key, value):
    ret = value ^ z3.LShR(value, 8) ^ key
    return ret

def shift(value):
    ret = value ^ (value << 56)
    return ret

# Constrói uma tabela (tabulate_one) com base na função de mapeamento.
# Define a chave como uma variável simbólica (key).
# Adiciona restrições para que as transformações entre mangle_in e mangle_out sejam satisfeitas

def build_tabulate_one(solver):
    tabulate_one = z3.Function("tabulate", z3.BitVecSort(8), z3.BitVecSort(8))
    for idx, table_i in enumerate(table):
        solver.add(tabulate_one(idx) == table_i)
    return tabulate_one


def tabulate(value, name, tabulate_one, solver):
    value_sym = z3.BitVec(name, 64)
    solver.add(value_sym == value)
    ret = []
    for pos in reversed(range(0, 64, 8)):
        ret.append(tabulate_one(z3.Extract(pos + 7, pos, value_sym)))
    ret = z3.Concat(*ret)
    return ret

def u8s_to_bitecval(x):
    return z3.BitVecVal(int(bytes(x).hex(), 16), len(x) * 8)

# Solver para encontrar a chave de autenticação
s = z3.Solver()
tabulate_one = build_tabulate_one(s)
key = z3.BitVec("key", 64)

# Aplica uma série de operações (mix, shift, tabulate) às entradas mangle_in.
# Ajusta as restrições para que as saídas resultantes correspondam a mangle_out.
# Resolve o problema para encontrar a chave de autenticação (cipher_auth_key).


for idx, (mangle_in, mangle_out) in enumerate(zip(mangle_ins, mangle_outs)):
    value = u8s_to_bitecval(mangle_in) # Binario de 64 bits
    goal = u8s_to_bitecval(mangle_out)

    value = mix(key, value)
    value = shift(value)
    value = mix(key, value)
    value = shift(value)
    value = mix(key, value)
    value = tabulate(value, f"one_{idx}", tabulate_one, s)
    value = shift(value)
    value = mix(key, value)
    value = tabulate(value, f"two_{idx}", tabulate_one, s)
    value = shift(value)
    value = mix(key, value)
    value = shift(value)
    value = mix(key, value)

    s.add(value == goal)

assert s.check() == z3.sat, "Chave de autenticação não encontrada."
cipher_auth_key = hex(s.model()[key].as_long())[2:].zfill(16)
print(f"Chave de autenticação: {cipher_auth_key}")

# Funções auxiliares de XOR
def bxor(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])

def do_cipher_auth_key(x):
    k = bytes.fromhex(cipher_auth_key)
    return bxor(x, k)

# Conexão remota e derivação da chave de sessão
# Interage com o servidor para:
# Obter um desafio (host_challenge).
# Derivar a chave de sessão usando mangle, combinando chaves e nonces do servidor e do cliente.

r = remote("127.0.0.1", 1996)
host_challenge = bytes([0] * 16)
r.send(host_challenge)
challenge_key = host_challenge[:8]
encrypted_host_nonce = host_challenge[8:]
host_mangling_key = do_cipher_auth_key(challenge_key)

r.recv(8)
host_nonce = do_cipher_auth_key(encrypted_host_nonce)

player_challenge_key = r.recv(8)
encrypted_player_nonce = r.recv(8)
player_nonce = do_cipher_auth_key(encrypted_player_nonce)

player_mangling_key = do_cipher_auth_key(player_challenge_key)
response = mangle(player_mangling_key, do_cipher_auth_key(player_nonce))
r.send(response)

mangling_key = bxor(host_mangling_key, player_mangling_key)
session_nonce = bxor(host_nonce, player_nonce)
session_key = mangle(mangling_key, session_nonce)

print(f"Chave de sessão: {session_key.hex()}")

# Recebendo e decriptando setores
# Recepção: Obtém setores de dados (8208 bytes cada) do servidor remoto.
# Decriptação: Usa a chave de sessão para decifrar os setores e reconstituir os dados.

def receive_sectors(r):
    sectors = []
    while True:
        try:
            ct = r.recvn(8208, timeout=10)
            if len(ct) == 0:  # Conexão fechada
                break
            if len(ct) != 8208:
                raise ValueError(f"Tamanho inesperado do setor: {len(ct)}")
            sectors.append(ct)
        except Exception as e:
            print(f"Erro ao receber setor: {e}")
            break
    return sectors

sectors = receive_sectors(r)

stream_cipher = Cipher(session_key, Mode.Data)
decrypted_sectors = []
for sector in tqdm(sectors, desc="Decrypting sectors"):
    decrypted_sector = stream_cipher.decrypt(sector)
    x, t = decrypted_sector[:16], decrypted_sector[16:]
    result = bxor(cycle(x), t)
    decrypted_sectors.append(result)

#   Por fim, escreve o resultado no ISO
with open("diskA.iso", "wb") as f:
    for sector in decrypted_sectors:
        f.write(sector)

print("Disco ISO gerado: diskA.iso")
