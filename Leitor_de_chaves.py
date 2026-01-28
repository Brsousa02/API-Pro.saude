import os
import xml.etree.ElementTree as ET

# Nome exato da pasta onde estão as notas
PASTA_NOTAS = "Notas abaixadas"

def ler_chaves_das_notas():
    print(f"--- Lendo arquivos da pasta: {PASTA_NOTAS} ---")
    
    # Verifica se a pasta existe
    if not os.path.exists(PASTA_NOTAS):
        print(f"ERRO: A pasta '{PASTA_NOTAS}' não existe!")
        return

    arquivos = [f for f in os.listdir(PASTA_NOTAS) if f.endswith('.xml')]
    
    #leitor de chaves
    total_resumos = 0
    total_completas = 0
    lista_para_manifestar = []
   
    print(f"Encontrei {len(arquivos)} arquivos XML.")

    for arquivo in arquivos:
        caminho = os.path.join(PASTA_NOTAS, arquivo)
        try:
            tree = ET.parse(caminho)
            root = tree.getroot()
            
            chave = None
            for elem in root.iter():
                if elem.tag.endswith('chNFe'):
                    chave = elem.text
                    break
            
            tamanho = os.path.getsize(caminho)
            
            if chave:
                if tamanho < 5000: 
                    lista_para_manifestar.append(chave)
                    total_resumos += 1
                else:
                    total_completas += 1
            else:
                pass # Arquivo sem chave ignorado

        except Exception as e:
            print(f"Erro ao ler {arquivo}: {e}")

    print("-" * 30)
    print(f"RELATÓRIO FINAL:")
    print(f"Notas Completas (Já temos): {total_completas}")
    print(f"Notas Resumidas (Precisam Manifestar): {total_resumos}")
    
    with open("chaves_para_manifestar.txt", "w") as f:
        for c in lista_para_manifestar:
            f.write(c + "\n")
            
    if total_resumos > 0:
        print(f"\n Salvei as {total_resumos} chaves no arquivo 'chaves_para_manifestar.txt'.")
    else:
        print("\nNenhuma chave nova para manifestar.")

if __name__ == "__main__":
    ler_chaves_das_notas()