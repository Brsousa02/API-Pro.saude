import os
import shutil
from lxml import etree

# Configurações
PASTA_ORIGEM = "Notas_Baixadas" 
NS_NFE = "{http://www.portalfiscal.inf.br/nfe}"

def organizar_notas():
    if not os.path.exists(PASTA_ORIGEM):
        print(f"Pasta '{PASTA_ORIGEM}' não encontrada. Verifique o nome.")
        return
    
    # Lista apenas arquivos XML
    arquivos_lista = [f for f in os.listdir(PASTA_ORIGEM) if f.endswith(".xml")]
    print(f"Encontrados {len(arquivos_lista)} arquivos XML na pasta...")
    
    for arquivo in arquivos_lista:
        caminho_completo = os.path.join(PASTA_ORIGEM, arquivo)
        
        try:
            # Ler o XML
            tree = etree.parse(caminho_completo)
            root = tree.getroot()
            
            # Descobre a data de emissão
            data_elem = root.find(f".//{NS_NFE}dhEmi")
            
            # Define o nome da pasta
            if data_elem is not None and data_elem.text:
                data_completa = data_elem.text 
                ano_mes = data_completa[0:7] 
            else:
                ano_mes = "Sem_Data"
            pasta_destino = os.path.join(PASTA_ORIGEM, ano_mes)
            
            # Cria a pasta se não existir
            if not os.path.exists(pasta_destino):
                os.makedirs(pasta_destino)
            
            # Move o arquivo
            shutil.move(caminho_completo, os.path.join(pasta_destino, arquivo))
            print(f"Movido: {arquivo} -> {ano_mes}")

        except Exception as e:
            print(f"Erro ao processar '{arquivo}': {e}")

if __name__ == "__main__":
    organizar_notas()
    print("Organização concluída!")