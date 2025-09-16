import os
print(f"DEBUG: Arquivo sendo executado: {os.path.abspath(__file__)}")

import sys
import base64
import gzip
import logging
from datetime import datetime
from lxml import etree
from zeep import Client
from zeep.transports import Transport
from requests import Session
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from requests_pkcs12 import Pkcs12Adapter
from zeep import Client, xsd

# CONFIGURAÇÕES 

# Pasta onde está o certificado (.pfx)
pasta_certificado = r"C:\Users\bruno.sousa\Documents\API-Pr-saude"
arquivo_certificado = "certificado.pfx"

# Senha 
senha = "Abcd1234"
# CNPJ 
cnpj = "06.288.135/0021-24"

# mês e ano desejado
mes_desejado = 7 # (1 a 12)
ano_desejado = 2025 #(4 digitos)

# Pasta onde salvar as NF-e 
pasta_destino = r"C:\Users\Public\NFes"

os.makedirs(pasta_destino, exist_ok=True)
log_file = os.path.join(pasta_destino, "consulta_nfe.log")

logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
)
console = logging.StreamHandler(sys.stdout)
console.setLevel(logging.INFO)
logging.getLogger().addHandler(console)

LOCK_FILE = os.path.join(pasta_destino, ".consulta_nfe.lock")
URL = "https://www1.nfe.fazenda.gov.br/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx"


certificado = os.path.join(pasta_certificado, arquivo_certificado)

def already_running():
    if os.path.exists(LOCK_FILE):
        return True
    with open(LOCK_FILE, "w") as fh:
        fh.write(str(os.getpid()))
    return False

def clear_lock():
    try:
        if os.path.exists(LOCK_FILE):
            os.remove(LOCK_FILE)
    except Exception:
        pass

def load_password():
    env = os.environ.get("CERT_PASS")
    if env:
        return env
    # fallback: arquivo senha.txt ao lado do script
    fallback = os.path.join(os.path.dirname(__file__), "senha.txt")
    if os.path.exists(fallback):
        with open(fallback, "r", encoding="utf-8") as f:
            return f.read().strip()
    return senha
import xml.etree.ElementTree as ET

def parse_xml_to_dict(xml_string):
    root = ET.fromstring(xml_string)
    data = {}
    # Extrair os dados relevantes do seu XML
    
    tp_amb_element = root.find(".//{http://www.portalfiscal.inf.br/nfe}tpAmb" )
    if tp_amb_element is not None:
        data["tpAmb"] = int(tp_amb_element.text)

    
    cuf_autor_element = root.find(".//{http://www.portalfiscal.inf.br/nfe}cUFAutor" )
    if cuf_autor_element is not None:
        data["cUFAutor"] = int(cuf_autor_element.text)

    
    cnpj_element = root.find(".//{http://www.portalfiscal.inf.br/nfe}CNPJ" )
    if cnpj_element is not None:
        data["CNPJ"] = cnpj_element.text

    
    ult_nsu_element = root.find(".//{http://www.portalfiscal.inf.br/nfe}ultNSU" )
    if ult_nsu_element is not None:
        data["ultNSU"] = ult_nsu_element.text

    return data
# --- Fim da função parse_xml_to_dict ---

def main():
    """
    Função principal para consultar, baixar e salvar NF-es.
    """
    try:
        # --- Validações Iniciais ---
        cert_pass = load_password()
        if not cert_pass:
            logging.error("Senha do certificado não informada.")
            return

        if already_running():
            logging.warning("Outra execução já está em andamento. Saindo.")
            return

      # --- Preparação da Conexão SOAP (com TLS 1.2 forçado) ---
        import ssl
        from requests.adapters import HTTPAdapter
        from urllib3.poolmanager import PoolManager

        # Classe especial para forçar o uso do protocolo TLS 1.2
        class Tls12Adapter(HTTPAdapter):
            def init_poolmanager(self, connections, maxsize, block=False):
                self.poolmanager = PoolManager(
                    num_pools=connections,
                    maxsize=maxsize,
                    block=block,
                    ssl_version=ssl.PROTOCOL_TLSv1_2
                )

        session = Session()
        
        # 1. Monta o adaptador para forçar o TLS 1.2
        session.mount("https://", Tls12Adapter( ))
        
        # 2. Monta o adaptador do certificado digital (essencial para autenticação)
        session.mount("https://", Pkcs12Adapter(pkcs12_filename=certificado, pkcs12_password=cert_pass ))

        transport = Transport(session=session)
        client = Client(URL + "?wsdl", transport=transport)

        # --- Montagem e Envio da Requisição ---
        xml_requisicao_texto = f"""
        <distDFeInt xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.01">
            <tpAmb>1</tpAmb>
            <cUFAutor>35</cUFAutor>
            <CNPJ>{cnpj}</CNPJ>
            <distNSU>
                <ultNSU>000000000000000</ultNSU>
            </distNSU>
        </distDFeInt>
        """
        
    
        xml_objeto = etree.fromstring(xml_requisicao_texto )

        logging.info("Iniciando conexão e consulta de DFe na SEFAZ...")
        resp = client.service.nfeDistDFeInteresse(nfeDadosMsg=xml_objeto)

        # --- Processamento da Resposta ---
        logging.info("Resposta recebida.")
        
        # Verificar a resposta 
        if not resp:
             logging.warning("Resposta da SEFAZ foi vazia.")
             return

        root = resp
 
        total_found = 0
        saved = 0
        ns = {'nfe': 'http://www.portalfiscal.inf.br/nfe'}

        for doczip in root.xpath(".//nfe:docZip", namespaces=ns ):
            # procesar cada documento 
            total_found += 1
        
        logging.info("Processamento concluído. Total de documentos: %d", total_found)

    except Exception as e:
        logging.error(f"Ocorreu uma falha ao processar a requisição: {e}")
        return

    # O código aqui SÓ será executado se o TRY for bem-sucedido
    logging.info("Função main executada com sucesso.")


# Esta parte já está correta e fica fora da função
if __name__ == "__main__":
    main()