import os
import time
import ssl
import warnings
import re
from datetime import datetime
from lxml import etree
from requests import Session
from requests.adapters import HTTPAdapter
from requests_pkcs12 import Pkcs12Adapter
from urllib3.poolmanager import PoolManager
from urllib3.exceptions import InsecureRequestWarning
from signxml import XMLSigner, methods
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization

# Configurações 
warnings.simplefilter("ignore", InsecureRequestWarning)

CAMINHO_CERTIFICADO = r"C:\Users\bruno.sousa\Documents\.env\Certificado.pfx"
SENHA_DO_CERTIFICADO = "Abcd1234"
CNPJ_EMPRESA = "06288135002124"
AMBIENTE = "1" 

# Endpoint da sefaz 
SOAP_URL = "https://www1.nfe.fazenda.gov.br/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx"
SOAP_ACTION = "http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4/nfeRecepcaoEvento"

NS_NFE = "http://www.portalfiscal.inf.br/nfe"
NS_SIG = "http://www.w3.org/2000/09/xmldsig#"

# Conexão 
class Tls12Adapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize, block=block,
            ssl_version=ssl.PROTOCOL_TLSv1_2
        )

def get_session():
    session = Session()
    session.verify = False
    session.mount("https://", Tls12Adapter())
    pkcs12_adapter = Pkcs12Adapter(
        pkcs12_filename=CAMINHO_CERTIFICADO,
        pkcs12_password=SENHA_DO_CERTIFICADO
    )
    session.mount("https://", pkcs12_adapter)
    return session

# Gera assinatura 
def gerar_envelope_completo(chave: str, sequencia: int = 1):
    chave = "".join(filter(str.isdigit, chave))
    cnpj = "".join(filter(str.isdigit, CNPJ_EMPRESA))
    
    id_evento = f"ID210210{chave}0{sequencia:02d}"
    data_hora = datetime.now().strftime("%Y-%m-%dT%H:%M:%S-03:00")

    # Texto limpo 
    inf_evento_str = f"""<infEvento xmlns="{NS_NFE}" Id="{id_evento}"><cOrgao>91</cOrgao><tpAmb>{AMBIENTE}</tpAmb><CNPJ>{cnpj}</CNPJ><chNFe>{chave}</chNFe><dhEvento>{data_hora}</dhEvento><tpEvento>210210</tpEvento><nSeqEvento>{sequencia}</nSeqEvento><verEvento>1.00</verEvento><detEvento versao="1.00"><descEvento>Ciencia da Operacao</descEvento></detEvento></infEvento>"""
    
    # Assinatura 
    root_to_sign = etree.fromstring(inf_evento_str)

    with open(CAMINHO_CERTIFICADO, "rb") as f:
        pfx_bytes = f.read()
    private_key, cert, _ = pkcs12.load_key_and_certificates(pfx_bytes, SENHA_DO_CERTIFICADO.encode())

    signer = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha1",
        digest_algorithm="sha1",
        c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    )

    signed_node = signer.sign(
        root_to_sign,
        key=private_key,
        cert=cert.public_bytes(serialization.Encoding.PEM),
        reference_uri="#" + id_evento
    )
    
    # Extrair a tag Signature 
    signature_element = signed_node.find(f".//{{{NS_SIG}}}Signature")
    
    if signature_element is None:
        raise ValueError("Erro fatal: A biblioteca não gerou a tag Signature.")

    # Serializa apenas para o texto da assinatura 
    signature_str = etree.tostring(signature_element, encoding="unicode")
    signature_str = re.sub(r'</?(\w+:)?Signature', lambda m: m.group(0).replace(m.group(1) or '', ''), signature_str)
    
    # Remove xmlns residuais
    signature_str = re.sub(r'\sxmlns:\w+="[^"]+"', '', signature_str)
    
    # Garante o xmlns correto na raiz da assinatura
    if 'xmlns="http://www.w3.org/2000/09/xmldsig#"' not in signature_str:
        signature_str = signature_str.replace('<Signature', f'<Signature xmlns="{NS_SIG}"', 1)

    # Montagem do envelope final
    inf_evento_limpo = inf_evento_str.replace(f' xmlns="{NS_NFE}"', '')

    envelope = f"""<envEvento xmlns="{NS_NFE}" versao="1.00"><idLote>1</idLote><evento xmlns="{NS_NFE}" versao="1.00">{inf_evento_limpo}{signature_str}</evento></envEvento>"""
    
    # Remove espaços entre tags
    envelope = re.sub(r'>\s+<', '><', envelope)
    
    return envelope

# Envio e processamento 
def enviar_manifestacao(chave: str):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Nota: {chave} ...", end=" ")
    
     #Gerador do XML 
    try:
        xml_str = gerar_envelope_completo(chave)

        # Envelope SOAP
        soap_envelope = '<?xml version="1.0" encoding="utf-8"?>'
        soap_envelope += '<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">'
        soap_envelope += '<soap12:Body>'
        soap_envelope += '<nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4">'
        soap_envelope += xml_str
        soap_envelope += '</nfeDadosMsg>'
        soap_envelope += '</soap12:Body>'
        soap_envelope += '</soap12:Envelope>'

        headers = {
            "Content-Type": f'application/soap+xml; charset=utf-8; action="{SOAP_ACTION}"',
            "User-Agent": "Mozilla/5.0"
        }

        # Envio
        session = get_session()
        resp = session.post(SOAP_URL, data=soap_envelope.encode("utf-8"), headers=headers, timeout=30)

        # Retorno
        if resp.status_code == 200:
            txt_clean = re.sub(r' xmlns:.*?"[^"]+"', '', resp.text).replace('soap:', '').replace('nfe:', '')
            
            if '<cStat>128</cStat>' in txt_clean:
                match = re.search(r'<retEvento>.*?<cStat>(\d+)</cStat>.*?<xMotivo>(.*?)</xMotivo>', txt_clean, re.DOTALL)
                if match: 
                    print(f"OK -> {match.group(1)} - {match.group(2)}")
                    with open("historico_retornos.txt", "a", encoding="utf-8") as f:
                        f.write(f"SUCESSO {chave}: {match.group(1)} - {match.group(2)}\n")
                else: 
                    print("LOTE 128 (Processado) - OK")
            else:
                match_err = re.search(r'<xMotivo>(.*?)</xMotivo>', txt_clean)
                msg = match_err.group(1) if match_err else "Erro desconhecido"
                print(f"ERRO LOTE: {msg}")
                
        elif resp.status_code == 400:
            print("ERRO 400. Verifique 'debug_envelope_400.xml'.")
            with open("debug_envelope_400.xml", "w", encoding="utf-8") as f:
                f.write(soap_envelope)
        else:
            print(f"ERRO HTTP: {resp.status_code}")

    except Exception as e:
        print(f"ERRO GERAL: {e}")

def iniciar():
    print(">>> INICIANDO (FRANKENSTEIN 2.0 - CORRIGIDO) <<<")
    arquivo_chaves = "chaves_para_manifestar.txt"
    if not os.path.exists(arquivo_chaves):
        with open(arquivo_chaves, "w") as f: f.write("")
        return

    with open(arquivo_chaves, "r") as f:
        chaves = [linha.strip() for linha in f if len(linha.strip()) == 44]
    
    print(f"--- Processando {len(chaves)} notas ---")
    for chave in chaves:
        enviar_manifestacao(chave)
        time.sleep(1)

if __name__ == "__main__":
    iniciar()