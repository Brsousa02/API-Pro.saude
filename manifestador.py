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

# --- CONFIGURAÇÕES ---
warnings.simplefilter("ignore", InsecureRequestWarning)

CAMINHO_CERTIFICADO = r"C:\Users\bruno.sousa\Documents\.env\Certificado.pfx"
SENHA_DO_CERTIFICADO = "Abcd1234"
CNPJ_EMPRESA = "06288135002124"
AMBIENTE = "1" 

# ENDPOINTS
SOAP_URL = "https://www1.nfe.fazenda.gov.br/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx"
SOAP_ACTION = "http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4/nfeRecepcaoEvento"

NS_NFE = "http://www.portalfiscal.inf.br/nfe"
NS_SIG = "http://www.w3.org/2000/09/xmldsig#"

# --- 1. CONEXÃO ---
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

# --- 2. GERAÇÃO XML ---
def criar_xml_manifestacao(chave: str, sequencia: int = 1) -> etree._Element:
    nsmap = {None: NS_NFE}
    chave = "".join(filter(str.isdigit, chave))
    cnpj = "".join(filter(str.isdigit, CNPJ_EMPRESA))
    
    id_evento = f"ID210210{chave}0{sequencia:02d}"
    data_hora = datetime.now().strftime("%Y-%m-%dT%H:%M:%S-03:00")

    env_evento = etree.Element(f"{{{NS_NFE}}}envEvento", versao="1.00", nsmap=nsmap)
    etree.SubElement(env_evento, f"{{{NS_NFE}}}idLote").text = "1"
    evento = etree.SubElement(env_evento, f"{{{NS_NFE}}}evento", versao="1.00")
    inf_evento = etree.SubElement(evento, f"{{{NS_NFE}}}infEvento", Id=id_evento)
    
    etree.SubElement(inf_evento, f"{{{NS_NFE}}}cOrgao").text = "91"
    etree.SubElement(inf_evento, f"{{{NS_NFE}}}tpAmb").text = AMBIENTE
    etree.SubElement(inf_evento, f"{{{NS_NFE}}}CNPJ").text = cnpj
    etree.SubElement(inf_evento, f"{{{NS_NFE}}}chNFe").text = chave
    etree.SubElement(inf_evento, f"{{{NS_NFE}}}dhEvento").text = data_hora
    etree.SubElement(inf_evento, f"{{{NS_NFE}}}tpEvento").text = "210210"
    etree.SubElement(inf_evento, f"{{{NS_NFE}}}nSeqEvento").text = str(sequencia)
    etree.SubElement(inf_evento, f"{{{NS_NFE}}}verEvento").text = "1.00"

    det = etree.SubElement(inf_evento, f"{{{NS_NFE}}}detEvento", versao="1.00")
    etree.SubElement(det, f"{{{NS_NFE}}}descEvento").text = "Ciencia da Operacao"

    return env_evento

# --- 3. ASSINATURA ---
def assinar_env_evento(xml_root: etree._Element) -> etree._Element:
    with open(CAMINHO_CERTIFICADO, "rb") as f:
        pfx_bytes = f.read()
    private_key, cert, _ = pkcs12.load_key_and_certificates(pfx_bytes, SENHA_DO_CERTIFICADO.encode())

    inf_evento = xml_root.find(f".//{{{NS_NFE}}}infEvento")
    
    signer = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha1",
        digest_algorithm="sha1",
        c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    )

    signed_inf = signer.sign(
        inf_evento,
        key=private_key,
        cert=cert.public_bytes(serialization.Encoding.PEM),
        reference_uri="#" + inf_evento.get("Id")
    )

    evento = xml_root.find(f".//{{{NS_NFE}}}evento")
    evento.remove(inf_evento)
    evento.append(signed_inf)
    
    return xml_root

# --- 4. TRATAMENTO FINAL (A CORREÇÃO DO SCHEMA) ---
def finalizar_xml_string(xml_root: etree._Element) -> str:
    # Transforma em string
    xml_str = etree.tostring(xml_root, encoding="unicode", xml_declaration=False)
    
    # 1. Remove definições de namespace poluídas (xmlns:ns0, xmlns:ds)
    xml_str = re.sub(r'\sxmlns:ns\d+="[^"]+"', '', xml_str)
    xml_str = re.sub(r'\sxmlns:ds="[^"]+"', '', xml_str)
    
    # 2. Remove os prefixos das tags (ns0: e ds:)
    xml_str = re.sub(r'<(/?)(ns\d+|ds):', r'<\1', xml_str)
    
    # 3. CORREÇÃO DA ASSINATURA
    # Se a assinatura ficou sem xmlns, adiciona
    if '<Signature' in xml_str and 'xmlns="http://www.w3.org/2000/09/xmldsig#"' not in xml_str:
        xml_str = xml_str.replace('<Signature', f'<Signature xmlns="{NS_SIG}"')

    # 4. CORREÇÃO DA RAIZ (Onde deu o erro de Schema)
    # Procura a tag de abertura <envEvento...> e substitui pela correta e completa
    # Usamos regex para pegar qualquer variação que esteja lá
    xml_str = re.sub(
        r'<envEvento.*?>', 
        f'<envEvento xmlns="{NS_NFE}" versao="1.00">', 
        xml_str, 
        count=1
    )
    
    return xml_str

# --- 5. ENVIO ---
def enviar_manifestacao(chave: str):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Nota: {chave} ...", end=" ")
    
    try:
        # Gera e Assina
        xml_root = criar_xml_manifestacao(chave)
        xml_root = assinar_env_evento(xml_root)
        
        # Finaliza string (Limpa prefixos e Força Schema)
        xml_str = finalizar_xml_string(xml_root)

        # Envelope SOAP
        soap_envelope = f"""<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4">
{xml_str}
    </nfeDadosMsg>
  </soap12:Body>
</soap12:Envelope>"""

        headers = {
            "Content-Type": f'application/soap+xml; charset=utf-8; action="{SOAP_ACTION}"',
            "User-Agent": "Mozilla/5.0"
        }

        # Conexão
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
    print(">>> INICIANDO (SCHEMA FIX FORCE) <<<")
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