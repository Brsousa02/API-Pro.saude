import os
import time
import ssl
import warnings
import re
import html
import xml.etree.ElementTree as ET
from datetime import datetime
from lxml import etree
import requests
from requests import Session
from requests_pkcs12 import Pkcs12Adapter
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from urllib3.exceptions import InsecureRequestWarning
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from signxml import XMLSigner, methods

warnings.simplefilter("ignore", InsecureRequestWarning)

CAMINHO_CERTIFICADO = r"C:\Users\bruno.sousa\Documents\.env\Certificado.pfx"
SENHA_DO_CERTIFICADO = "Abcd1234"
CNPJ_EMPRESA = "06288135002124"
AMBIENTE = "1"

# Endpoint (Mesma URL)
SOAP_URL = "https://www1.nfe.fazenda.gov.br/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx"
# Ação (Mesma URL)
SOAP_ACTION = "http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4/nfeRecepcaoEventoNF"

NS_NFE = "http://www.portalfiscal.inf.br/nfe"
NSMAP = {None: NS_NFE}

class Tls12Adapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_version=ssl.PROTOCOL_TLSv1_2
        )

def criar_xml_manifestacao(chave: str, sequencia: int = 1) -> etree._Element:
    id_evento = f"ID210210{chave}0{sequencia:02d}"
    data_hora = datetime.now().strftime("%Y-%m-%dT%H:%M:%S-03:00")

    env_evento = etree.Element(f"{{{NS_NFE}}}envEvento", versao="1.00", nsmap=NSMAP)
    etree.SubElement(env_evento, f"{{{NS_NFE}}}idLote").text = "1"

    evento = etree.SubElement(env_evento, f"{{{NS_NFE}}}evento", versao="1.00")

    inf_evento = etree.SubElement(evento, f"{{{NS_NFE}}}infEvento", Id=id_evento)
    etree.SubElement(inf_evento, f"{{{NS_NFE}}}cOrgao").text = "91"
    etree.SubElement(inf_evento, f"{{{NS_NFE}}}tpAmb").text = AMBIENTE
    etree.SubElement(inf_evento, f"{{{NS_NFE}}}CNPJ").text = CNPJ_EMPRESA
    etree.SubElement(inf_evento, f"{{{NS_NFE}}}chNFe").text = chave
    etree.SubElement(inf_evento, f"{{{NS_NFE}}}dhEvento").text = data_hora
    etree.SubElement(inf_evento, f"{{{NS_NFE}}}tpEvento").text = "210210"
    etree.SubElement(inf_evento, f"{{{NS_NFE}}}nSeqEvento").text = str(sequencia)
    etree.SubElement(inf_evento, f"{{{NS_NFE}}}verEvento").text = "1.00"

    det = etree.SubElement(inf_evento, f"{{{NS_NFE}}}detEvento", versao="1.00")
    etree.SubElement(det, f"{{{NS_NFE}}}descEvento").text = "Ciencia da Operacao"

    return env_evento

def assinar_env_evento(xml_root: etree._Element, private_key, cert) -> etree._Element:
    inf_evento = xml_root.find(f".//{{{NS_NFE}}}infEvento")
    
    signer = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha1",
        digest_algorithm="sha1",
        c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    )

    signed_inf = signer.sign(
        inf_evento,
        key=private_key,
        cert=cert.public_bytes(serialization.Encoding.PEM),
        reference_uri="#" + inf_evento.get("Id"),
    )

    evento_node = xml_root.find(f".//{{{NS_NFE}}}evento")
    evento_node.remove(inf_evento)
    evento_node.append(signed_inf)
    
    # Remove assinatura duplicada se houver
    ns_sig = "{http://www.w3.org/2000/09/xmldsig#}"
    signature_node = signed_inf.find(f".//{ns_sig}Signature") or signed_inf.find(".//Signature")
    if signature_node is not None:
         signed_inf.remove(signature_node)
         evento_node.append(signature_node)

    return xml_root

def enviar_soap_envio_evento(xml_env_evento_str: str) -> requests.Response:
    # 1. FAXINA DO XML (Remove prefixos ns0, ds, xsi)
    xml_clean = re.sub(r' xmlns:ns\d+="[^"]+"', '', xml_env_evento_str)
    xml_clean = re.sub(r' xmlns:ds="[^"]+"', '', xml_clean)
    xml_clean = re.sub(r' xmlns:xsi="[^"]+"', '', xml_clean)
    xml_clean = re.sub(r'<(/?)(ns\d+|ds|xsi):', r'<\1', xml_clean)
    xml_clean = re.sub(r'^<\?xml[^>]*\?>', '', xml_clean).strip()

    # 2. Garante namespaces oficiais
    if 'xmlns="http://www.portalfiscal.inf.br/nfe"' not in xml_clean:
         xml_clean = xml_clean.replace('<envEvento', '<envEvento xmlns="http://www.portalfiscal.inf.br/nfe" ')
    if 'xmlns="http://www.w3.org/2000/09/xmldsig#"' not in xml_clean:
         xml_clean = xml_clean.replace('<Signature', '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#" ')
    
    xml_clean = xml_clean.replace("http://www.w3.org/2006/12/xml-c14n11", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315")

    # 3. Monta Envelope SOAP 1.1 (MUDANÇA AQUI)
    # Note que usamos 'soapenv' e a estrutura clássica
    soap_envelope = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:nfe="http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4">
   <soapenv:Header/>
   <soapenv:Body>
      <nfe:nfeDadosMsg>
        {xml_clean}
      </nfe:nfeDadosMsg>
   </soapenv:Body>
</soapenv:Envelope>"""

    # 4. Cabeçalhos SOAP 1.1 (Action Separada -> Evita Erro 400/500)
    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": SOAP_ACTION,
        "User-Agent": "Mozilla/5.0",
    }

    s = Session()
    s.verify = False
    s.mount("https://", Tls12Adapter())
    s.mount("https://", Pkcs12Adapter(pkcs12_filename=CAMINHO_CERTIFICADO, pkcs12_password=SENHA_DO_CERTIFICADO))

    try:
        # Envia como bytes para garantir encoding correto
        response = s.post(SOAP_URL, data=soap_envelope.encode("utf-8"), headers=headers, timeout=60)
        return response
    except Exception as e:
        print(f"ERRO DE CONEXÃO: {e}")
        return None

def ler_resposta(response_content):
    if not response_content: return
    
    try:
        # Tenta decodificar a resposta
        xml_resp = response_content.decode('utf-8', errors='ignore')
        
        # Remove prefixos de resposta para facilitar o parser
        xml_resp = re.sub(r'<(/?)(soap|soapenv|nfe):', r'<\1', xml_resp)
        xml_resp = xml_resp.replace('xmlns:soap="http://www.w3.org/2003/05/soap-envelope"', '')
        xml_resp = xml_resp.replace('xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"', '')
        
        root = etree.fromstring(xml_resp.encode('utf-8'))
        
        # Busca Fault (Erro SOAP)
        fault = root.find(".//Fault")
        if fault is not None:
            reason = fault.find(".//faultstring")
            text = reason.text if reason is not None else "Erro desconhecido"
            print(f"ERRO SOAP: {text}")
            return

        # Busca Retorno
        ret_env = root.find(".//retEnvEvento")
        
        if ret_env is not None:
            c_stat = ret_env.find(".//cStat")
            x_motivo = ret_env.find(".//xMotivo")
            
            c_stat_text = c_stat.text if c_stat is not None else "?"
            x_motivo_text = x_motivo.text if x_motivo is not None else "?"
            
            if c_stat_text == '128':
                inf_evento = ret_env.find(".//infEvento")
                if inf_evento is not None:
                    c_stat_evt = inf_evento.find("cStat").text
                    x_motivo_evt = inf_evento.find("xMotivo").text
                    print(f"RESULTADO: {c_stat_evt} - {x_motivo_evt}")
                else:
                    print(f"LOTE 128 (Processado).")
            else:
                print(f"STATUS LOTE: {c_stat_text} - {x_motivo_text}")
        else:
            print("Não encontrei tag <retEnvEvento>.")
            print(f"RAW: {xml_resp[:600]}")

    except Exception as e:
        print(f"Erro ao ler XML: {e}")

def enviar_manifestacao(chave: str):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Processando: {chave} ...", end=" ")

    try:
        with open(CAMINHO_CERTIFICADO, "rb") as f: pfx_bytes = f.read()
        private_key, cert, _ = pkcs12.load_key_and_certificates(pfx_bytes, SENHA_DO_CERTIFICADO.encode())

        xml_root = criar_xml_manifestacao(chave)
        xml_root = assinar_env_evento(xml_root, private_key, cert)
        
        xml_str = etree.tostring(xml_root, encoding="unicode", xml_declaration=False)

        print("--> Enviando...", end=" ")
        
        response = enviar_soap_envio_evento(xml_str)
        
        if response is not None:
            if response.status_code == 200:
                ler_resposta(response.content)
            else:
                print(f"ERRO HTTP: {response.status_code}")
                # Imprime o corpo do erro para sabermos o que houve
                print(f"BODY: {response.text[:1000]}") 
        else:
            print("Sem resposta (Conexão falhou)")

    except Exception as e:
        print(f"ERRO GERAL: {e}")

def iniciar():
    arquivo_lista = "chaves_para_manifestar.txt"
    if not os.path.exists(arquivo_lista):
        with open(arquivo_lista, "w") as f: f.write("")
        return

    with open(arquivo_lista, "r") as f:
        chaves = [linha.strip() for linha in f if len(linha.strip()) == 44]

    print(f"--- Iniciando {len(chaves)} notas (SOAP 1.1) ---")

    try:
        for chave in chaves:
            enviar_manifestacao(chave)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nInterrompido pelo usuário.")

if __name__ == "__main__":
    iniciar()