import os
import base64
import gzip
import logging
import re
import ssl
import warnings
import time
from datetime import datetime
from requests import Session
from requests.adapters import HTTPAdapter
from requests_pkcs12 import Pkcs12Adapter
from urllib3.poolmanager import PoolManager
from urllib3.exceptions import InsecureRequestWarning
from lxml import etree
from zeep import Client, Settings
from zeep.transports import Transport
from signxml import XMLSigner, methods
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization

warnings.simplefilter('ignore', InsecureRequestWarning)

# Endpoint da sefaz 
URL_DISTRIBUICAO = "https://www1.nfe.fazenda.gov.br/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx"
URL_EVENTO = "https://www1.nfe.fazenda.gov.br/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx"
WSDL_DISTRIBUICAO = URL_DISTRIBUICAO + "?wsdl"

NS_NFE = "http://www.portalfiscal.inf.br/nfe"
NS_SIG = "http://www.w3.org/2000/09/xmldsig#"

class Tls12Adapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize, block=block,
            ssl_version=ssl.PROTOCOL_TLSv1_2
        )

class SefazAutomacao:
    def __init__(self, certificado_path, certificado_senha):
        self.certificado_path = certificado_path
        self.certificado_senha = certificado_senha
        self.cnpj_empresa = "06288135002124"
        
        self.logger = logging.getLogger("RoboFiscal")
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

        self.session = self._criar_sessao()
        self.client_distribuicao = self._criar_cliente_zeep()

    def _criar_sessao(self):
        session = Session()
        session.verify = False
        session.mount("https://", Tls12Adapter())
        adapter = Pkcs12Adapter(
            pkcs12_filename=self.certificado_path,
            pkcs12_password=self.certificado_senha
        )
        session.mount("https://", adapter)
        return session

    def _criar_cliente_zeep(self):
        try:
            transport = Transport(session=self.session)
            settings = Settings(strict=False, xml_huge_tree=True)
            client = Client(
                wsdl=WSDL_DISTRIBUICAO,
                transport=transport,
                settings=settings
            )
            return client
        except Exception as e:
            self.logger.error(f"Erro zeep: {e}")
            raise

    def _gerar_xml_manifesto_assinado(self, chave_nfe, sequencia=1):
        chave = "".join(filter(str.isdigit, chave_nfe))
        cnpj = "".join(filter(str.isdigit, self.cnpj_empresa))
        id_evento = f"ID210210{chave}0{sequencia:02d}"
        data_hora = datetime.now().strftime("%Y-%m-%dT%H:%M:%S-03:00")

        NS_MAP = {None: NS_NFE}
        
        inf_evento = etree.Element(f"{{{NS_NFE}}}infEvento", Id=id_evento, nsmap=NS_MAP)
        etree.SubElement(inf_evento, f"{{{NS_NFE}}}cOrgao").text = "91"
        etree.SubElement(inf_evento, f"{{{NS_NFE}}}tpAmb").text = "1"
        etree.SubElement(inf_evento, f"{{{NS_NFE}}}CNPJ").text = cnpj
        etree.SubElement(inf_evento, f"{{{NS_NFE}}}chNFe").text = chave
        etree.SubElement(inf_evento, f"{{{NS_NFE}}}dhEvento").text = data_hora
        etree.SubElement(inf_evento, f"{{{NS_NFE}}}tpEvento").text = "210210"
        etree.SubElement(inf_evento, f"{{{NS_NFE}}}nSeqEvento").text = str(sequencia)
        etree.SubElement(inf_evento, f"{{{NS_NFE}}}verEvento").text = "1.00"

        det = etree.SubElement(inf_evento, f"{{{NS_NFE}}}detEvento", versao="1.00")
        etree.SubElement(det, f"{{{NS_NFE}}}descEvento").text = "Ciencia da Operacao"

        with open(self.certificado_path, "rb") as f:
            pfx_bytes = f.read()
        private_key, cert, _ = pkcs12.load_key_and_certificates(pfx_bytes, self.certificado_senha.encode())

        signer = XMLSigner(
            method=methods.enveloped,
            signature_algorithm="rsa-sha1",
            digest_algorithm="sha1",
            c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        )

        signed_node = signer.sign(
            inf_evento,
            key=private_key,
            cert=cert.public_bytes(serialization.Encoding.PEM),
            reference_uri="#" + id_evento
        )
        
        xml_assinado = etree.tostring(signed_node, encoding="unicode")
        
        # limpeza do XML 
        xml_limpo = re.sub(r'\sxmlns:ns\d+="[^"]+"', '', xml_assinado)
        xml_limpo = re.sub(r'<(/?)\w+:', r'<\1', xml_limpo)
        xml_limpo = xml_limpo.replace('<Signature>', f'<Signature xmlns="{NS_SIG}">')

        envelope = f"""<envEvento xmlns="{NS_NFE}" versao="1.00"><idLote>1</idLote><evento xmlns="{NS_NFE}" versao="1.00">{xml_limpo}</evento></envEvento>"""
        
        return re.sub(r'>\s+<', '><', envelope)

    def manifestar_ciencia(self, chave_nfe):
        self.logger.info(f"Manifestando: {chave_nfe}")
        
        try:
            xml_envio = self._gerar_xml_manifesto_assinado(chave_nfe)
            
            soap = f'<?xml version="1.0" encoding="utf-8"?><soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope"><soap12:Body><nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4">{xml_envio}</nfeDadosMsg></soap12:Body></soap12:Envelope>'
            
            headers = {
                "Content-Type": "application/soap+xml; charset=utf-8; action=\"http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4/nfeRecepcaoEvento\"",
                "User-Agent": "Mozilla/5.0"
            }

            response = self.session.post(URL_EVENTO, data=soap.encode("utf-8"), headers=headers, timeout=30)
            
            if response.status_code == 200:
                if '<cStat>128</cStat>' in response.text:
                    if '<cStat>135</cStat>' in response.text:
                        self.logger.info(f"SUCESSO Ciencia: {chave_nfe}")
                        return True
                    elif '<cStat>573</cStat>' in response.text:
                        self.logger.warning(f"Ja manifestada: {chave_nfe}")
                        return True
                    else:
                        match = re.search(r'<xMotivo>(.*?)</xMotivo>', response.text)
                        motivo = match.group(1) if match else "Erro desconhecido"
                        self.logger.error(f"FALHA EVENTO: {motivo}")
                        return False
                else:
                    self.logger.error("Erro Lote cStat!=128")
                    return False
            else:
                self.logger.error(f"Erro HTTP {response.status_code}")
                return False

        except Exception as e:
            self.logger.error(f"Erro ao manifestar: {e}")
            return False

        #Consultor de novas notas 
    def consultar_novas_notas(self, ult_nsu="0"):
        self.logger.info(f"Consultando NSU: {ult_nsu}")
        
        try:
            dist_xml = etree.Element("distDFeInt", versao="1.01", xmlns=NS_NFE)
            etree.SubElement(dist_xml, "tpAmb").text = "1"
            etree.SubElement(dist_xml, "CNPJ").text = self.cnpj_empresa
            distNSU = etree.SubElement(dist_xml, "distNSU")
            etree.SubElement(distNSU, "ultNSU").text = str(ult_nsu).zfill(15)

            resposta = self.client_distribuicao.service.nfeDistDFeInteresse(nfeDadosMsg=dist_xml)
            
            resp_xml = etree.fromstring(etree.tostring(resposta, encoding="unicode"))
            
            cStat = resp_xml.find(f".//{{{NS_NFE}}}cStat").text
            xMotivo = resp_xml.find(f".//{{{NS_NFE}}}xMotivo").text
            ultNSU_ret = resp_xml.find(f".//{{{NS_NFE}}}ultNSU").text
            maxNSU_ret = resp_xml.find(f".//{{{NS_NFE}}}maxNSU").text
            
            self.logger.info(f"Status: {cStat} - {xMotivo} | MaxNSU: {maxNSU_ret}")

            if cStat in ["138", "137"]:
                lote = resp_xml.find(f".//{{{NS_NFE}}}loteDistDFeInt")
                if lote is not None:
                    docs = lote.findall(f".//{{{NS_NFE}}}docZip")
                    self._processar_documentos(docs)
                
                return ultNSU_ret
            else:
                self.logger.error(f"Erro consulta: {xMotivo}")
                return ult_nsu

        except Exception as e:
            self.logger.error(f"Erro consulta: {e}")
            return ult_nsu

        # Processamento de documentos baixados
    def _processar_documentos(self, docs):
        pasta_destino = "Notas_Baixadas"
        if not os.path.exists(pasta_destino): os.makedirs(pasta_destino)

        for doc in docs:
            try:
                ns_doc = doc.get("NSU")
                schema = doc.get("schema")
                conteudo_b64 = doc.text
                
                xml_bytes = gzip.decompress(base64.b64decode(conteudo_b64))
                xml_str = xml_bytes.decode('utf-8')
                root = etree.fromstring(xml_bytes)

                chave = "Desconhecida"
                
                if "resNFe" in schema:
                    chave_elem = root.find(f".//{{{NS_NFE}}}chNFe")
                    if chave_elem is not None:
                        chave = chave_elem.text
                        self.logger.info(f"RESUMO: {chave} - NSU: {ns_doc}")
                        self.manifestar_ciencia(chave)
                
                elif "procNFe" in schema:
                    inf_prot = root.find(f".//{{{NS_NFE}}}infProt")
                    if inf_prot is not None:
                        chave = inf_prot.find(f".//{{{NS_NFE}}}chNFe").text
                        
                    nome_arquivo = os.path.join(pasta_destino, f"{chave}.xml")
                    with open(nome_arquivo, "w", encoding="utf-8") as f:
                        f.write(xml_str)
                    self.logger.info(f"XML BAIXADO: {chave}")

            except Exception as e:
                self.logger.error(f"Erro doc NSU {ns_doc}: {e}")

    #Retorno de notas
if __name__ == "__main__":
    CERTIFICADO = r"C:\Users\bruno.sousa\Documents\.env\Certificado.pfx"
    SENHA = "Abcd1234"
    ARQUIVO_NSU = "ultimo_nsu.txt"
    
    robo = SefazAutomacao(CERTIFICADO, SENHA)
    
    if os.path.exists(ARQUIVO_NSU):
        with open(ARQUIVO_NSU, "r") as f:
            ultimo_nsu = f.read().strip()
        print(f"Retomando NSU: {ultimo_nsu}")
    else:
        ultimo_nsu = "0"
        print("Comecando NSU 0")
    
    while True:
        novo_nsu = robo.consultar_novas_notas(ultimo_nsu)
        
        if novo_nsu != ultimo_nsu:
            ultimo_nsu = novo_nsu
            with open(ARQUIVO_NSU, "w") as f:
                f.write(ultimo_nsu)
            print(f"NSU {ultimo_nsu} salvo.")
            time.sleep(2)
        else:
            print("Sem novas notas. Aguardando...")
            break