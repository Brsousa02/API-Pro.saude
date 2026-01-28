"""
Módulo para consulta de NF-e na SEFAZ (NFeDistribuicaoDFe)
Versão corrigida e refatorada
"""
import os
import sys
import base64
import gzip
import logging
import signxml
from datetime import datetime
from lxml import etree
from zeep import Client, Settings
from zeep.transports import Transport
from requests import Session
from requests_pkcs12 import Pkcs12Adapter
import ssl
from signxml import XMLSigner, XMLVerifier
import time
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
import warnings
import OpenSSL.crypto as crypto

# Ignorar avisos de verificação SSL 
from urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

# URLs Corretas de Produção 
URL_SEFAZ_PRODUCAO = "https://www1.nfe.fazenda.gov.br/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx"
WSDL_SEFAZ_PRODUCAO = URL_SEFAZ_PRODUCAO + "?wsdl"

class Tls12Adapter(HTTPAdapter):
    """Adaptador que força o uso de TLS 1.2"""
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_version=ssl.PROTOCOL_TLSv1_2
        )

class SefazConsulta:
    """
    Classe para realizar consultas de NF-e na SEFAZ
    """
    def _assinar_xml(self, xml_element):
        """Assina o XML usando o certificado A1 (PKCS12) carregado"""
        try:
            # Carrega o certificado e a chave privada do arquivo PFX
            with open(self.certificado_path, "rb") as f:
                pfx_data = f.read()
            
            from OpenSSL import crypto
            p12 = crypto.load_pkcs12(pfx_data, self.certificado_senha.encode())
            cert = p12.get_certificate()
            key = p12.get_privatekey()
            
            # Converte para o formato pem 
            cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
            key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

            signer = XMLSigner(
                method=signxml.methods.enveloped,
                signature_algorithm="rsa-sha1",
                digest_algorithm="sha1",
                c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
            )
            
            signed_xml = signer.sign(
                xml_element,
                key=key_pem,
                cert=cert_pem,
                reference_uri=None 
            )
            
            return signed_xml
        except Exception as e:
            self.logger.error(f"Erro ao assinar XML: {e}")
            raise

    def enviar_ciencia_operacao(self, chave_nfe, cnpj):
        """Envia o evento de Ciência da Operação (210210) para a chave informada"""
        try:
            self.logger.info(f"Tentando manifestar Ciência para a nota: {chave_nfe}")
            
            # URL nacional 
            url_evento = "https://www.nfe.fazenda.gov.br/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx"
            
            dh_evento = datetime.now().strftime("%Y-%m-%dT%H:%M:%S-03:00")
            
            xml_evento = f"""
            <envEvento xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.00">
                <idLote>1</idLote>
                <evento xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.00">
                    <infEvento Id="ID210210{chave_nfe}01">
                        <cOrgao>91</cOrgao>
                        <tpAmb>1</tpAmb>
                        <CNPJ>{''.join(filter(str.isdigit, cnpj))}</CNPJ>
                        <chNFe>{chave_nfe}</chNFe>
                        <dhEvento>{dh_evento}</dhEvento>
                        <tpEvento>210210</tpEvento>
                        <nSeqEvento>1</nSeqEvento>
                        <verEvento>1.00</verEvento>
                        <detEvento versao="1.00">
                            <descEvento>Ciencia da Operacao</descEvento>
                        </detEvento>
                    </infEvento>
                </evento>
            </envEvento>
            """
            
            # Converter string para Elemento XML
            root = etree.fromstring(xml_evento)
            evento_element = root.find(".//{http://www.portalfiscal.inf.br/nfe}evento")
            
            # Assinar o evento
            signed_root = self._assinar_xml(root)
             
            # HACK - criar um novo cliente Zeep 
            
            self.logger.info("Evento assinado (simulação). Enviando...")
            return True

        except Exception as e:
            self.logger.error(f"Erro ao manifestar nota {chave_nfe}: {e}")
            return False
    def __init__(self, certificado_path, certificado_senha, url_sefaz=None, wsdl_url=None):
        """
        Inicializa a classe de consulta SEFAZ
        
        Args:
            certificado_path (str): Caminho para o arquivo .pfx do certificado
            certificado_senha (str): Senha do certificado
            url_sefaz (str, optional): URL do webservice da SEFAZ
            wsdl_url (str, optional): URL do WSDL do webservice
        """ 
        self.certificado_path = certificado_path
        self.certificado_senha = certificado_senha
        self.url_sefaz = url_sefaz or URL_SEFAZ_PRODUCAO
        self.wsdl_url = wsdl_url or WSDL_SEFAZ_PRODUCAO

        # Configuração do Logger
        self.logger = logging.getLogger(__name__)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

        try:
            # Criar sessão com certificado e TLS 1.2
            session = Session()
            session.verify = False  # Desabilitar verificação SSL

            # Montar adaptador TLS 1.2
            session.mount("https://", Tls12Adapter())

            # Montar adaptador do certificado digital
            adapter = Pkcs12Adapter(
                pkcs12_filename=self.certificado_path,
                pkcs12_password=self.certificado_senha
            )
            session.mount("https://", adapter)
            
            transport = Transport(session=session)
            
            # Configurações do Zeep
            # Criar um parser XML 
            parser = etree.XMLParser(recover=True, resolve_entities=False)
            settings = Settings(strict=False, xml_huge_tree=True,)

            # Criar o cliente SOAP
            self.client = Client(
                wsdl=self.wsdl_url,
                transport=transport,
                settings=settings
            )
            # Definir o endpoint correto
            self.client.service._binding_options['address'] = self.url_sefaz
            
            self.logger.info("Cliente SOAP criado com sucesso para: " + self.url_sefaz)

        except FileNotFoundError:
            self.logger.error(f"Erro Crítico: Arquivo de certificado não encontrado em: {self.certificado_path}")
            raise
        except Exception as e:
            self.logger.error(f"Erro ao criar cliente SOAP: {e}")
            raise e
        
        # Requisição 

    def _montar_xml_requisicao(self, cnpj, ult_nsu="0"):
        # Removemos pontos, traços e barras
        cnpj_limpo = ''.join(filter(str.isdigit, cnpj))

        # Cria o elemento raiz
        ns_map = {None: "http://www.portalfiscal.inf.br/nfe"}
        root = etree.Element("distDFeInt", versao="1.01", nsmap=ns_map)
        
        # Ambiente (Produção)
        etree.SubElement(root, "tpAmb").text = "1"
        
        # CNPJ 
        etree.SubElement(root, "CNPJ").text = cnpj_limpo
        
        # Grupo distNSU
        dist_nsu = etree.SubElement(root, "distNSU")
        
        # ultNSU
        etree.SubElement(dist_nsu, "ultNSU").text = str(ult_nsu).zfill(15)
        
        # Log para conferência
        xml_texto = etree.tostring(root, encoding="unicode")
        self.logger.info(f"Enviando XML: {xml_texto}")
        
        return root

    def _processar_doczip(self, doczip):
        """
        Salva o XML diretamente na pasta 'Notas abaixadas'
        """
        import os
        import gzip
        import base64
        from lxml import etree

        try:
            # 1. Validações iniciais
            schema = doczip.get("schema", "xml")
           # if "procNfe" not in schema:
            #     return None 

            conteudo_b64 = doczip.text
            if not conteudo_b64:
                return None

            # 2. Descodifica o XML
            conteudo_bytes = base64.b64decode(conteudo_b64)
            conteudo_xml = gzip.decompress(conteudo_bytes).decode("utf-8")
            
            # 3. Prepara para ler dados
            root_nfe = etree.fromstring(conteudo_xml.encode('utf-8'))
            ns = {"nfe": "http://www.portalfiscal.inf.br/nfe"}

            # Para pegar a partir do mês de novembro 2025
            data_emissao_xml = root_nfe.xpath(".//nfe:ide/nfe:dhEmi/text()", namespaces=ns)
            if data_emissao_xml:
                data_str = data_emissao_xml[0]
                ano_nota = int(data_str[0:4])
                mes_nota = int(data_str[5:7])
                
                # Se for antes de novembro 2025 ignora 
                if ano_nota < 2025 or (ano_nota == 2025 and mes_nota < 11):
                    return None

            #  Define o nome do arquivo
            chave_nfe = root_nfe.xpath(".//nfe:infNfe/@Id", namespaces=ns)
            if chave_nfe:
                nome_arquivo = f"{chave_nfe[0]}.xml"
            else:
                nome_arquivo = f"nota_sem_chave_{os.urandom(4).hex()}.xml"

           # Para salvar na pasta correta 
            import os 
            # Pega a pasta onde está o script
            diretorio_base = os.path.dirname(os.path.abspath(__file__))
            pasta_destino = os.path.join(diretorio_base, "Notas abaixadas")
            
            if not os.path.exists(pasta_destino):
                os.makedirs(pasta_destino)

            caminho_completo = os.path.join(pasta_destino, nome_arquivo)
            
            # Imprime antes para vê onde vai salvar no terminal 
            print(f"Tentando salvar em: {caminho_completo}")

            with open(caminho_completo, "w", encoding="utf-8") as f:
                f.write(conteudo_xml)
                f.flush()     # força a gravação no disco imediatamente
                os.fsync(f.fileno()) # obriga windows a gravar no disco 
            
            print(f"SALVO E CONFIRMADO: {nome_arquivo}")
            return nome_arquivo

        except Exception as e:
            print(f"Erro ao salvar XML: {e}")
            return None
    
    def consultar_nfe(self, cnpj, mes=None, ano=None, ult_nsu="0"):
        """
        Consulta NF-e na SEFAZ para um CNPJ específico
        """
        
        try:
            self.logger.info(f"Iniciando consulta para CNPJ: {cnpj} | Mês: {mes} | Ano: {ano} | UltNSU: {ult_nsu}")

            # Montar requisição XML
            xml_requisicao_obj = self._montar_xml_requisicao(cnpj, ult_nsu)


            from lxml import etree
            from zeep.transports import Transport
            from requests import Session

            # converter 
            xml_string = etree.tostring(xml_requisicao_obj, pretty_print=True, encoding='unicode')
            self.logger.info(f"XML completo a ser enviado:\n{xml_string}")
            # Fim converter 

            resp = self.client.service.nfeDistDFeInteresse(nfeDadosMsg=xml_requisicao_obj)

            self.logger.info(f"Resposta recebida da SEFAZ: {resp}")

            #Lendo XML 
            
            # Definir o namespace do XML da NFe
            ns = {'nfe': 'http://www.portalfiscal.inf.br/nfe'}

            # Encontrar os elementos cStat e xMotivo
            cStat_element = resp.find('nfe:cStat', namespaces=ns)
            xMotivo_element = resp.find('nfe:xMotivo', namespaces=ns)

            if cStat_element is None:
                self.logger.error("Resposta da SEFAZ não contém 'cStat'.")
                return {'sucesso': False, 'erro': 'Resposta inválida da SEFAZ (sem cStat)'}

            # Pegar os valores de texto
            cStat = int(cStat_element.text)
            xMotivo = xMotivo_element.text if xMotivo_element is not None else "Sem motivo"

            # Verificação do status da SEFAZ
            if cStat != 138: # 138 = Documento(s) localizado(s)
                self.logger.warning(f"SEFAZ retornou status: {cStat} - {xMotivo}")
                if cStat == 137: # 137 = Nenhum documento encontrado
                     return {'sucesso': True, 'nfe_encontradas': [], 'mensagem': xMotivo}
                return {'sucesso': False, 'erro': f"Erro da SEFAZ: {cStat} - {xMotivo}"}

            # processar o lote
            nfe_encontradas = []
            total_documentos = 0
            
            lote_element = resp.find('nfe:loteDistDFeInt', namespaces=ns)
            
            if lote_element is not None:
                docZip_elements = lote_element.findall('nfe:docZip', namespaces=ns)
                
                if docZip_elements is not None:
                    total_documentos = len(docZip_elements)
                    
                    for docZip in docZip_elements:
                        nfe_data = self._processar_doczip(docZip)
                        
                        if nfe_data:
                            if mes is not None and ano is not None and nfe_data.get("data_emissao"):
                                try:
                                    data_emissao = datetime.fromisoformat(nfe_data["data_emissao"].replace("Z", "+00:00"))
                                    if data_emissao.month != mes or data_emissao.year != ano:
                                        continue 
                                except Exception as e:
                                    self.logger.warning(f"Não foi possível filtrar data: {nfe_data.get('data_emissao')} | Erro: {e}")
                                    continue
                            
                    nfe_encontradas.append(nfe_data)

            # Retornar o resultado final
            ultNSU_element = resp.find('nfe:ultNSU', namespaces=ns)
            maxNSU_element = resp.find('nfe:maxNSU', namespaces=ns)
            
            ultNSU = ultNSU_element.text if ultNSU_element is not None else "0"
            maxNSU = maxNSU_element.text if maxNSU_element is not None else "0"

            self.logger.info(f"Processamento concluído. Total de docs no lote: {total_documentos}, NF-e filtradas: {len(nfe_encontradas)}")
            
            return {
                "sucesso": True,
                "cStat": cStat,
                "xMotivo": xMotivo,
                "ultNSU": ultNSU,
                "maxNSU": maxNSU,
                "nfe_encontradas": nfe_encontradas
            } 

        except Exception as e:
            self.logger.error(f"Erro fatal na consulta: {e}", exc_info=True)
            return {"sucesso": False, "erro": f"Erro interno no servidor: {e}", "nfe_encontradas": []}
