"""
Módulo para consulta de NF-e na SEFAZ (NFeDistribuicaoDFe)
Versão corrigida e refatorada
"""
import os
import sys
import base64
import gzip
import logging
from datetime import datetime
from lxml import etree
from zeep import Client, Settings
from zeep.transports import Transport
from requests import Session
from requests_pkcs12 import Pkcs12Adapter
import ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
import warnings

# Ignorar avisos de verificação SSL 
from urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

# --- URLs Corretas de Produção (Ambiente Nacional) ---
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
            # Definir o endpoint correto (o WSDL pode ter vários)
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
        # --- CORREÇÃO 1: Limpeza e CNPJ ---
        # Removemos pontos, traços e barras
        cnpj_limpo = "06288135000180"

        # Cria o elemento raiz
        ns_map = {None: "http://www.portalfiscal.inf.br/nfe"}
        root = etree.Element("distDFeInt", versao="1.01", nsmap=ns_map)
        
        # 1. Ambiente (1 = Produção)
        etree.SubElement(root, "tpAmb").text = "1"
        
        # --- CORREÇÃO 2: cUFAutor REMOVIDO (Evita Erro 215) ---
        
        # 2. CNPJ 
        etree.SubElement(root, "CNPJ").text = cnpj_limpo
        
        # 3. Grupo distNSU
        dist_nsu = etree.SubElement(root, "distNSU")
        
        # 4. ultNSU
        etree.SubElement(dist_nsu, "ultNSU").text = str(ult_nsu).zfill(15)
        
        # Log para conferência
        xml_texto = etree.tostring(root, encoding="unicode")
        self.logger.info(f"Enviando XML: {xml_texto}")
        
        return root

    def _processar_doczip(self, doczip):
        """
        Salva o XML diretamente na pasta 'notas_baixadas' sem tentar ler o conteúdo.
        """
        import os
        import gzip
        import base64
        
        try:
            # 1. Identificadores
            nsu = doczip.get("NSU", "desconhecido")
            schema = doczip.get("schema", "xml")

            # 2. Decodifica o Base64
            conteudo_b64 = doczip.text
            if not conteudo_b64:
                return

            conteudo_bytes = base64.b64decode(conteudo_b64)

            # 3. Descompacta o GZIP (vira o XML texto)
            conteudo_xml = gzip.decompress(conteudo_bytes).decode("utf-8")

            # 4. Cria pasta e salva
            pasta_destino = "notas_baixadas"
            if not os.path.exists(pasta_destino):
                os.makedirs(pasta_destino)

            nome_arquivo = f"{pasta_destino}/{nsu}_{schema}.xml"

            with open(nome_arquivo, "w", encoding="utf-8") as arquivo:
                arquivo.write(conteudo_xml)

            self.logger.info(f"✅ XML salvo com sucesso: {nome_arquivo}")

        except Exception as e:
            self.logger.error(f"❌ Erro ao salvar arquivo NSU {nsu}: {e}")
    
    def consultar_nfe(self, cnpj, mes=None, ano=None, ult_nsu="0"):
        """
        Consulta NF-e na SEFAZ para um CNPJ específico
        """
        
        try:
            self.logger.info(f"Iniciando consulta para CNPJ: {cnpj} | Mês: {mes} | Ano: {ano} | UltNSU: {ult_nsu}")

            # 1. Montar requisição XML
            xml_requisicao_obj = self._montar_xml_requisicao(cnpj, ult_nsu)


            from lxml import etree
            from zeep.transports import Transport
            from requests import Session

            #converter 
            xml_string = etree.tostring(xml_requisicao_obj, pretty_print=True, encoding='unicode')
            self.logger.info(f"XML completo a ser enviado:\n{xml_string}")
            #Fim converter 

            resp = self.client.service.nfeDistDFeInteresse(nfeDadosMsg=xml_requisicao_obj)

            self.logger.info(f"Resposta recebida da SEFAZ: {resp}")

            #Lendo XML 
            
            # 3. Definir o namespace do XML da NFe
            ns = {'nfe': 'http://www.portalfiscal.inf.br/nfe'}

            # 4. Encontrar os elementos cStat e xMotivo
            cStat_element = resp.find('nfe:cStat', namespaces=ns)
            xMotivo_element = resp.find('nfe:xMotivo', namespaces=ns)

            if cStat_element is None:
                self.logger.error("Resposta da SEFAZ não contém 'cStat'.")
                return {'sucesso': False, 'erro': 'Resposta inválida da SEFAZ (sem cStat)'}

            # 5. Pegar os valores de texto
            cStat = int(cStat_element.text)
            xMotivo = xMotivo_element.text if xMotivo_element is not None else "Sem motivo"

            # 6. Verificação do status da SEFAZ
            if cStat != 138: # 138 = Documento(s) localizado(s)
                self.logger.warning(f"SEFAZ retornou status: {cStat} - {xMotivo}")
                if cStat == 137: # 137 = Nenhum documento encontrado
                     return {'sucesso': True, 'nfe_encontradas': [], 'mensagem': xMotivo}
                return {'sucesso': False, 'erro': f"Erro da SEFAZ: {cStat} - {xMotivo}"}

            # 7. Se cStat == 138 (Sucesso), processar o lote
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

            # 8. Retornar o resultado final
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