"""
Módulo para consulta de NF-e na SEFAZ
Refatorado para aceitar parâmetros dinâmicos e retornar dados estruturados
"""
import os
import sys
import base64
import gzip
import logging
from datetime import datetime
from lxml import etree
from zeep import Client
from zeep.transports import Transport
from requests import Session
from requests_pkcs12 import Pkcs12Adapter
import ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager


class SefazConsulta:
    """
    Classe para realizar consultas de NF-e na SEFAZ
    """
    
    def __init__(self, certificado_path, certificado_senha, url_sefaz=None):
        """
        Inicializa a classe de consulta SEFAZ
        
        Args:
            certificado_path (str): Caminho para o arquivo .pfx do certificado
            certificado_senha (str): Senha do certificado
            url_sefaz (str, optional): URL do webservice da SEFAZ
        """
        self.certificado_path = certificado_path
        self.certificado_senha = certificado_senha
        self.url_sefaz = url_sefaz or "https://www.nfe.fazenda.gov.br/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx"
        
        # Configurar logging
        self.logger = logging.getLogger(__name__ )
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def _criar_adaptador_tls(self):
        """
        Cria adaptador HTTP com TLS 1.2 forçado
        """
        class Tls12Adapter(HTTPAdapter):
            def init_poolmanager(self, connections, maxsize, block=False):
                self.poolmanager = PoolManager(
                    num_pools=connections,
                    maxsize=maxsize,
                    block=block,
                    ssl_version=ssl.PROTOCOL_TLSv1_2
                )
        return Tls12Adapter()
    
    def _criar_cliente_soap(self):
        """
        Cria cliente SOAP com certificado digital e TLS 1.2
        """
        try:
            session = Session()
            
            # Monta adaptador TLS 1.2
            session.mount("https://", self._criar_adaptador_tls( ))
            
            # Monta adaptador do certificado digital
            session.mount("https://", Pkcs12Adapter(
                pkcs12_filename=self.certificado_path,
                pkcs12_password=self.certificado_senha
             ))
            
            transport = Transport(session=session)
            client = Client(self.url_sefaz + "?wsdl", transport=transport)
            
            self.logger.info("Cliente SOAP criado com sucesso")
            return client
            
        except Exception as e:
            self.logger.error( "Erro ao criar cliente SOAP: " + str(e))
            raise
    
    def _montar_xml_requisicao(self, cnpj, ult_nsu="000000000000000"):
        """
        Monta XML de requisição para consulta de DFe
        
        Args:
            cnpj (str): CNPJ da empresa
            ult_nsu (str): Último NSU consultado
            
        Returns:
            lxml.etree._Element: Objeto XML da requisição
        """
        xml_texto = """
        <distDFeInt xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.01">
            <tpAmb>1</tpAmb>
            <cUFAutor>35</cUFAutor>
            <CNPJ>{cnpj}</CNPJ>
            <distNSU>
                <ultNSU>{ult_nsu}</ultNSU>
            </distNSU>
        </distDFeInt>
        """
        
        return etree.fromstring(xml_texto )
    
    def _processar_doczip(self, doczip_element):
        """
        Processa um elemento docZip e extrai o XML da NF-e
        
        Args:
            doczip_element: Elemento XML docZip
            
        Returns:
            dict: Dados da NF-e processada
        """
        try:
            # Extrair dados do docZip
            nsu = doczip_element.get("NSU", "")
            schema = doczip_element.get("schema", "")
            
            # Decodificar conteúdo base64
            conteudo_b64 = doczip_element.text
            if not conteudo_b64:
                return None
                
            conteudo_bytes = base64.b64decode(conteudo_b64)
            
            # Descompactar se necessário (gzip)
            try:
                conteudo_xml = gzip.decompress(conteudo_bytes).decode("utf-8")
            except:
                # Se não for gzip, tentar como texto direto
                conteudo_xml = conteudo_bytes.decode("utf-8")
            
            # Parsear XML da NF-e
            root_nfe = etree.fromstring(conteudo_xml)
            
            # Extrair informações básicas da NF-e
            ns = {"nfe": "http://www.portalfiscal.inf.br/nfe"}
            
            # Buscar dados da NF-e
            chave_nfe = None
            data_emissao = None
            cnpj_emitente = None
            nome_emitente = None
            valor_total = None
            
            # Chave da NF-e
            chave_element = root_nfe.xpath(".//nfe:infNFe/@Id", namespaces=ns )
            if chave_element:
                chave_nfe = chave_element[0].replace("NFe", "")
            
            # Data de emissão
            data_element = root_nfe.xpath(".//nfe:dhEmi/text()", namespaces=ns)
            if data_element:
                data_emissao = data_element[0]
            
            # CNPJ do emitente
            cnpj_element = root_nfe.xpath(".//nfe:emit/nfe:CNPJ/text()", namespaces=ns)
            if cnpj_element:
                cnpj_emitente = cnpj_element[0]
            
            # Nome do emitente
            nome_element = root_nfe.xpath(".//nfe:emit/nfe:xNome/text()", namespaces=ns)
            if nome_element:
                nome_emitente = nome_element[0]
            
            # Valor total
            valor_element = root_nfe.xpath(".//nfe:total/nfe:ICMSTot/nfe:vNF/text()", namespaces=ns)
            if valor_element:
                valor_total = float(valor_element[0])
            
            return {
                "nsu": nsu,
                "schema": schema,
                "chave_nfe": chave_nfe,
                "data_emissao": data_emissao,
                "cnpj_emitente": cnpj_emitente,
                "nome_emitente": nome_emitente,
                "valor_total": valor_total,
                "xml_completo": conteudo_xml
            }
            
        except Exception as e:
            self.logger.error("Erro ao processar docZip: " + str(e))
            return None
    
    def consultar_nfe(self, cnpj, mes=None, ano=None, ult_nsu="000000000000000"):
        """
        Consulta NF-e na SEFAZ para um CNPJ específico
        
        Args:
            cnpj (str): CNPJ da empresa (com ou sem formatação)
            mes (int, optional): Mês desejado (1-12)
            ano (int, optional): Ano desejado (4 dígitos)
            ult_nsu (str): Último NSU consultado
            
        Returns:
            dict: Resultado da consulta com lista de NF-e encontradas
        """
        try:
            # Limpar formatação do CNPJ
            cnpj_limpo = "".join(filter(str.isdigit, cnpj))
            if len(cnpj_limpo) == 11:  # CPF
                cnpj_formatado = cnpj_limpo[:3] + "." + cnpj_limpo[3:6] + "." + cnpj_limpo[6:9] + "-" + cnpj_limpo[9:]
            elif len(cnpj_limpo) == 14:  # CNPJ
                cnpj_formatado =cnpj_limpo[:2] + "." + cnpj_limpo[2:5] + "." + cnpj_limpo[5:8] + "/" + cnpj_limpo[8:12] + "-" + cnpj_limpo[12:]
            else:
                raise ValueError("CNPJ/CPF inválido")
            
            self.logger.info("Iniciando consulta para CNPJ: " + str(cnpj_formatado))
            
            # Criar cliente SOAP
            client = self._criar_cliente_soap()
            
            # Montar requisição XML
            xml_requisicao = self._montar_xml_requisicao(cnpj_formatado, ult_nsu)
            
            # Enviar requisição
            self.logger.info("Enviando requisição para SEFAZ...")
            resp = client.service.nfeDistDFeInteresse(nfeDadosMsg=xml_requisicao)
            
            if not resp:
                return {
                    "sucesso": False,
                    "erro": "Resposta vazia da SEFAZ",
                    "nfe_encontradas": []
                }
            
            self.logger.info("Resposta recebida da SEFAZ")
            
            # Processar resposta
            ns = {"nfe": "http://www.portalfiscal.inf.br/nfe"}
            nfe_encontradas = []
            total_documentos = 0
            
            # Buscar elementos docZip
            for doczip in resp.xpath(".//nfe:docZip", namespaces=ns ):
                total_documentos += 1
                nfe_data = self._processar_doczip(doczip)
                
                if nfe_data:
                    # Filtrar por mês/ano se especificado
                    if mes is not None and ano is not None:
                        try:
                            data_emissao = datetime.fromisoformat(nfe_data["data_emissao"].replace("Z", "+00:00"))
                            if data_emissao.month != mes or data_emissao.year != ano:
                                continue
                        except:
                            continue
                    
                    nfe_encontradas.append(nfe_data)
            
            self.logger.info("Processamento concluído. Total de documentos: " + str(total_documentos) + ", NF-e filtradas: " + str(len(nfe_encontradas)))

            return {
                "sucesso": True,
                "total_documentos": total_documentos,
                "nfe_encontradas": nfe_encontradas,
                "cnpj_consultado": cnpj_formatado
            }
            
        except Exception as e:
            self.logger.error("Erro na consulta SEFAZ: " + str(e))
            return {
                "sucesso": False,
                "erro": str(e),
                "nfe_encontradas": []
            }


def consultar_nfe_simples(cnpj, mes=None, ano=None, certificado_path=None, certificado_senha=None):
    """
    Função simplificada para consulta de NF-e
    
    Args:
        cnpj (str): CNPJ da empresa
        mes (int, optional): Mês desejado
        ano (int, optional): Ano desejado
        certificado_path (str, optional): Caminho do certificado
        certificado_senha (str, optional): Senha do certificado
        
    Returns:
        dict: Resultado da consulta
    """
    # Usar configurações padrão se não fornecidas
    if not certificado_path:
        certificado_path = r"C:\Users\bruno.sousa\Documents\API-Pr-saude\API-Pro.saude"
    
    if not certificado_senha:
        # Tentar carregar da variável de ambiente ou arquivo
        certificado_senha = os.environ.get("CERT_PASS")
        if not certificado_senha:
            senha_file = os.path.join(os.path.dirname(__file__), "senha.txt")
            if os.path.exists(senha_file):
                with open(senha_file, "r", encoding="utf-8") as f:
                    certificado_senha = f.read().strip()
            else:
                certificado_senha = "Abcd1234"  
    
    # Criar instância e consultar
    consulta = SefazConsulta(certificado_path, certificado_senha)
    return consulta.consultar_nfe(cnpj, mes, ano)


if __name__ == "__main__":
    # Teste do módulo
    resultado = consultar_nfe_simples("06.288.135/0021-24", 7, 2025)
    print("Sucesso: " + str(resultado["sucesso"]))
    if resultado["sucesso"]:
        print("NF-e encontradas: " + str(len(resultado["nfe_encontradas"])))
        for nfe in resultado["nfe_encontradas"]:
            print("- Chave: " + str(nfe["chave_nfe"]) + ", Emitente: " + str(nfe["nome_emitente"]))
    else:
        print( "Erro: " + str(resultado["erro"]) )
