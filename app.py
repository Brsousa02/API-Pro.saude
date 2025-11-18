"""
Aplicação Flask para consulta de NF-e na SEFAZ
Interface web para o módulo sefaz_consulta
"""

# 1. IMPORTS
from flask import Flask, render_template, request, jsonify, send_file
import os
import sys
import json
import logging
from datetime import datetime
import tempfile
import zipfile
import io
from dotenv import load_dotenv

# 2. CARREGAR VARIÁVEIS DE AMBIENTE
load_dotenv()

# 3. CONFIGURAÇÕES GLOBAIS
# O caminho
CERTIFICADO_PATH = r"C:\Users\bruno.sousa\Documents\.env\Certificado.pfx"
# A senha 
CERTIFICADO_SENHA = "Abcd1234" 

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')

# Garantir que o diretório de dados existe
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR, exist_ok=True)

# Adicionar o diretório do módulo ao path do sistema
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    # Importar APENAS a classe principal
    from consulta_nfe_mes import SefazConsulta
except ImportError as e:
    print(f"Erro ao importar módulo sefaz_consulta: {e}")
    print("Certifique-se de que o arquivo consulta_nfe_mes.py está no diretório correto")
    sys.exit(1)

# 4. INICIALIZAÇÃO DO APP FLASK
app = Flask(__name__)
print("!!!!!!!!!! O SERVIDOR REINICIOU COM O CÓDIGO NOVO !!!!!!!!!!")
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui' # Mude em produção

# 5. CONFIGURAÇÃO DO LOGGING (APENAS UMA VEZ)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# 6. DEFINIÇÃO DAS ROTAS
@app.route('/')
def index():
    """
    Página principal da aplicação
    """
    logger.info("Acessando a página inicial.")
    # Presume que tem um arquivo index.html
    return render_template('index.html')


@app.route('/api/consultar', methods=['POST'])
def consultar_nfe():
    """
    API endpoint para consultar NF-e na SEFAZ
    """
    logger.info("Recebida requisição em /api/consultar")
    

    try:
        
        # Voltar a ler JSON
        data = request.get_json()
        if not data:
            return jsonify({'sucesso': False, 'erro': 'Dados não fornecidos (JSON vazio)'}), 400

        # Ler os dados do JSON 
        cnpj = data.get('cnpj')
        mes_str = data.get('mes')
        ano_str = data.get('ano')

        if not cnpj:
            return jsonify({'sucesso': False, 'erro': 'CNPJ/CPF é obrigatório'}), 400
        
        cnpj = cnpj.strip() # Limpa o CNPJ

        mes_numero = None
        # A opção "Todos os meses" envia value=""
        if mes_str and mes_str.isdigit():
            mes_numero = int(mes_str)

        ano_numero = None
        if ano_str and ano_str.isdigit():
            ano_numero = int(ano_str)
        # A opção "Todos os anos" envia value=""
        if ano_str == "":
            ano_numero = None # Permite busca sem ano

        logger.info(f"Iniciando consulta para CNPJ: {cnpj}, Mês: {mes_numero}, Ano: {ano_numero}")
        consulta = SefazConsulta(CERTIFICADO_PATH, CERTIFICADO_SENHA)
        resultado = consulta.consultar_nfe(cnpj, mes_numero, ano_numero)
        return jsonify(resultado)
        
    except Exception as e:
        logger.error(f"Erro na consulta: {e}")
        return jsonify({'sucesso': False, 'erro': f'Erro Interno: {str(e)}'}), 500

    except Exception as e:
        logger.error(f"Erro na consulta: {e}")
        # Retorna o erro real para o frontend para depuração
        return jsonify({'sucesso': False, 'erro': f'Erro Interno: {str(e)}'}), 500

        # --- REALIZAR CONSULTA USANDO O MÓDULO REATORADO ---

        # Valida se as variáveis globais do certificado foram carregadas
        if not CERTIFICADO_PATH or not CERTIFICADO_SENHA:
            logger.error("Credenciais do certificado (CERTIFICADO_PATH/CERTIFICADO_SENHA) não estão definidas no app.")
            return jsonify({'sucesso': False, 'erro': 'Erro de configuração no servidor.'}), 500

        # Cria a instância passando as variáveis
        consulta = SefazConsulta(CERTIFICADO_PATH, CERTIFICADO_SENHA)
        
        # Chama o método da instância
        resultado = consulta.consultar_nfe(cnpj, mes_numero, ano_numero)

        if resultado is None:
            logger.warning("A consulta à SEFAZ não retornou resultados ou falhou.")
            return jsonify({'sucesso': False, 'erro': 'Nenhum dado retornado pela SEFAZ ou falha na comunicação.'}), 404

        # --- SALVAR RESULTADO E RETORNAR SUCESSO ---
        
        # Salvar resultado em arquivo para histórico
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        resultado_file = os.path.join(DATA_DIR, f"consulta_{timestamp}.json")
        
        # Adiciona o timestamp ao resultado para uso no download
        resultado['timestamp_consulta'] = timestamp
        
        with open(resultado_file, 'w', encoding='utf-8') as f:
            json.dump(resultado, f, ensure_ascii=False, indent=2, default=str)

        logger.info(f"Consulta concluída. Sucesso. Resultado salvo em {resultado_file}")
        
        # Retorna o resultado da consulta para o frontend
        return jsonify(resultado)

    except FileNotFoundError as e:
        logger.error(f"Erro de Arquivo Não Encontrado: {e}", exc_info=True)
        return jsonify({'sucesso': False, 'erro': f'Erro de Configuração: Arquivo não encontrado. Verifique o caminho do certificado. Detalhe: {e}'}), 500
    except Exception as e:
        logger.error(f"Erro na consulta: {e}", exc_info=True) # exc_info=True loga o traceback completo
        return jsonify({
            'sucesso': False,
            'erro': f'Erro Interno: {str(e)}'
        }), 500

@app.route('/api/download_xml/<timestamp>/<chave_nfe>')
def download_xml(timestamp, chave_nfe):
    """
    Download de XML específico de uma NF-e de uma consulta específica
    (Rota otimizada para não varrer todos os arquivos)
    """
    try:
        resultado_file = os.path.join(DATA_DIR, f"consulta_{timestamp}.json")
        
        if not os.path.exists(resultado_file):
            return jsonify({'erro': 'Arquivo de consulta não encontrado'}), 404
            
        with open(resultado_file, 'r', encoding='utf-8') as f:
            resultado = json.load(f)
        
        if resultado.get('sucesso'):
            for nfe in resultado.get('nfe_encontradas', []):
                if nfe.get('chave_nfe') == chave_nfe:
                    # Criar arquivo temporário com o XML
                    temp_file = tempfile.NamedTemporaryFile(
                        mode='w',
                        suffix='.xml',
                        delete=False,
                        encoding='utf-8'
                    )
                    temp_file.write(nfe['xml_completo'])
                    temp_file.close()
                    
                    return send_file(
                        temp_file.name,
                        as_attachment=True,
                        download_name=f"NFe_{chave_nfe}.xml",
                        mimetype='application/xml'
                    )
        
        return jsonify({'erro': 'XML não encontrado nesta consulta'}), 404
        
    except Exception as e:
        logger.error(f"Erro no download: {e}")
        return jsonify({'erro': f'Erro interno: {str(e)}'}), 500


@app.route('/api/download_all/<timestamp>')
def download_all_xml(timestamp):
    """
    Download de todos os XMLs de uma consulta específica
    """
    try:
        resultado_file = os.path.join(DATA_DIR, f"consulta_{timestamp}.json")
        
        if not os.path.exists(resultado_file):
            return jsonify({'erro': 'Consulta não encontrada'}), 404
        
        with open(resultado_file, 'r', encoding='utf-8') as f:
            resultado = json.load(f)
        
        if not resultado.get('sucesso') or not resultado.get('nfe_encontradas'):
            return jsonify({'erro': 'Nenhuma NF-e encontrada nesta consulta'}), 404
        
        # Criar arquivo ZIP em memória
        memory_file = io.BytesIO()
        
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for nfe in resultado['nfe_encontradas']:
                chave = nfe.get('chave_nfe', 'sem_chave')
                xml_content = nfe.get('xml_completo', '')
                
                if xml_content:
                    zipf.writestr(f"NFe_{chave}.xml", xml_content.encode('utf-8'))
        
        memory_file.seek(0)
        return send_file(
            memory_file,
            as_attachment=True,
            download_name=f"NFes_{timestamp}.zip",
            mimetype='application/zip'
        )
        
    except Exception as e:
        logger.error(f"Erro no download em lote: {e}")
        return jsonify({'erro': f'Erro interno: {str(e)}'}), 500


@app.route('/api/historico')
def historico_consultas():
    """
    Retorna histórico de consultas realizadas
    """
    try:
        historico = []
        
        for filename in sorted(os.listdir(DATA_DIR), reverse=True):
            if filename.startswith('consulta_') and filename.endswith('.json'):
                filepath = os.path.join(DATA_DIR, filename)
                
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        resultado = json.load(f)
                    
                    timestamp = filename.replace('consulta_', '').replace('.json', '')
                    
                    historico.append({
                        'timestamp': timestamp,
                        'data_consulta': datetime.strptime(timestamp, "%Y%m%d_%H%M%S").strftime("%d/%m/%Y %H:%M:%S"),
                        'cnpj': resultado.get('cnpj_consultado', 'N/A'),
                        'sucesso': resultado.get('sucesso', False),
                        'total_nfe': len(resultado.get('nfe_encontradas', [])),
                        'erro': resultado.get('erro', '')
                    })
                    
                except Exception as e:
                    logger.warning(f"Erro ao processar arquivo {filename}: {e}")
                    continue
        
        return jsonify({
            'sucesso': True,
            'historico': historico[:50]  # Limitar a 50 registros mais recentes
        })
        
    except Exception as e:
        logger.error(f"Erro ao obter histórico: {e}")
        return jsonify({'sucesso': False, 'erro': f'Erro interno: {str(e)}'}), 500


@app.route('/api/status')
def status():
    """
    Endpoint para verificar status da aplicação
    """
    return jsonify({
        'status': 'online',
        'timestamp': datetime.now().isoformat(),
        'certificado_configurado': os.path.exists(CERTIFICADO_PATH),
        'modulo_sefaz': True
    })

# ROTA MOVIDA E CORRIGIDA
@app.route('/nfe/download_zip', methods=['GET'])
def download_zip():
    """
    Realiza uma nova consulta e baixa um ZIP com os resultados.
    """
    cnpj = request.args.get('cnpj')
    mes = request.args.get('mes', type=int)
    ano = request.args.get('ano', type=int)

    if not cnpj or not mes or not ano:
        return jsonify({"erro": "Parâmetros 'cnpj', 'mes' e 'ano' são obrigatórios para download em lote."}), 400

    try:
        # 1. Criar a instância da classe
        consulta = SefazConsulta(CERTIFICADO_PATH, CERTIFICADO_SENHA)
        
        # 2. Usar o método da instância (CORRIGIDO)
        resultado = consulta.consultar_nfe(cnpj, mes, ano)
        
        if resultado["sucesso"] and resultado["nfe_encontradas"]:
            memory_file = io.BytesIO()
            with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
                for nfe_data in resultado["nfe_encontradas"]:
                    xml_content = nfe_data.get("xml_completo")
                    chave_nfe = nfe_data.get("chave_nfe")
                    if xml_content and chave_nfe:
                        zf.writestr(f"NFe_{chave_nfe}.xml", xml_content.encode('utf-8'))
            
            memory_file.seek(0)
            return send_file(
                memory_file, 
                mimetype='application/zip', 
                as_attachment=True, 
                download_name=f"NFes_{cnpj}_{mes}_{ano}.zip"
            )

        elif resultado["sucesso"] and not resultado["nfe_encontradas"]:
            return jsonify({"mensagem": "Nenhuma NF-e encontrada para os critérios informados."}), 404
        else:
            return jsonify({"erro": resultado.get("erro", "Erro desconhecido na consulta")}), 500
            
    except Exception as e:
        logging.error(f"Erro ao gerar ZIP de NF-e: {e}")
        return jsonify({"erro": f"Erro interno ao gerar o arquivo ZIP: {e}"}), 500


# ESTE BLOCO DEVE SER O ÚLTIMO NO ARQUIVO
if __name__ == '__main__':
    # Configurações para desenvolvimento
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True  # Debug=True é ótimo para desenvolvimento
    )