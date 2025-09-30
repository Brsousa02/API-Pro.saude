"""
Aplicação Flask para consulta de NF-e na SEFAZ
Interface web para o módulo sefaz_consulta
"""

from flask import Flask, render_template, request, jsonify, send_file
import os
import sys
import json
import logging
from datetime import datetime
import tempfile
import zipfile
import io 

# Adicionar o diretório pai ao path para importar o módulo sefaz_consulta
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
   from consulta_nfe_mes import SefazConsulta, consultar_nfe_simples
except ImportError as e:
    print("Erro ao importar módulo sefaz_consulta: {e}")
    print("Certifique-se de que o arquivo sefaz_consulta.py está no diretório pai")
    sys.exit(1)

# Configuração da aplicação Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui'  # Mude em produção

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configurações da aplicação (podem ser movidas para arquivo de config)
CERTIFICADO_PATH = r"C:\Users\bruno.sousa\Documents\API-Pr-saude\certificado.pfx"
CERTIFICADO_SENHA = "Abcd1234"  # Em produção, usar variável de ambiente
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')

# Garantir que o diretório de dados existe
os.makedirs(DATA_DIR, exist_ok=True)


@app.route('/')
def index():
    """
    Página principal da aplicação
    """
    return render_template('index.html')


@app.route('/api/consultar', methods=['POST'])
def consultar_nfe():
    """
    API endpoint para consultar NF-e na SEFAZ
    """
    try:
        # Obter dados do formulário
        data = request.get_json()
        
        if not data:
            return jsonify({
                'sucesso': False,
                'erro': 'Dados não fornecidos'
            }), 400
        
        cnpj = data.get('cnpj', '').strip()
        mes = data.get('mes')
        ano = data.get('ano')
        
        # Validações básicas
        if not cnpj:
            return jsonify({
                'sucesso': False,
                'erro': 'CNPJ/CPF é obrigatório'
            }), 400
        
        # Converter mês e ano para inteiros se fornecidos
        if mes:
            try:
                mes = int(mes)
                if mes < 1 or mes > 12:
                    raise ValueError("Mês deve estar entre 1 e 12")
            except ValueError:
                return jsonify({
                    'sucesso': False,
                    'erro': 'Mês inválido'
                }), 400
        
        if ano:
            try:
                ano = int(ano)
                if ano < 2000 or ano > datetime.now().year + 1:
                    raise ValueError("Ano inválido")
            except ValueError:
                return jsonify({
                    'sucesso': False,
                    'erro': 'Ano inválido'
                }), 400
        
        logger.info("Iniciando consulta para CNPJ: {cnpj}, Mês: {mes}, Ano: {ano}")
        
        # Realizar consulta usando o módulo refatorado

        consulta = SefazConsulta(CERTIFICADO_PATH, CERTIFICADO_SENHA)
        resultado = consulta.consultar_nfe(cnpj, mes, ano)

        # Salvar resultado em arquivo para histórico (opcional)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        resultado_file = os.path.join(DATA_DIR, "consulta_{timestamp}.json")
        
        with open(resultado_file, 'w', encoding='utf-8') as f:
            json.dump(resultado, f, ensure_ascii=False, indent=2, default=str)
        
        logger.info("Consulta concluída. Sucesso: {resultado['sucesso']}")
        
        return jsonify(resultado)
        
    except Exception as e:
        logger.error("Erro na consulta: {e}")
        return jsonify({
            'sucesso': False,
            'erro': f'Erro interno: {str(e)}'
        }), 500


@app.route('/api/download_xml/<chave_nfe>')
def download_xml(chave_nfe):
    """
    Download de XML específico de uma NF-e
    """
    try:
        # Buscar o XML nos arquivos de resultado salvos
        for filename in os.listdir(DATA_DIR):
            if filename.startswith('consulta_') and filename.endswith('.json'):
                filepath = os.path.join(DATA_DIR, filename)
                
                with open(filepath, 'r', encoding='utf-8') as f:
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
                                download_name="NFe_{chave_nfe}.xml",
                                mimetype='application/xml'
                            )
        
        return jsonify({
            'erro': 'XML não encontrado'
        }), 404
        
    except Exception as e:
        logger.error("Erro no download: {e}")
        return jsonify({
            'erro': f'Erro interno: {str(e)}'
        }), 500


@app.route('/api/download_all/<timestamp>')
def download_all_xml(timestamp):
    """
    Download de todos os XMLs de uma consulta específica
    """
    try:
        resultado_file = os.path.join(DATA_DIR, "consulta_{timestamp}.json")
        
        if not os.path.exists(resultado_file):
            return jsonify({
                'erro': 'Consulta não encontrada'
            }), 404
        
        with open(resultado_file, 'r', encoding='utf-8') as f:
            resultado = json.load(f)
        
        if not resultado.get('sucesso') or not resultado.get('nfe_encontradas'):
            return jsonify({
                'erro': 'Nenhuma NF-e encontrada nesta consulta'
            }), 404
        
        # Criar arquivo ZIP temporário
        temp_zip = tempfile.NamedTemporaryFile(suffix='.zip', delete=False)
        temp_zip.close()
        
        with zipfile.ZipFile(temp_zip.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for nfe in resultado['nfe_encontradas']:
                chave = nfe.get('chave_nfe', 'sem_chave')
                xml_content = nfe.get('xml_completo', '')
                
                if xml_content:
                    zipf.writestr("NFe_{chave}.xml", xml_content)
        
        return send_file(
            temp_zip.name,
            as_attachment=True,
            download_name="NFes_{timestamp}.zip",
            mimetype='application/zip'
        )
        
    except Exception as e:
        logger.error("Erro no download em lote: {e}")
        return jsonify({
            'erro': f'Erro interno: {str(e)}'
        }), 500


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
                    logger.warning("Erro ao processar arquivo {filename}: {e}")
                    continue
        
        return jsonify({
            'sucesso': True,
            'historico': historico[:50]  # Limitar a 50 registros mais recentes
        })
        
    except Exception as e:
        logger.error("Erro ao obter histórico: {e}")
        return jsonify({
            'sucesso': False,
            'erro': f'Erro interno: {str(e)}'
        }), 500


@app.route('/api/status')
def status():
    """
    Endpoint para verificar status da aplicação
    """
    return jsonify({
        'status': 'online',
        'timestamp': datetime.now().isoformat(),
        'certificado_configurado': os.path.exists(CERTIFICADO_PATH),
        'modulo_sefaz': True  # Se chegou até aqui, o módulo foi importado com sucesso
    })


if __name__ == '__main__':
    # Configurações para desenvolvimento
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )
@app.route('/nfe/download_zip', methods=['GET'])
def download_zip():
    cnpj = request.args.get('cnpj')
    mes = request.args.get('mes', type=int)
    ano = request.args.get('ano', type=int)

    if not cnpj or not mes or not ano:
        return jsonify({"erro": "Parâmetros 'cnpj', 'mes' e 'ano' são obrigatórios para download em lote."}), 400

    # ou para realizar uma nova consulta e gerar o ZIP.
    # Por simplicidade, vamos simular a criação de um ZIP com base na consulta.
    # Em um cenário real, você buscaria os arquivos da PASTA_XML_AUTOMATICO ou de um banco de dados.

    try:
        consulta = SefazConsulta(CERTIFICADO_PATH, CERTIFICADO_SENHA)
        resultado = consultar_nfe_simples(cnpj, mes, ano, CERTIFICADO_PATH, CERTIFICADO_SENHA)

        if resultado["sucesso"] and resultado["nfe_encontradas"]:
            memory_file = io.BytesIO()
            with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
                for nfe_data in resultado["nfe_encontradas"]:
                    xml_content = nfe_data.get("xml_completo")
                    chave_nfe = nfe_data.get("chave_nfe")
                    if xml_content and chave_nfe:
                        zf.writestr(str(chave_nfe) + ".xml", xml_content.encode('utf-8'))
            memory_file.seek(0)
            return send_file(memory_file, mimetype='application/zip', as_attachment=True, download_name="NFes_" + str(cnpj) + "_" + str(mes) + "_" + str(ano) + ".zip")

        elif resultado["sucesso"] and not resultado["nfe_encontradas"]:
            return jsonify({"mensagem": "Nenhuma NF-e encontrada para os critérios informados."}), 404
        else:
            return jsonify({"erro": resultado["erro"]}), 500
    except Exception as e:
        logging.error("Erro ao gerar ZIP de NF-e: " + str(e))
        return jsonify({"erro": "Erro interno ao gerar o arquivo ZIP: " + str(e)}), 500
