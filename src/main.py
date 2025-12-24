import threading
import logging
import time
from .config import DEFAULT_PING_WORKERS, DEFAULT_NMAP_WORKERS, DEFAULT_TARGET_CIDR
from .core.services import run_initial_full_scan_in_background
from .ui.app_instance import app
from .ui.layout import create_layout
from .ui.callbacks import register_callbacks

# Configuração de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    # Setup layout
    app.layout = create_layout()
    
    # Register callbacks
    register_callbacks(app)
    
    # Inicia o scan inicial em uma thread separada ao iniciar o app
    logger.info("Iniciando scan inicial ao iniciar o aplicativo...")
    threading.Thread(
        target=run_initial_full_scan_in_background, 
        args=(DEFAULT_PING_WORKERS, DEFAULT_NMAP_WORKERS, DEFAULT_TARGET_CIDR)
    ).start()
    
    # Run server
    app.run(debug=True, port=8050, host='0.0.0.0')

if __name__ == "__main__":
    main()
