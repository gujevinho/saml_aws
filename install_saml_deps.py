import subprocess
import sys

def install_packages():
    packages = [
        "lxml",
        "signxml",
        "cryptography"
    ]
    
    print("Iniciando a instalação das dependências para SAML AWS...")
    
    for package in packages:
        try:
            print(f"Instalando {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"Sucesso: {package} instalado corretamente.")
        except subprocess.CalledProcessError as e:
            print(f"Erro ao instalar {package}: {e}")
            sys.exit(1)

    print("\nTodas as dependências foram instaladas com sucesso!")
    print("Você já pode utilizar o arquivo saml_utils_fixed.py.")

if __name__ == "__main__":
    install_packages()
